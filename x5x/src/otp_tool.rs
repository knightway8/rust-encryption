use crate::io_util::{IO_BUFFER_SIZE, files_are_same, local_path, open_regular_file};
use anyhow::{Context, Result, bail};
use std::ffi::OsStr;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

/// XOR a file with the beginning of a key file and atomically replace the
/// explicitly named input only after the full transformed file is durable.
///
/// # Errors
///
/// Returns an error for invalid filenames, identical input and key, a key
/// shorter than the input, non-regular files, or any I/O or replacement
/// failure.
pub fn xor_file_in_place(directory: &Path, input_name: &OsStr, key_name: &OsStr) -> Result<()> {
    let input_path = local_path(directory, input_name)?;
    let key_path = local_path(directory, key_name)?;

    let input_link_metadata = std::fs::symlink_metadata(&input_path)
        .with_context(|| format!("cannot resolve input '{}'", input_path.display()))?;
    if input_link_metadata.file_type().is_symlink() {
        bail!("OTP input must be a regular file, not a symbolic link");
    }

    let mut input = open_regular_file(&input_path)
        .with_context(|| format!("cannot resolve input '{}'", input_path.display()))?;
    let mut key = open_regular_file(&key_path)
        .with_context(|| format!("cannot resolve key '{}'", key_path.display()))?;
    if files_are_same(&input, &key).with_context(|| {
        format!(
            "cannot compare input '{}' with OTP key '{}'",
            input_path.display(),
            key_path.display()
        )
    })? {
        bail!("input file and OTP key file must be different files");
    }

    let input_metadata = input
        .metadata()
        .with_context(|| format!("cannot inspect input '{}'", input_path.display()))?;
    let input_len = input_metadata.len();

    let key_len = key
        .metadata()
        .with_context(|| format!("cannot inspect key '{}'", key_path.display()))?
        .len();
    if key_len < input_len {
        bail!("OTP key is too short: input is {input_len} bytes but key is only {key_len} bytes");
    }

    let mut temporary = tempfile::NamedTempFile::new_in(directory).with_context(|| {
        format!(
            "cannot create temporary output in '{}'",
            directory.display()
        )
    })?;
    let mut input_buffer = Zeroizing::new(vec![0_u8; IO_BUFFER_SIZE]);
    let mut key_buffer = Zeroizing::new(vec![0_u8; IO_BUFFER_SIZE]);
    let mut remaining = input_len;

    while remaining != 0 {
        let length = usize::try_from(remaining.min(IO_BUFFER_SIZE as u64))
            .context("buffer length does not fit this platform")?;
        input
            .read_exact(&mut input_buffer[..length])
            .context("input changed while OTP was running")?;
        key.read_exact(&mut key_buffer[..length])
            .context("key changed while OTP was running")?;
        for (byte, key_byte) in input_buffer[..length].iter_mut().zip(&key_buffer[..length]) {
            *byte ^= *key_byte;
        }
        temporary
            .write_all(&input_buffer[..length])
            .context("cannot write OTP temporary output")?;
        input_buffer[..length].zeroize();
        key_buffer[..length].zeroize();
        remaining -= length as u64;
    }

    let mut extra = [0_u8; 1];
    if input.read(&mut extra)? != 0 {
        bail!("input grew while OTP was running");
    }
    temporary
        .flush()
        .context("cannot flush OTP temporary output")?;

    temporary
        .as_file()
        .set_permissions(input_metadata.permissions())
        .context("cannot preserve input file permissions")?;
    temporary
        .as_file()
        .sync_all()
        .context("cannot sync OTP temporary output")?;
    persist_otp_output(temporary, &input_path, input)?;

    #[cfg(unix)]
    {
        std::fs::File::open(directory)
            .and_then(|file| file.sync_all())
            .with_context(|| format!("cannot sync directory '{}'", directory.display()))?;
    }
    Ok(())
}

fn persist_otp_output(
    temporary: tempfile::NamedTempFile,
    input_path: &Path,
    original_input: File,
) -> Result<()> {
    let current_input = open_regular_file(input_path).with_context(|| {
        format!(
            "input path '{}' changed before replacement",
            input_path.display()
        )
    })?;
    if !files_are_same(&original_input, &current_input)
        .with_context(|| format!("cannot revalidate input path '{}'", input_path.display()))?
    {
        bail!(
            "input path '{}' changed before replacement; refusing to overwrite it",
            input_path.display()
        );
    }

    #[cfg(windows)]
    let original_permissions = original_input
        .metadata()
        .with_context(|| {
            format!(
                "cannot inspect input permissions for '{}'",
                input_path.display()
            )
        })?
        .permissions();
    #[cfg(windows)]
    if original_permissions.readonly() {
        let mut replaceable_permissions = original_permissions.clone();
        make_windows_permissions_replaceable(&mut replaceable_permissions);
        std::fs::set_permissions(input_path, replaceable_permissions).with_context(|| {
            format!(
                "cannot temporarily make read-only input '{}' replaceable",
                input_path.display()
            )
        })?;
    }

    // Windows will not replace a destination while either validation handle
    // remains open. Close both only after the identity comparison succeeds.
    drop(current_input);
    drop(original_input);

    let persisted = match temporary.persist(input_path) {
        Ok(file) => file,
        Err(error) => {
            #[cfg(windows)]
            if original_permissions.readonly() {
                let restore_result =
                    std::fs::set_permissions(input_path, original_permissions.clone());
                if let Err(restore_error) = restore_result {
                    bail!(
                        "cannot atomically replace '{}': {}; additionally could not restore its read-only permission: {restore_error}",
                        input_path.display(),
                        error.error
                    );
                }
            }
            return Err(error.error)
                .with_context(|| format!("cannot atomically replace '{}'", input_path.display()));
        }
    };

    #[cfg(windows)]
    {
        persisted
            .set_permissions(original_permissions)
            .with_context(|| {
                format!(
                    "cannot restore permissions after replacing '{}'",
                    input_path.display()
                )
            })?;
        persisted.sync_all().with_context(|| {
            format!(
                "cannot sync restored permissions for '{}'",
                input_path.display()
            )
        })?;
    }
    #[cfg(not(windows))]
    drop(persisted);
    Ok(())
}

#[cfg(windows)]
#[allow(clippy::permissions_set_readonly_false)]
fn make_windows_permissions_replaceable(permissions: &mut std::fs::Permissions) {
    // Clearing `readonly` is the Windows attribute operation required before
    // replacing an existing read-only file; the Unix behavior warned about by
    // this lint cannot be compiled here.
    permissions.set_readonly(false);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replacement_refuses_a_changed_input_path() {
        let directory = tempfile::tempdir().expect("create OTP test directory");
        let input_path = directory.path().join("input");
        std::fs::write(&input_path, b"original").expect("write original input");
        let original_input = open_regular_file(&input_path).expect("open original input");

        std::fs::rename(&input_path, directory.path().join("moved")).expect("move original input");
        std::fs::write(&input_path, b"replacement").expect("write replacement input");

        let mut temporary =
            tempfile::NamedTempFile::new_in(directory.path()).expect("create temporary output");
        temporary
            .write_all(b"transformed")
            .expect("write temporary output");

        let error = persist_otp_output(temporary, &input_path, original_input)
            .expect_err("changed path must be rejected");
        assert!(error.to_string().contains("changed before replacement"));
        assert_eq!(
            std::fs::read(input_path).expect("read replacement input"),
            b"replacement"
        );
    }
}
