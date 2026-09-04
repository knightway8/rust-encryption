use anyhow::{Context, Result, bail};
use std::ffi::OsStr;
use std::fs::File;
use std::io::Write;
use std::path::{Component, Path, PathBuf};

pub(crate) const IO_BUFFER_SIZE: usize = 1024 * 1024;

/// Accept only a single portable filename component. This deliberately rejects
/// absolute paths and directory traversal for identical behavior on all
/// supported operating systems.
pub(crate) fn validate_filename(name: &OsStr) -> Result<()> {
    let text = name
        .to_str()
        .context("filenames must be valid Unicode for cross-platform use")?;
    if text.chars().any(|character| {
        character.is_ascii_control()
            || matches!(
                character,
                '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|'
            )
    }) || text.ends_with(['.', ' '])
    {
        bail!("filename contains characters that are not portable across operating systems");
    }

    let base = text
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    let is_reserved_word = matches!(
        base.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$" | "CONIN$" | "CONOUT$"
    );
    let is_reserved_numbered = base
        .strip_prefix("COM")
        .or_else(|| base.strip_prefix("LPT"))
        .is_some_and(|suffix| {
            matches!(
                suffix,
                "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        });
    if is_reserved_word || is_reserved_numbered {
        bail!("filename is a reserved device name on Windows");
    }

    let path = Path::new(name);
    let mut components = path.components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(_)), None) => Ok(()),
        _ => bail!("files must be specified by filename only and must be in the working directory"),
    }
}

pub(crate) fn local_path(directory: &Path, name: &OsStr) -> Result<PathBuf> {
    validate_filename(name)?;
    Ok(directory.join(name))
}

pub(crate) fn open_regular_file(path: &Path) -> Result<File> {
    let file =
        File::open(path).with_context(|| format!("cannot open input file '{}'", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("cannot inspect input file '{}'", path.display()))?;
    if !metadata.is_file() {
        bail!("'{}' is not a regular file", path.display());
    }
    Ok(file)
}

pub(crate) fn files_are_same(first: &File, second: &File) -> Result<bool> {
    let first = same_file::Handle::from_file(
        first
            .try_clone()
            .context("cannot duplicate the first file handle")?,
    )
    .context("cannot identify the first file")?;
    let second = same_file::Handle::from_file(
        second
            .try_clone()
            .context("cannot duplicate the second file handle")?,
    )
    .context("cannot identify the second file")?;
    Ok(first == second)
}

pub(crate) fn ensure_absent(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => bail!("refusing to overwrite existing file '{}'", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("cannot inspect output path '{}'", path.display()))
        }
    }
}

/// A private temporary output installed only when finish completes.
pub(crate) struct NewOutput {
    path: PathBuf,
    writer: Option<tempfile::NamedTempFile>,
}

impl NewOutput {
    pub(crate) fn create(path: &Path) -> Result<Self> {
        ensure_absent(path)?;
        let parent = path
            .parent()
            .context("output path does not have a parent directory")?;
        let temporary = tempfile::NamedTempFile::new_in(parent)
            .with_context(|| format!("cannot create temporary output in '{}'", parent.display()))?;
        Ok(Self {
            path: path.to_owned(),
            writer: Some(temporary),
        })
    }

    pub(crate) fn writer(&mut self) -> &mut tempfile::NamedTempFile {
        self.writer.as_mut().expect("output writer is present")
    }

    pub(crate) fn finish(mut self) -> Result<()> {
        let mut writer = self.writer.take().expect("output writer is present");
        writer
            .flush()
            .with_context(|| format!("cannot flush output '{}'", self.path.display()))?;
        writer
            .as_file()
            .sync_all()
            .with_context(|| format!("cannot sync output '{}'", self.path.display()))?;
        writer
            .persist_noclobber(&self.path)
            .map_err(|error| error.error)
            .with_context(|| format!("refusing to overwrite output '{}'", self.path.display()))?;

        #[cfg(unix)]
        {
            let parent = self
                .path
                .parent()
                .context("output path does not have a parent directory")?;
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .with_context(|| format!("cannot sync directory '{}'", parent.display()))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_characters_that_are_invalid_in_portable_filenames() {
        for name in [
            "has/slash",
            "has\\backslash",
            "has:colon",
            "has*asterisk",
            "has?question",
            "has\"quote",
            "has<less",
            "has>greater",
            "has|pipe",
            "has\u{1f}control",
        ] {
            assert!(
                validate_filename(OsStr::new(name)).is_err(),
                "accepted nonportable filename {name:?}"
            );
        }
    }

    #[test]
    fn accepts_short_unicode_names_without_panicking() {
        assert!(validate_filename(OsStr::new("abé")).is_ok());
        assert!(validate_filename(OsStr::new("a€")).is_ok());
        assert!(validate_filename(OsStr::new("éé")).is_ok());
    }

    #[test]
    fn rejects_all_windows_numbered_device_spellings() {
        for prefix in ["COM", "LPT"] {
            for suffix in ["1", "2", "3", "4", "5", "6", "7", "8", "9", "¹", "²", "³"] {
                let name = format!("{prefix}{suffix}.key");
                assert!(
                    validate_filename(OsStr::new(&name)).is_err(),
                    "accepted Windows device name {name:?}"
                );
            }
        }
    }
    #[test]
    fn dropping_unfinished_output_removes_the_temporary_file() {
        let directory = tempfile::tempdir().expect("create output test directory");
        let output_path = directory.path().join("output");
        {
            let mut output = NewOutput::create(&output_path).expect("create private output");
            output
                .writer()
                .write_all(b"incomplete")
                .expect("write private output");
        }

        assert!(!output_path.exists());
        assert_eq!(
            std::fs::read_dir(directory.path())
                .expect("list output test directory")
                .count(),
            0
        );
    }

    #[test]
    fn finish_refuses_a_destination_created_after_preflight() {
        let directory = tempfile::tempdir().expect("create output race test directory");
        let output_path = directory.path().join("output");
        let mut output = NewOutput::create(&output_path).expect("create private output");
        output
            .writer()
            .write_all(b"candidate")
            .expect("write private output");
        std::fs::write(&output_path, b"preserve me").expect("create competing output");

        let error = output
            .finish()
            .expect_err("late destination must not be replaced");
        assert!(error.to_string().contains("refusing to overwrite output"));
        assert_eq!(
            std::fs::read(&output_path).expect("read competing output"),
            b"preserve me"
        );
        assert_eq!(
            std::fs::read_dir(directory.path())
                .expect("list output race test directory")
                .count(),
            1,
            "failed no-clobber install left a temporary artifact"
        );
    }

    #[test]
    fn successful_finish_installs_only_the_requested_file() {
        let directory = tempfile::tempdir().expect("create successful output test directory");
        let output_path = directory.path().join("output");
        let mut output = NewOutput::create(&output_path).expect("create private output");
        output
            .writer()
            .write_all(b"complete")
            .expect("write private output");
        output.finish().expect("install complete output");

        assert_eq!(
            std::fs::read(&output_path).expect("read output"),
            b"complete"
        );
        assert_eq!(
            std::fs::read_dir(directory.path())
                .expect("list successful output test directory")
                .count(),
            1
        );
    }
}
