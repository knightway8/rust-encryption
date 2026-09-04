use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};

use crate::error::{FileCryptError, Result};
use crate::staging::{StagedFile, output_parent, path_exists_without_following};

/// Name of the mandatory raw key file located beside the executable.
pub const KEY_FILE_NAME: &str = "key.key";
/// Required raw key length.
pub const KEY_SIZE: usize = 32;
/// Heap-allocated, redacted, zeroizing master key.
pub type MasterKey = SecretBox<[u8; KEY_SIZE]>;

/// Return the mandatory key path beside the currently running executable.
///
/// # Errors
///
/// Returns an error if the operating system cannot locate the executable or
/// the resulting executable path has no parent directory.
pub fn executable_key_path() -> Result<PathBuf> {
    let executable = std::env::current_exe().map_err(|source| {
        FileCryptError::io("locate the running executable", "<executable>", source)
    })?;
    let directory = executable
        .parent()
        .ok_or(FileCryptError::InvalidExecutablePath)?;
    Ok(directory.join(KEY_FILE_NAME))
}

/// Read and validate a raw 32-byte key file.
///
/// # Errors
///
/// Returns an error if the path cannot be opened, is not a regular file, does
/// not contain exactly 32 raw bytes, grants group/other access on Unix, or
/// lacks a protected current-user-only DACL on Windows.
pub fn load_key_file(path: &Path) -> Result<MasterKey> {
    let mut file = match open_key_file(path) {
        Ok(file) => file,
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            return Err(FileCryptError::KeyNotFound(path.to_path_buf()));
        }
        Err(source) => return Err(FileCryptError::io("open key file", path, source)),
    };

    validate_open_key_file(&file, path)?;
    #[cfg(unix)]
    restore_blocking_reads(&file, path)?;

    let mut key = MasterKey::default();
    file.read_exact(key.expose_secret_mut())
        .map_err(|source| FileCryptError::io("read key file", path, source))?;

    let mut extra = [0_u8; 1];
    let extra_len = read_retry(&mut file, &mut extra)
        .map_err(|source| FileCryptError::io("finish reading key file", path, source))?;
    if extra_len != 0 {
        let metadata = file
            .metadata()
            .map_err(|source| FileCryptError::io("inspect key file", path, source))?;
        return Err(FileCryptError::InvalidKeyLength {
            path: path.to_path_buf(),
            // We observed at least one byte beyond the key even if a racing
            // writer truncated the file again before the metadata query.
            actual: metadata.len().max(KEY_SIZE as u64 + 1),
        });
    }

    // Revalidate after reading so a concurrent length or permission change is
    // not silently accepted merely because the opening metadata was safe.
    validate_open_key_file(&file, path)?;
    Ok(key)
}

#[cfg(unix)]
fn open_key_file(path: &Path) -> io::Result<File> {
    use rustix::fs::{Mode, OFlags};

    // A blocking read-only open of a FIFO (including through a symlink) waits
    // forever for a writer before we can reject it as non-regular. NONBLOCK is
    // ignored for ordinary files and lets validation safely inspect specials.
    let descriptor = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )?;
    Ok(File::from(descriptor))
}

#[cfg(unix)]
fn restore_blocking_reads(file: &File, path: &Path) -> Result<()> {
    let flags = rustix::fs::fcntl_getfl(file).map_err(|source| {
        FileCryptError::io(
            "inspect key descriptor flags",
            path,
            io::Error::from(source),
        )
    })?;
    rustix::fs::fcntl_setfl(file, flags.difference(rustix::fs::OFlags::NONBLOCK)).map_err(
        |source| FileCryptError::io("restore blocking key reads", path, io::Error::from(source)),
    )
}

#[cfg(not(unix))]
fn open_key_file(path: &Path) -> io::Result<File> {
    File::open(path)
}

fn validate_open_key_file(file: &File, path: &Path) -> Result<()> {
    let metadata = file
        .metadata()
        .map_err(|source| FileCryptError::io("inspect key file", path, source))?;
    if !metadata.is_file() {
        return Err(FileCryptError::KeyNotRegular(path.to_path_buf()));
    }
    if metadata.len() != KEY_SIZE as u64 {
        return Err(FileCryptError::InvalidKeyLength {
            path: path.to_path_buf(),
            actual: metadata.len(),
        });
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(FileCryptError::InsecureKeyPermissions(path.to_path_buf()));
        }
    }

    #[cfg(windows)]
    {
        let private = crate::windows_security::has_protected_current_user_dacl(file)
            .map_err(|source| FileCryptError::io("inspect key permissions", path, source))?;
        if !private {
            return Err(FileCryptError::InsecureKeyPermissions(path.to_path_buf()));
        }
    }

    Ok(())
}

/// Read the mandatory key beside the currently running executable.
///
/// # Errors
///
/// Returns an error if the executable-relative path cannot be determined or
/// the key fails any check documented by [`load_key_file`].
pub fn load_executable_key() -> Result<MasterKey> {
    let path = executable_key_path()?;
    load_key_file(&path)
}

/// Generate a new raw key file without ever replacing an existing path.
///
/// # Errors
///
/// Returns an error if secure randomness fails, the parent is not a writable
/// directory, any write or synchronization fails, or `path` already exists.
pub fn generate_key_file(path: &Path) -> Result<()> {
    if path.file_name().is_none() {
        return Err(FileCryptError::InvalidOutputPath(path.to_path_buf()));
    }
    let parent = output_parent(path);
    let metadata = fs::metadata(parent)
        .map_err(|source| FileCryptError::io("inspect key directory", parent, source))?;
    if !metadata.is_dir() {
        return Err(FileCryptError::InvalidOutputPath(path.to_path_buf()));
    }

    if path_exists_without_following(path)? {
        return Err(FileCryptError::OutputExists(path.to_path_buf()));
    }

    let mut key = MasterKey::default();
    getrandom::fill(key.expose_secret_mut())
        .map_err(|error| FileCryptError::Random(error.to_string()))?;

    let mut temporary = StagedFile::create(parent, ".filecrypt-key-")?;
    let temporary_path = temporary.path().to_path_buf();

    temporary
        .as_file_mut()
        .write_all(key.expose_secret())
        .map_err(|source| {
            FileCryptError::io("write temporary key file", &temporary_path, source)
        })?;
    temporary.commit(path, "publish key file")
}

/// Generate `key.key` beside the running executable, without replacement.
///
/// # Errors
///
/// Returns an error if the executable-relative path cannot be determined or
/// key creation fails as documented by [`generate_key_file`].
pub fn generate_executable_key() -> Result<PathBuf> {
    let path = executable_key_path()?;
    generate_key_file(&path)?;
    Ok(path)
}

fn read_retry(reader: &mut impl Read, buffer: &mut [u8]) -> io::Result<usize> {
    loop {
        match reader.read(buffer) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            result => return result,
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;
    use std::sync::{Arc, Barrier};
    use std::thread;

    const STAGING_PREFIX: &str = ".filecrypt-key-";

    fn write_private_key(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).expect("write test key");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("protect test key");
        }
        #[cfg(windows)]
        {
            let file = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)
                .expect("open test key for DACL protection");
            crate::windows_security::protect_file(&file).expect("protect test key DACL");
        }
    }

    fn assert_no_key_staging_directories(parent: &Path) {
        let leaked = fs::read_dir(parent)
            .expect("list key parent")
            .filter_map(std::result::Result::ok)
            .any(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(STAGING_PREFIX)
            });
        assert!(!leaked, "key generation leaked a staging directory");
    }

    #[test]
    fn executable_key_path_is_beside_the_running_test_binary() {
        let executable = std::env::current_exe().expect("locate test executable");
        let expected = executable
            .parent()
            .expect("test executable directory")
            .join(KEY_FILE_NAME);

        assert_eq!(
            executable_key_path().expect("derive executable key path"),
            expected
        );
    }

    #[test]
    fn loader_preserves_all_binary_key_bytes() {
        let parent = tempfile::tempdir().expect("test parent");
        let path = parent.path().join("binary.key");
        let mut bytes = [0_u8; KEY_SIZE];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = index.wrapping_mul(197).to_le_bytes()[0];
        }
        bytes[3] = b'\n';
        bytes[17] = 0xff;
        write_private_key(&path, &bytes);

        let loaded = load_key_file(&path).expect("load binary key");

        assert_eq!(loaded.expose_secret(), &bytes);
    }

    #[test]
    fn loader_reports_missing_key_path() {
        let parent = tempfile::tempdir().expect("test parent");
        let path = parent.path().join("missing.key");

        let error = load_key_file(&path).expect_err("missing key must fail");

        assert!(matches!(error, FileCryptError::KeyNotFound(found) if found == path));
    }

    #[cfg(unix)]
    #[test]
    fn loader_rejects_directories_and_character_devices() {
        let parent = tempfile::tempdir().expect("test parent");
        let directory_error =
            load_key_file(parent.path()).expect_err("a directory is not a key file");
        assert!(matches!(directory_error, FileCryptError::KeyNotRegular(_)));

        if Path::new("/dev/null").exists() {
            let device_error = load_key_file(Path::new("/dev/null"))
                .expect_err("a character device is not a key file");
            assert!(matches!(device_error, FileCryptError::KeyNotRegular(_)));
        }
    }

    #[test]
    fn loader_reports_every_observed_wrong_length() {
        let parent = tempfile::tempdir().expect("test parent");

        for length in [0_usize, 1, KEY_SIZE - 1, KEY_SIZE + 1, 255] {
            let path = parent.path().join(format!("key-{length}"));
            write_private_key(&path, &vec![0x5a; length]);

            let error = load_key_file(&path).expect_err("wrong key length must fail");

            assert!(matches!(
                error,
                FileCryptError::InvalidKeyLength { path: found, actual }
                    if found == path && actual == length as u64
            ));
        }
    }

    #[cfg(unix)]
    #[test]
    fn loader_rejects_each_group_or_other_permission_class() {
        use std::os::unix::fs::PermissionsExt;

        let parent = tempfile::tempdir().expect("test parent");
        let path = parent.path().join("permissions.key");
        fs::write(&path, [0x41; KEY_SIZE]).expect("write test key");

        for mode in [
            0o601, 0o602, 0o604, 0o610, 0o620, 0o640, 0o701, 0o710, 0o740, 0o777,
        ] {
            fs::set_permissions(&path, fs::Permissions::from_mode(mode))
                .expect("set exposed key mode");
            let error = load_key_file(&path).expect_err("exposed key must fail");
            assert!(matches!(
                error,
                FileCryptError::InsecureKeyPermissions(found) if found == path
            ));
        }
    }

    #[cfg(unix)]
    #[test]
    fn loader_accepts_owner_only_permission_variants() {
        use std::os::unix::fs::PermissionsExt;

        let parent = tempfile::tempdir().expect("test parent");
        let path = parent.path().join("private.key");
        let bytes = [0x93; KEY_SIZE];
        fs::write(&path, bytes).expect("write test key");

        for mode in [0o400, 0o600, 0o700] {
            fs::set_permissions(&path, fs::Permissions::from_mode(mode))
                .expect("set private key mode");
            assert_eq!(
                load_key_file(&path)
                    .expect("load owner-only key")
                    .expose_secret(),
                &bytes
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn loader_follows_a_symlink_only_to_a_valid_private_regular_file() {
        use std::os::unix::fs::symlink;

        let parent = tempfile::tempdir().expect("test parent");
        let target = parent.path().join("target.key");
        let link = parent.path().join("link.key");
        let bytes = [0x2d; KEY_SIZE];
        write_private_key(&target, &bytes);
        symlink(&target, &link).expect("create key symlink");

        assert_eq!(
            load_key_file(&link)
                .expect("load private key through symlink")
                .expose_secret(),
            &bytes
        );
    }

    #[cfg(unix)]
    #[test]
    fn accepted_regular_key_has_blocking_reads_restored() {
        let parent = tempfile::tempdir().expect("test parent");
        let path = parent.path().join("blocking.key");
        write_private_key(&path, &[0x52; KEY_SIZE]);
        let file = open_key_file(&path).expect("open key nonblocking");
        let opening_flags = rustix::fs::fcntl_getfl(&file).expect("inspect opening flags");
        assert!(opening_flags.contains(rustix::fs::OFlags::NONBLOCK));

        validate_open_key_file(&file, &path).expect("validate regular key");
        restore_blocking_reads(&file, &path).expect("restore blocking reads");

        let restored_flags = rustix::fs::fcntl_getfl(&file).expect("inspect restored flags");
        assert!(!restored_flags.contains(rustix::fs::OFlags::NONBLOCK));
    }

    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[test]
    fn loader_rejects_direct_and_symlinked_fifos_without_blocking() {
        use rustix::fs::{CWD, Mode, mkfifoat};
        use std::os::unix::fs::symlink;
        use std::sync::mpsc::{self, RecvTimeoutError};
        use std::time::Duration;

        fn assert_rejected_without_blocking(path: &Path, fifo: &Path) {
            let (sender, receiver) = mpsc::channel();
            let path = path.to_path_buf();
            let loader = thread::spawn(move || {
                let rejected = matches!(
                    load_key_file(&path),
                    Err(FileCryptError::KeyNotRegular(found)) if found == path
                );
                sender.send(rejected).expect("send FIFO load result");
            });

            let completed = match receiver.recv_timeout(Duration::from_secs(2)) {
                Ok(rejected) => {
                    assert!(rejected, "FIFO returned an unexpected error");
                    true
                }
                Err(RecvTimeoutError::Timeout) => {
                    // Release a loader that regressed to a blocking read-only
                    // open so the test can fail without hanging the suite.
                    let writer = fs::OpenOptions::new()
                        .write(true)
                        .open(fifo)
                        .expect("open FIFO writer to release blocked loader");
                    drop(writer);
                    false
                }
                Err(RecvTimeoutError::Disconnected) => false,
            };
            loader.join().expect("join FIFO loader");
            assert!(completed, "loading a FIFO blocked or failed to report");
        }

        let parent = tempfile::tempdir().expect("test parent");
        let fifo = parent.path().join("key.fifo");
        let link = parent.path().join("key-link");
        mkfifoat(CWD, &fifo, Mode::RUSR | Mode::WUSR).expect("create test FIFO");
        symlink(&fifo, &link).expect("create FIFO symlink");

        assert_rejected_without_blocking(&fifo, &fifo);
        assert_rejected_without_blocking(&link, &fifo);
    }

    #[cfg(unix)]
    #[test]
    fn post_read_validation_detects_length_and_permission_changes() {
        use std::os::unix::fs::PermissionsExt;

        let parent = tempfile::tempdir().expect("test parent");
        let path = parent.path().join("racing.key");
        write_private_key(&path, &[0x77; KEY_SIZE]);
        let file = open_key_file(&path).expect("open key");
        validate_open_key_file(&file, &path).expect("validate initial key");

        fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("open key for append")
            .write_all(&[0])
            .expect("extend key");
        let length_error =
            validate_open_key_file(&file, &path).expect_err("extended key must fail validation");
        assert!(matches!(
            length_error,
            FileCryptError::InvalidKeyLength { actual, .. } if actual == KEY_SIZE as u64 + 1
        ));

        fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path)
            .expect("open key for rewrite")
            .write_all(&[0x77; KEY_SIZE])
            .expect("rewrite key");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o604))
            .expect("expose key permissions");
        let permission_error = validate_open_key_file(&file, &path)
            .expect_err("permission change must fail validation");
        assert!(matches!(
            permission_error,
            FileCryptError::InsecureKeyPermissions(found) if found == path
        ));
    }

    #[test]
    fn read_retry_retries_interrupts_and_returns_data() {
        struct InterruptingReader {
            interruptions: usize,
            bytes: &'static [u8],
        }

        impl Read for InterruptingReader {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                if self.interruptions != 0 {
                    self.interruptions -= 1;
                    return Err(io::ErrorKind::Interrupted.into());
                }
                let amount = buffer.len().min(self.bytes.len());
                buffer[..amount].copy_from_slice(&self.bytes[..amount]);
                self.bytes = &self.bytes[amount..];
                Ok(amount)
            }
        }

        let mut reader = InterruptingReader {
            interruptions: 4,
            bytes: b"key",
        };
        let mut buffer = [0_u8; 3];

        assert_eq!(read_retry(&mut reader, &mut buffer).expect("retry read"), 3);
        assert_eq!(&buffer, b"key");
    }

    #[test]
    fn read_retry_propagates_non_interrupt_errors() {
        struct FailingReader;

        impl Read for FailingReader {
            fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
                Err(io::ErrorKind::PermissionDenied.into())
            }
        }

        let error = read_retry(&mut FailingReader, &mut [0_u8; 1])
            .expect_err("non-interrupt error must be returned");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn key_generation_validates_output_paths_before_staging() {
        let parent = tempfile::tempdir().expect("test parent");
        let ordinary_file = parent.path().join("ordinary-file");
        fs::write(&ordinary_file, b"sentinel").expect("write parent sentinel");

        let empty_error =
            generate_key_file(Path::new("")).expect_err("empty output path must fail");
        assert!(
            matches!(empty_error, FileCryptError::InvalidOutputPath(path) if path.as_os_str().is_empty())
        );

        let child = ordinary_file.join("child.key");
        let file_parent_error =
            generate_key_file(&child).expect_err("regular-file parent must fail");
        assert!(matches!(
            file_parent_error,
            FileCryptError::InvalidOutputPath(found) if found == child
        ));

        let missing_parent = parent.path().join("missing").join("child.key");
        let missing_parent_error =
            generate_key_file(&missing_parent).expect_err("missing parent must fail");
        assert!(matches!(missing_parent_error, FileCryptError::Io { .. }));
        assert_no_key_staging_directories(parent.path());
    }

    #[test]
    fn key_generation_preserves_existing_files_and_directories() {
        let parent = tempfile::tempdir().expect("test parent");
        let existing_file = parent.path().join("existing.key");
        let existing_directory = parent.path().join("existing-directory");
        fs::write(&existing_file, b"sentinel").expect("write existing file");
        fs::create_dir(&existing_directory).expect("create existing directory");

        for path in [&existing_file, &existing_directory] {
            let error = generate_key_file(path).expect_err("existing output must fail");
            assert!(matches!(
                error,
                FileCryptError::OutputExists(found) if found == *path
            ));
        }
        assert_eq!(
            fs::read(&existing_file).expect("read existing file"),
            b"sentinel"
        );
        assert!(existing_directory.is_dir());
        assert_no_key_staging_directories(parent.path());
    }

    #[cfg(unix)]
    #[test]
    fn key_generation_preserves_dangling_symlink_destinations() {
        use std::os::unix::fs::symlink;

        let parent = tempfile::tempdir().expect("test parent");
        let path = parent.path().join("key-link");
        let target = parent.path().join("missing-target");
        symlink(&target, &path).expect("create dangling destination symlink");

        let error = generate_key_file(&path).expect_err("existing symlink must fail");

        assert!(matches!(error, FileCryptError::OutputExists(found) if found == path));
        assert!(
            fs::symlink_metadata(&path)
                .expect("symlink metadata")
                .file_type()
                .is_symlink()
        );
        assert!(!target.exists());
        assert_no_key_staging_directories(parent.path());
    }

    #[test]
    fn generated_key_round_trips_and_leaves_no_staging_directory() {
        let parent = tempfile::tempdir().expect("test parent");
        let path = parent.path().join("generated.key");

        generate_key_file(&path).expect("generate key");
        let raw = fs::read(&path).expect("read generated key");
        let loaded = load_key_file(&path).expect("load generated key");

        assert_eq!(raw.len(), KEY_SIZE);
        assert_eq!(loaded.expose_secret(), raw.as_slice());
        assert_no_key_staging_directories(parent.path());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            assert_eq!(
                fs::metadata(&path)
                    .expect("generated key metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn concurrent_key_generation_has_one_winner_and_no_leaks() {
        const ATTEMPTS: usize = 12;

        let parent = tempfile::tempdir().expect("test parent");
        let path = parent.path().join("contended.key");
        let barrier = Arc::new(Barrier::new(ATTEMPTS));
        let mut threads = Vec::with_capacity(ATTEMPTS);

        for _ in 0..ATTEMPTS {
            let path = path.clone();
            let barrier = Arc::clone(&barrier);
            threads.push(thread::spawn(move || {
                barrier.wait();
                generate_key_file(&path)
            }));
        }

        let mut successes = 0;
        let mut existing_errors = 0;
        let mut unexpected_errors = Vec::new();
        for thread in threads {
            match thread.join().expect("join key generator") {
                Ok(()) => successes += 1,
                Err(FileCryptError::OutputExists(found)) => {
                    assert_eq!(found, path);
                    existing_errors += 1;
                }
                Err(other) => unexpected_errors.push(format!("{other:?}")),
            }
        }

        assert!(
            unexpected_errors.is_empty(),
            "unexpected key generation errors: {unexpected_errors:?}"
        );
        assert_eq!(successes, 1);
        assert_eq!(existing_errors, ATTEMPTS - 1);
        assert_eq!(
            fs::metadata(&path).expect("winner metadata").len(),
            KEY_SIZE as u64
        );
        load_key_file(&path).expect("load winning key");
        assert_no_key_staging_directories(parent.path());
    }
}
