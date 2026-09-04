use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use same_file::Handle;

use crate::error::{FileCryptError, Result};

#[cfg(not(windows))]
type PrivateTempDir = tempfile::TempDir;

#[cfg(windows)]
struct PrivateTempDir {
    path: tempfile::TempPath,
}

#[cfg(windows)]
impl PrivateTempDir {
    fn path(&self) -> &Path {
        self.path.as_ref()
    }
}

#[cfg(windows)]
impl Drop for PrivateTempDir {
    fn drop(&mut self) {
        // `TempPath` removes files, not directories. Remove the directory and
        // all unpublished staging contents before its own harmless cleanup.
        let _ = fs::remove_dir_all(self.path());
    }
}

/// A synchronized file held inside a private, same-filesystem staging directory.
pub(crate) struct StagedFile {
    // Fields are dropped in declaration order: close the file before removing its directory.
    file: File,
    path: PathBuf,
    _directory: PrivateTempDir,
}

impl StagedFile {
    pub(crate) fn create(parent: &Path, prefix: &str) -> Result<Self> {
        let directory = create_private_temp_dir(parent, prefix)?;

        let path = directory.path().join("payload.tmp");
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options
            .open(&path)
            .map_err(|source| FileCryptError::io("create protected staging file", &path, source))?;
        protect_file(&file, &path)?;

        Ok(Self {
            file,
            path,
            _directory: directory,
        })
    }

    pub(crate) fn as_file_mut(&mut self) -> &mut File {
        &mut self.file
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Sync and publish without replacement, checking the file identity before and after.
    pub(crate) fn commit(mut self, destination: &Path, action: &'static str) -> Result<()> {
        self.file.flush().map_err(|source| {
            FileCryptError::io("flush staged output", self.path.clone(), source)
        })?;
        self.file.sync_all().map_err(|source| {
            FileCryptError::io("synchronize staged output", self.path.clone(), source)
        })?;

        let identity = Handle::from_file(self.file.try_clone().map_err(|source| {
            FileCryptError::io("duplicate staged output handle", self.path.clone(), source)
        })?)
        .map_err(|source| {
            FileCryptError::io("identify staged output", self.path.clone(), source)
        })?;
        let path_identity =
            Handle::from_path(&self.path).map_err(|_| FileCryptError::StagingFileReplaced)?;
        if identity != path_identity {
            return Err(FileCryptError::StagingFileReplaced);
        }

        match atomicwrites::move_atomic(&self.path, destination) {
            Ok(()) => {
                let published_identity = Handle::from_path(destination)
                    .map_err(|_| FileCryptError::PublicationIdentityMismatch(destination.into()))?;
                if identity != published_identity {
                    return Err(FileCryptError::PublicationIdentityMismatch(
                        destination.to_path_buf(),
                    ));
                }
                Ok(())
            }
            Err(source) => {
                // Some filesystems can report a late durability/unlink failure after the
                // no-clobber destination entry has already been installed.
                if Handle::from_path(destination).is_ok_and(|published| published == identity) {
                    return Err(FileCryptError::PublishedButDurabilityUncertain {
                        path: destination.to_path_buf(),
                        source,
                    });
                }
                if source.kind() == io::ErrorKind::AlreadyExists {
                    Err(FileCryptError::OutputExists(destination.to_path_buf()))
                } else {
                    Err(FileCryptError::io(action, destination, source))
                }
            }
        }
    }
}

#[cfg(not(windows))]
fn create_private_temp_dir(parent: &Path, prefix: &str) -> Result<PrivateTempDir> {
    let mut builder = tempfile::Builder::new();
    builder.prefix(prefix);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        // `tempfile` otherwise requests 0o777 for directories and relies on
        // the process umask. Request owner-only access in the creation syscall
        // so there is no create-then-chmod exposure window.
        builder.permissions(fs::Permissions::from_mode(0o700));
    }

    let directory = builder.tempdir_in(parent).map_err(|source| {
        FileCryptError::io("create protected staging directory", parent, source)
    })?;
    protect_directory(directory.path())?;
    Ok(directory)
}

#[cfg(windows)]
fn create_private_temp_dir(parent: &Path, prefix: &str) -> Result<PrivateTempDir> {
    // `tempfile::TempDir` creates with an inherited DACL and can only tighten
    // it afterward. Use its collision-resistant path generator with an atomic
    // Windows creation routine that supplies the private DACL up front.
    let directory = tempfile::Builder::new()
        .prefix(prefix)
        .make_in(parent, crate::windows_security::create_protected_directory)
        .map_err(|source| {
            FileCryptError::io("create protected staging directory", parent, source)
        })?;
    let ((), path) = directory.into_parts();
    Ok(PrivateTempDir { path })
}

pub(crate) fn output_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

pub(crate) fn path_exists_without_following(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(FileCryptError::io("inspect destination", path, source)),
    }
}

#[cfg(unix)]
fn protect_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|source| FileCryptError::io("protect staging directory", path, source))
}

#[cfg(not(any(unix, windows)))]
fn protect_directory(path: &Path) -> Result<()> {
    let _ = path;
    Ok(())
}

#[cfg(unix)]
fn protect_file(file: &File, path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|source| FileCryptError::io("protect staging file", path, source))
}

#[cfg(windows)]
fn protect_file(file: &File, path: &Path) -> Result<()> {
    crate::windows_security::protect_file(file)
        .map_err(|source| FileCryptError::io("protect staging file", path, source))
}

#[cfg(not(any(unix, windows)))]
fn protect_file(file: &File, path: &Path) -> Result<()> {
    let _ = (file, path);
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;

    const PREFIX: &str = ".filecrypt-staging-test-";

    fn assert_no_staging_directories(parent: &Path) {
        let leaked = fs::read_dir(parent)
            .expect("list staging parent")
            .filter_map(std::result::Result::ok)
            .any(|entry| entry.file_name().to_string_lossy().starts_with(PREFIX));
        assert!(!leaked, "a staging directory was not cleaned up");
    }

    #[test]
    fn output_parent_handles_bare_and_nested_paths() {
        assert_eq!(output_parent(Path::new("output")), Path::new("."));
        assert_eq!(
            output_parent(Path::new("directory/output")),
            Path::new("directory")
        );
        assert_eq!(output_parent(Path::new("")), Path::new("."));
        assert_eq!(output_parent(Path::new(".")), Path::new("."));
    }

    #[test]
    fn path_existence_distinguishes_missing_and_present_entries() {
        let parent = tempfile::tempdir().expect("test parent");
        let missing = parent.path().join("missing");
        let file = parent.path().join("file");
        let directory = parent.path().join("directory");
        fs::write(&file, b"contents").expect("write file");
        fs::create_dir(&directory).expect("create directory");

        assert!(!path_exists_without_following(&missing).expect("inspect missing path"));
        assert!(path_exists_without_following(&file).expect("inspect file path"));
        assert!(path_exists_without_following(&directory).expect("inspect directory path"));
    }

    #[cfg(unix)]
    #[test]
    fn path_existence_does_not_follow_dangling_symlinks() {
        use std::os::unix::fs::symlink;

        let parent = tempfile::tempdir().expect("test parent");
        let link = parent.path().join("dangling");
        symlink(parent.path().join("absent-target"), &link).expect("create dangling symlink");

        assert!(path_exists_without_following(&link).expect("inspect dangling symlink"));
    }

    #[test]
    fn dropping_an_uncommitted_file_removes_all_staging_entries() {
        let parent = tempfile::tempdir().expect("test parent");
        let staging_directory = {
            let mut staged = StagedFile::create(parent.path(), PREFIX).expect("create staged file");
            staged
                .as_file_mut()
                .write_all(b"unpublished secret")
                .expect("write staged bytes");
            let directory = staged
                .path()
                .parent()
                .expect("staging directory")
                .to_path_buf();
            assert!(directory.exists());
            directory
        };

        assert!(!staging_directory.exists());
        assert_no_staging_directories(parent.path());
    }

    #[test]
    fn committing_publishes_exact_bytes_and_removes_staging_directory() {
        let parent = tempfile::tempdir().expect("test parent");
        let destination = parent.path().join("destination");
        let mut staged = StagedFile::create(parent.path(), PREFIX).expect("create staged file");
        let staging_directory = staged
            .path()
            .parent()
            .expect("staging directory")
            .to_path_buf();
        staged
            .as_file_mut()
            .write_all(b"complete synchronized output")
            .expect("write staged bytes");

        staged
            .commit(&destination, "publish test output")
            .expect("commit staged output");

        assert_eq!(
            fs::read(&destination).expect("read destination"),
            b"complete synchronized output"
        );
        assert!(!staging_directory.exists());
        assert_no_staging_directories(parent.path());
    }

    #[cfg(unix)]
    #[test]
    fn staging_directory_and_file_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let parent = tempfile::tempdir().expect("test parent");
        let mut staged = StagedFile::create(parent.path(), PREFIX).expect("create staged file");
        let directory_mode = fs::metadata(staged.path().parent().expect("staging directory"))
            .expect("staging directory metadata")
            .permissions()
            .mode()
            & 0o777;
        let file_mode = staged
            .as_file_mut()
            .metadata()
            .expect("staging file metadata")
            .permissions()
            .mode()
            & 0o777;

        assert_eq!(directory_mode, 0o700);
        assert_eq!(file_mode, 0o600);
    }

    #[test]
    fn existing_destination_is_preserved_and_staging_is_cleaned() {
        let parent = tempfile::tempdir().expect("test parent");
        let destination = parent.path().join("destination");
        fs::write(&destination, b"existing sentinel").expect("write destination sentinel");
        let mut staged = StagedFile::create(parent.path(), PREFIX).expect("create staged file");
        staged
            .as_file_mut()
            .write_all(b"new output")
            .expect("write staged bytes");

        let error = staged
            .commit(&destination, "publish test output")
            .expect_err("existing destination must not be replaced");

        assert!(matches!(error, FileCryptError::OutputExists(path) if path == destination));
        assert_eq!(
            fs::read(&destination).expect("read destination sentinel"),
            b"existing sentinel"
        );
        assert_no_staging_directories(parent.path());
    }

    #[cfg(unix)]
    #[test]
    fn existing_symlink_destination_is_preserved() {
        use std::os::unix::fs::symlink;

        let parent = tempfile::tempdir().expect("test parent");
        let target = parent.path().join("target");
        let destination = parent.path().join("destination");
        fs::write(&target, b"target sentinel").expect("write target sentinel");
        symlink(&target, &destination).expect("create destination symlink");
        let mut staged = StagedFile::create(parent.path(), PREFIX).expect("create staged file");
        staged
            .as_file_mut()
            .write_all(b"new output")
            .expect("write staged bytes");

        let error = staged
            .commit(&destination, "publish test output")
            .expect_err("symlink destination must not be replaced");

        assert!(matches!(error, FileCryptError::OutputExists(path) if path == destination));
        assert_eq!(
            fs::read(&target).expect("read target sentinel"),
            b"target sentinel"
        );
        assert!(
            fs::symlink_metadata(&destination)
                .expect("destination metadata")
                .file_type()
                .is_symlink()
        );
        assert_no_staging_directories(parent.path());
    }

    #[test]
    fn missing_staging_path_is_never_published_and_is_cleaned() {
        let parent = tempfile::tempdir().expect("test parent");
        let destination = parent.path().join("destination");
        let staged = StagedFile::create(parent.path(), PREFIX).expect("create staged file");
        fs::remove_file(staged.path()).expect("unlink staging name");

        let error = staged
            .commit(&destination, "publish test output")
            .expect_err("missing staging name must be detected");

        assert!(matches!(error, FileCryptError::StagingFileReplaced));
        assert!(!destination.exists());
        assert_no_staging_directories(parent.path());
    }

    #[test]
    fn replaced_staging_path_is_never_published() {
        let parent = tempfile::tempdir().expect("test parent");
        let destination = parent.path().join("destination");
        let mut staged = StagedFile::create(parent.path(), PREFIX).expect("create staged file");
        staged
            .as_file_mut()
            .write_all(b"authenticated bytes")
            .expect("write staged bytes");

        fs::remove_file(staged.path()).expect("unlink staging name");
        fs::write(staged.path(), b"attacker replacement").expect("replace staging name");

        let error = staged
            .commit(&destination, "publish test output")
            .expect_err("replacement must be detected");
        assert!(matches!(error, FileCryptError::StagingFileReplaced));
        assert!(!destination.exists());
        assert_no_staging_directories(parent.path());
    }

    #[test]
    fn concurrent_commits_have_exactly_one_winner_without_leaks() {
        const ATTEMPTS: usize = 12;

        let parent = tempfile::tempdir().expect("test parent");
        let destination = parent.path().join("destination");
        let barrier = Arc::new(Barrier::new(ATTEMPTS));
        let mut threads = Vec::with_capacity(ATTEMPTS);

        for candidate in 0..ATTEMPTS {
            let parent = parent.path().to_path_buf();
            let destination = destination.clone();
            let barrier = Arc::clone(&barrier);
            threads.push(thread::spawn(move || {
                let payload = format!("candidate-{candidate}").into_bytes();
                let mut staged =
                    StagedFile::create(&parent, PREFIX).expect("create concurrent staged file");
                staged
                    .as_file_mut()
                    .write_all(&payload)
                    .expect("write concurrent staged bytes");
                barrier.wait();
                (
                    payload,
                    staged.commit(&destination, "publish concurrent test output"),
                )
            }));
        }

        let mut winner = None;
        let mut existing_errors = 0;
        let mut unexpected_errors = Vec::new();
        for thread in threads {
            let (payload, result) = thread.join().expect("join concurrent commit");
            match result {
                Ok(()) => {
                    assert!(
                        winner.replace(payload).is_none(),
                        "more than one commit won"
                    );
                }
                Err(FileCryptError::OutputExists(path)) => {
                    assert_eq!(path, destination);
                    existing_errors += 1;
                }
                Err(other) => unexpected_errors.push(format!("{other:?}")),
            }
        }

        assert!(
            unexpected_errors.is_empty(),
            "unexpected commit errors: {unexpected_errors:?}"
        );
        let winner = winner.expect("one commit must win");
        assert_eq!(existing_errors, ATTEMPTS - 1);
        assert_eq!(fs::read(&destination).expect("read winner"), winner);
        assert_no_staging_directories(parent.path());
    }

    #[test]
    fn invalid_parent_cannot_leave_a_staging_directory() {
        let parent = tempfile::tempdir().expect("test parent");
        let not_a_directory = parent.path().join("ordinary-file");
        fs::write(&not_a_directory, b"sentinel").expect("write parent sentinel");

        let result = StagedFile::create(&not_a_directory, PREFIX);
        assert!(
            result.is_err(),
            "a regular file cannot contain staging data"
        );
        let Err(error) = result else { return };

        assert!(matches!(error, FileCryptError::Io { .. }));
        assert_eq!(
            fs::read(&not_a_directory).expect("read parent sentinel"),
            b"sentinel"
        );
        assert_no_staging_directories(parent.path());
    }
}
