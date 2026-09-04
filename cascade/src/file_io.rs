use std::{
    fs::{self, OpenOptions},
    io::Read,
    path::Path,
};

use zeroize::Zeroizing;

#[cfg(unix)]
use std::{
    ffi::{OsStr, OsString},
    io::Write,
    os::unix::ffi::OsStrExt,
    path::PathBuf,
};

use crate::error::AppError;

#[cfg(unix)]
use crate::unix_fs::{
    BindDirectoryError, BoundDir, CreateTemporaryError, PreInstallFailure, PublishError,
    TemporaryCleanupError,
};

/// Deliberate bound for the non-streaming design. This also bounds malformed-file
/// memory use before authentication.
pub const MAX_FILE_BYTES: u64 = 1024 * 1024 * 1024;

pub fn read_regular_file(path: &Path) -> Result<Zeroizing<Vec<u8>>, AppError> {
    let path_metadata = fs::symlink_metadata(path).map_err(|source| AppError::Metadata {
        path: path.to_path_buf(),
        source,
    })?;
    if path_metadata.file_type().is_symlink() {
        return Err(AppError::SymlinkInput(path.to_path_buf()));
    }
    // Check before opening so FIFOs/devices cannot block or trigger side effects.
    // The handle is checked again below to close the path-swap race.
    if !path_metadata.is_file() {
        return Err(AppError::NotRegularFile(path.to_path_buf()));
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(|source| AppError::Open {
        path: path.to_path_buf(),
        source,
    })?;
    let metadata = file.metadata().map_err(|source| AppError::Metadata {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(AppError::NotRegularFile(path.to_path_buf()));
    }
    #[cfg(unix)]
    validate_same_file(path, &path_metadata, &metadata)?;
    if metadata.len() > MAX_FILE_BYTES {
        return Err(AppError::InputTooLarge);
    }

    let capacity = usize::try_from(metadata.len()).map_err(|_| AppError::InputTooLarge)?;
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| AppError::Allocation)?;
    file.take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| AppError::Read {
            path: path.to_path_buf(),
            source,
        })?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(AppError::InputTooLarge);
    }
    Ok(bytes)
}

/// A destination whose actual parent directory has been opened and validated.
/// Binding creates no filesystem entry, which lets decryption authenticate
/// before any plaintext output is created.
#[cfg(unix)]
#[derive(Debug)]
pub(crate) struct OutputTarget {
    directory: BoundDir,
    name: OsString,
    display_path: PathBuf,
}

#[cfg(not(unix))]
#[derive(Debug)]
pub(crate) struct OutputTarget;

#[cfg(unix)]
impl OutputTarget {
    pub(crate) fn bind(path: &Path) -> Result<Self, AppError> {
        let (parent, name) = output_parts(path)?;
        let directory = BoundDir::open_private(&parent).map_err(|error| match error {
            BindDirectoryError::Io(source) => AppError::Metadata {
                path: parent.clone(),
                source,
            },
            BindDirectoryError::NotDirectory => AppError::NotDirectory(parent.clone()),
            BindDirectoryError::WrongOwner { expected, actual } => {
                AppError::WrongOutputDirectoryOwner {
                    path: parent.clone(),
                    expected,
                    actual,
                }
            }
            BindDirectoryError::InsecureMode { mode } => AppError::InsecureOutputDirectory {
                path: parent.clone(),
                mode,
            },
        })?;

        match directory.stat_nofollow(&name) {
            Ok(_) => return Err(AppError::OutputExists(path.to_path_buf())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(AppError::Metadata {
                    path: path.to_path_buf(),
                    source,
                });
            }
        }

        Ok(Self {
            directory,
            name,
            display_path: path.to_path_buf(),
        })
    }

    /// Write a private temporary file, sync it, atomically publish it without
    /// clobbering any entry, then sync the same retained directory handle.
    pub(crate) fn write_atomic_noclobber(&self, contents: &[u8]) -> Result<(), AppError> {
        let mut temporary = self
            .directory
            .create_private_temp(".cascade-output-")
            .map_err(|error| match error {
                CreateTemporaryError::Random => AppError::Random,
                CreateTemporaryError::Io(source) => AppError::CreateOutput {
                    path: self.directory.display_path().to_path_buf(),
                    source,
                },
                CreateTemporaryError::IoAndCleanupFailed { source, cleanup } => {
                    output_cleanup_failure(
                        &self.display_path,
                        format!("could not secure temporary output: {source}"),
                        cleanup,
                    )
                }
            })?;

        let write_result = temporary.file_mut().write_all(contents);
        let write_result = match write_result {
            Ok(()) => temporary.file().sync_all(),
            Err(error) => Err(error),
        };
        if let Err(source) = write_result {
            let primary = format!("could not write and sync temporary output: {source}");
            return match temporary.cleanup() {
                Ok(()) => Err(AppError::WriteOutput {
                    path: self.display_path.clone(),
                    source,
                }),
                Err(cleanup) => Err(output_cleanup_failure(&self.display_path, primary, cleanup)),
            };
        }

        match self.directory.publish_noclobber(temporary, &self.name) {
            Ok(()) => {}
            Err(PublishError::BeforeInstall { failure, cleanup }) => {
                if let Some(cleanup) = cleanup {
                    let primary = match &failure {
                        PreInstallFailure::Exists => "output target already existed".to_owned(),
                        PreInstallFailure::Io(source) => {
                            format!("could not commit output: {source}")
                        }
                    };
                    return Err(output_cleanup_failure(&self.display_path, primary, cleanup));
                }
                return match failure {
                    PreInstallFailure::Exists => {
                        Err(AppError::OutputExists(self.display_path.clone()))
                    }
                    PreInstallFailure::Io(source) => Err(AppError::CommitOutput {
                        path: self.display_path.clone(),
                        source,
                    }),
                };
            }
            Err(PublishError::InstalledButTemporaryRemains(cleanup)) => {
                return Err(AppError::OutputInstalledButTemporaryRemains {
                    path: self.display_path.clone(),
                    temporary_name: cleanup.temporary_name,
                    source: cleanup.source,
                });
            }
        }

        self.directory
            .sync()
            .map_err(|source| AppError::OutputInstalledButNotSynced {
                path: self.display_path.clone(),
                source,
            })
    }
}

#[cfg(unix)]
fn output_cleanup_failure(
    path: &Path,
    primary: String,
    cleanup: TemporaryCleanupError,
) -> AppError {
    AppError::OutputTemporaryCleanupFailed {
        path: path.to_path_buf(),
        temporary_name: cleanup.temporary_name,
        primary,
        cleanup_source: cleanup.source,
    }
}

#[cfg(not(unix))]
impl OutputTarget {
    pub(crate) fn bind(_path: &Path) -> Result<Self, AppError> {
        Err(AppError::UnsupportedPlatform)
    }

    pub(crate) fn write_atomic_noclobber(&self, _contents: &[u8]) -> Result<(), AppError> {
        Err(AppError::UnsupportedPlatform)
    }
}

/// Convenience wrapper used by focused unit tests and internal callers which
/// do not need to retain a destination across other work.
#[cfg(all(test, unix))]
fn write_atomic_noclobber(path: &Path, contents: &[u8]) -> Result<(), AppError> {
    OutputTarget::bind(path)?.write_atomic_noclobber(contents)
}

#[cfg(unix)]
fn output_parts(path: &Path) -> Result<(PathBuf, OsString), AppError> {
    let raw_path = path.as_os_str().as_bytes();
    if raw_path.ends_with(b"/")
        || has_terminal_component(raw_path, b".")
        || has_terminal_component(raw_path, b"..")
    {
        return Err(AppError::InvalidOutputPath(path.to_path_buf()));
    }
    let name = path
        .file_name()
        .filter(|name| !name.is_empty() && *name != OsStr::new(".") && *name != OsStr::new(".."))
        .ok_or_else(|| AppError::InvalidOutputPath(path.to_path_buf()))?
        .to_os_string();
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    };
    Ok((parent, name))
}

#[cfg(unix)]
fn has_terminal_component(path: &[u8], component: &[u8]) -> bool {
    path == component
        || (path.ends_with(component)
            && path
                .get(path.len().saturating_sub(component.len() + 1))
                .is_some_and(|separator| *separator == b'/'))
}

#[cfg(unix)]
fn validate_same_file(
    path: &Path,
    path_metadata: &fs::Metadata,
    opened_metadata: &fs::Metadata,
) -> Result<(), AppError> {
    use std::os::unix::fs::MetadataExt;

    if path_metadata.dev() != opened_metadata.dev() || path_metadata.ino() != opened_metadata.ino()
    {
        return Err(AppError::FileChangedDuringOpen(path.to_path_buf()));
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn round_trip_file_io_and_no_clobber() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("input");
        let output = directory.path().join("output");
        fs::write(&input, b"contents").unwrap();

        assert_eq!(&*read_regular_file(&input).unwrap(), b"contents");
        write_atomic_noclobber(&output, b"first").unwrap();
        assert!(matches!(
            write_atomic_noclobber(&output, b"second"),
            Err(AppError::OutputExists(_))
        ));
        assert_eq!(fs::read(&output).unwrap(), b"first");
    }

    #[cfg(unix)]
    #[test]
    fn outputs_are_private_despite_umask() {
        use std::os::unix::fs::MetadataExt;

        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("output");
        write_atomic_noclobber(&output, b"secret").unwrap();
        assert_eq!(fs::metadata(output).unwrap().mode() & 0o777, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn binding_destination_creates_no_entry() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("output");

        let target = OutputTarget::bind(&output).unwrap();
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
        drop(target);
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_terminal_separator_dot_and_dotdot_without_creating_alias() {
        let directory = tempfile::tempdir().unwrap();

        for relative in [
            "newname/",
            "newname//",
            "newname/.",
            "newname/..",
            ".",
            "..",
        ] {
            let output = directory.path().join(relative);
            assert!(matches!(
                OutputTarget::bind(&output),
                Err(AppError::InvalidOutputPath(_))
            ));
            assert!(!directory.path().join("newname").exists());
            assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
        }
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_output_name_is_preserved() {
        use std::os::unix::ffi::OsStringExt;

        let directory = tempfile::tempdir().unwrap();
        let name = OsString::from_vec(vec![b'o', b'u', b't', 0xff]);
        let output = directory.path().join(&name);

        write_atomic_noclobber(&output, b"secret").unwrap();
        assert_eq!(fs::read(directory.path().join(name)).unwrap(), b"secret");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_group_or_world_writable_output_directories_without_residue() {
        use std::os::unix::fs::PermissionsExt;

        for mode in [0o0777, 0o1777] {
            let root = tempfile::tempdir().unwrap();
            let directory = root.path().join("insecure");
            fs::create_dir(&directory).unwrap();
            fs::set_permissions(&directory, fs::Permissions::from_mode(mode)).unwrap();
            let output = directory.join("output");

            assert!(matches!(
                write_atomic_noclobber(&output, b"secret"),
                Err(AppError::InsecureOutputDirectory { .. })
            ));
            assert!(!output.exists());
            assert_eq!(fs::read_dir(&directory).unwrap().count(), 0);
        }
    }

    #[cfg(unix)]
    #[test]
    fn concurrent_output_install_has_exactly_one_winner() {
        use std::sync::{Arc, Barrier};

        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("output");
        let barrier = Arc::new(Barrier::new(2));

        let run = |contents: &'static [u8]| {
            let output = output.clone();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                (contents, write_atomic_noclobber(&output, contents))
            })
        };

        let first = run(b"first");
        let second = run(b"second");
        let first = first.join().unwrap();
        let second = second.join().unwrap();
        assert_ne!(first.1.is_ok(), second.1.is_ok());
        let winner = if first.1.is_ok() { first.0 } else { second.0 };
        assert_eq!(fs::read(&output).unwrap(), winner);
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn retained_directory_ignores_parent_path_replacement() {
        let root = tempfile::tempdir().unwrap();
        let original = root.path().join("destination");
        let moved = root.path().join("moved-destination");
        fs::create_dir(&original).unwrap();

        let target = OutputTarget::bind(&original.join("output")).unwrap();
        fs::rename(&original, &moved).unwrap();
        fs::create_dir(&original).unwrap();

        target.write_atomic_noclobber(b"bound inode").unwrap();
        assert_eq!(fs::read(moved.join("output")).unwrap(), b"bound inode");
        assert!(!original.join("output").exists());
        assert_eq!(fs::read_dir(&moved).unwrap().count(), 1);
        assert_eq!(fs::read_dir(&original).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn entries_created_after_binding_are_never_replaced() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();

        let regular_directory = root.path().join("regular");
        fs::create_dir(&regular_directory).unwrap();
        let regular_path = regular_directory.join("output");
        let regular_target = OutputTarget::bind(&regular_path).unwrap();
        fs::write(&regular_path, b"keep regular").unwrap();
        assert!(matches!(
            regular_target.write_atomic_noclobber(b"replacement"),
            Err(AppError::OutputExists(_))
        ));
        assert_eq!(fs::read(&regular_path).unwrap(), b"keep regular");
        assert_eq!(fs::read_dir(&regular_directory).unwrap().count(), 1);

        let symlink_directory = root.path().join("symlink");
        fs::create_dir(&symlink_directory).unwrap();
        let victim = root.path().join("victim");
        fs::write(&victim, b"keep victim").unwrap();
        let symlink_path = symlink_directory.join("output");
        let symlink_target = OutputTarget::bind(&symlink_path).unwrap();
        symlink(&victim, &symlink_path).unwrap();
        assert!(matches!(
            symlink_target.write_atomic_noclobber(b"replacement"),
            Err(AppError::OutputExists(_))
        ));
        assert_eq!(fs::read(&victim).unwrap(), b"keep victim");
        assert_eq!(fs::read_dir(&symlink_directory).unwrap().count(), 1);

        let directory_directory = root.path().join("directory");
        fs::create_dir(&directory_directory).unwrap();
        let directory_path = directory_directory.join("output");
        let directory_target = OutputTarget::bind(&directory_path).unwrap();
        fs::create_dir(&directory_path).unwrap();
        assert!(matches!(
            directory_target.write_atomic_noclobber(b"replacement"),
            Err(AppError::OutputExists(_))
        ));
        assert!(directory_path.is_dir());
        assert_eq!(fs::read_dir(&directory_directory).unwrap().count(), 1);

        let fifo_directory = root.path().join("fifo");
        fs::create_dir(&fifo_directory).unwrap();
        let fifo_path = fifo_directory.join("output");
        let fifo_target = OutputTarget::bind(&fifo_path).unwrap();
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&fifo_path)
                .status()
                .unwrap()
                .success()
        );
        assert!(matches!(
            fifo_target.write_atomic_noclobber(b"replacement"),
            Err(AppError::OutputExists(_))
        ));
        assert_eq!(fs::read_dir(&fifo_directory).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_input_symlinks() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target");
        let link = directory.path().join("link");
        fs::write(&target, b"secret").unwrap();
        symlink(&target, &link).unwrap();

        assert!(matches!(
            read_regular_file(&link),
            Err(AppError::SymlinkInput(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_fifo_before_opening_it() {
        let directory = tempfile::tempdir().unwrap();
        let fifo = directory.path().join("fifo");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );

        assert!(matches!(
            read_regular_file(&fifo),
            Err(AppError::NotRegularFile(_))
        ));
    }

    #[test]
    fn sparse_oversized_input_is_rejected_before_allocation() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("oversized");
        let file = fs::File::create(&input).unwrap();
        file.set_len(MAX_FILE_BYTES + 1).unwrap();

        assert!(matches!(
            read_regular_file(&input),
            Err(AppError::InputTooLarge)
        ));
    }
}
