//! Small, descriptor-relative Unix filesystem primitives.
//!
//! Paths are used only while acquiring a directory descriptor and for error
//! messages. Once acquired, every entry lookup, temporary-file operation,
//! publication, cleanup, and directory sync is relative to the retained
//! descriptor.

use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io,
    path::{Path, PathBuf},
};

use rustix::{
    fd::OwnedFd,
    fs::{self, AtFlags, FileType, Mode, OFlags, Stat},
    io::Errno,
    process::geteuid,
};

const PRIVATE_FILE_MODE: u32 = 0o600;
const TEMP_NAME_RANDOM_BYTES: usize = 16;
const TEMP_NAME_ATTEMPTS: usize = 128;

#[derive(Debug)]
pub(crate) enum BindDirectoryError {
    Io(io::Error),
    NotDirectory,
    WrongOwner { expected: u32, actual: u32 },
    InsecureMode { mode: u32 },
}

#[derive(Debug)]
pub(crate) enum CreateTemporaryError {
    Random,
    Io(io::Error),
    IoAndCleanupFailed {
        source: io::Error,
        cleanup: TemporaryCleanupError,
    },
}

#[derive(Debug)]
pub(crate) struct TemporaryCleanupError {
    pub(crate) temporary_name: OsString,
    pub(crate) source: io::Error,
}

#[derive(Debug)]
pub(crate) enum PreInstallFailure {
    Exists,
    Io(io::Error),
}

/// A no-clobber publication failure classified by whether installation
/// occurred. Callers must not report `InstalledButTemporaryRemains` as a
/// pre-install failure.
#[derive(Debug)]
pub(crate) enum PublishError {
    BeforeInstall {
        failure: PreInstallFailure,
        cleanup: Option<TemporaryCleanupError>,
    },
    InstalledButTemporaryRemains(TemporaryCleanupError),
}

/// An opened, owner-checked, non-shared directory.
#[derive(Debug)]
pub(crate) struct BoundDir {
    fd: OwnedFd,
    display_path: PathBuf,
}

impl BoundDir {
    /// Open and validate the actual directory object, rather than metadata
    /// obtained through a separate pathname lookup.
    pub(crate) fn open_private(path: &Path) -> Result<Self, BindDirectoryError> {
        let fd = match fs::open(
            path,
            OFlags::RDONLY
                | OFlags::DIRECTORY
                | OFlags::NOFOLLOW
                | OFlags::NONBLOCK
                | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(Errno::NOTDIR) => return Err(BindDirectoryError::NotDirectory),
            Err(error) => return Err(BindDirectoryError::Io(error.into())),
        };

        let metadata =
            fs::fstat(&fd).map_err(|error| BindDirectoryError::Io(io::Error::from(error)))?;
        if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory {
            return Err(BindDirectoryError::NotDirectory);
        }

        let expected_owner = geteuid().as_raw();
        if metadata.st_uid != expected_owner {
            return Err(BindDirectoryError::WrongOwner {
                expected: expected_owner,
                actual: metadata.st_uid,
            });
        }

        let mode = metadata.st_mode & 0o7777;
        if mode & 0o022 != 0 {
            return Err(BindDirectoryError::InsecureMode { mode });
        }

        Ok(Self {
            fd,
            display_path: path.to_path_buf(),
        })
    }

    pub(crate) fn display_path(&self) -> &Path {
        &self.display_path
    }

    pub(crate) fn stat_nofollow(&self, name: &OsStr) -> io::Result<Stat> {
        fs::statat(&self.fd, name, AtFlags::SYMLINK_NOFOLLOW).map_err(Into::into)
    }

    pub(crate) fn open_read_nofollow_nonblock(&self, name: &OsStr) -> io::Result<File> {
        let fd = fs::openat(
            &self.fd,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(io::Error::from)?;
        Ok(File::from(fd))
    }

    pub(crate) fn metadata(file: &File) -> io::Result<Stat> {
        fs::fstat(file).map_err(Into::into)
    }

    pub(crate) fn create_private_temp(
        &self,
        prefix: &str,
    ) -> Result<PrivateTemp<'_>, CreateTemporaryError> {
        for _ in 0..TEMP_NAME_ATTEMPTS {
            let name = random_temporary_name(prefix)?;
            let fd = match fs::openat(
                &self.fd,
                &name,
                OFlags::WRONLY
                    | OFlags::CREATE
                    | OFlags::EXCL
                    | OFlags::NOFOLLOW
                    | OFlags::NONBLOCK
                    | OFlags::CLOEXEC,
                Mode::from_raw_mode(PRIVATE_FILE_MODE),
            ) {
                Ok(fd) => fd,
                Err(Errno::EXIST) => continue,
                Err(error) => return Err(CreateTemporaryError::Io(error.into())),
            };

            let temporary = PrivateTemp {
                directory: self,
                name,
                file: File::from(fd),
                cleanup_on_drop: true,
            };

            // The create mode is filtered through umask. Widening it back to
            // exactly 0600 is safe because the file began with no group/other
            // access and remains known only by an unpredictable private name.
            if let Err(error) = fs::fchmod(&temporary.file, Mode::from_raw_mode(PRIVATE_FILE_MODE))
            {
                let source = error.into();
                return match temporary.cleanup() {
                    Ok(()) => Err(CreateTemporaryError::Io(source)),
                    Err(cleanup) => {
                        Err(CreateTemporaryError::IoAndCleanupFailed { source, cleanup })
                    }
                };
            }
            return Ok(temporary);
        }

        Err(CreateTemporaryError::Io(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique private temporary filename",
        )))
    }

    /// Atomically install `temporary` at `target` without replacing any
    /// existing directory entry.
    pub(crate) fn publish_noclobber(
        &self,
        mut temporary: PrivateTemp<'_>,
        target: &OsStr,
    ) -> Result<(), PublishError> {
        match self.try_rename_noreplace(&temporary.name, target) {
            RenameAttempt::Installed => {
                temporary.cleanup_on_drop = false;
                return Ok(());
            }
            RenameAttempt::Exists => {
                return Err(before_install_failure(temporary, PreInstallFailure::Exists));
            }
            RenameAttempt::Failed(source) => {
                return Err(before_install_failure(
                    temporary,
                    PreInstallFailure::Io(source),
                ));
            }
            RenameAttempt::Unsupported => {}
        }

        match fs::linkat(
            &self.fd,
            &temporary.name,
            &self.fd,
            target,
            AtFlags::empty(),
        ) {
            Ok(()) => {}
            Err(Errno::EXIST) => {
                return Err(before_install_failure(temporary, PreInstallFailure::Exists));
            }
            Err(error) => {
                return Err(before_install_failure(
                    temporary,
                    PreInstallFailure::Io(error.into()),
                ));
            }
        }

        match temporary.cleanup() {
            Ok(()) => Ok(()),
            Err(cleanup) => Err(PublishError::InstalledButTemporaryRemains(cleanup)),
        }
    }

    pub(crate) fn unlink(&self, name: &OsStr) -> io::Result<()> {
        fs::unlinkat(&self.fd, name, AtFlags::empty()).map_err(Into::into)
    }

    pub(crate) fn sync(&self) -> io::Result<()> {
        fs::fsync(&self.fd).map_err(Into::into)
    }

    #[cfg(any(
        target_os = "android",
        target_os = "linux",
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "visionos",
        target_os = "watchos",
        target_os = "redox"
    ))]
    fn try_rename_noreplace(&self, old_name: &OsStr, new_name: &OsStr) -> RenameAttempt {
        use rustix::fs::{RenameFlags, renameat_with};

        match renameat_with(
            &self.fd,
            old_name,
            &self.fd,
            new_name,
            RenameFlags::NOREPLACE,
        ) {
            Ok(()) => RenameAttempt::Installed,
            Err(Errno::EXIST) => RenameAttempt::Exists,
            Err(Errno::NOSYS | Errno::INVAL) => RenameAttempt::Unsupported,
            Err(error) => RenameAttempt::Failed(error.into()),
        }
    }

    #[cfg(not(any(
        target_os = "android",
        target_os = "linux",
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "visionos",
        target_os = "watchos",
        target_os = "redox"
    )))]
    fn try_rename_noreplace(&self, _old_name: &OsStr, _new_name: &OsStr) -> RenameAttempt {
        RenameAttempt::Unsupported
    }
}

enum RenameAttempt {
    Installed,
    Exists,
    Unsupported,
    Failed(io::Error),
}

pub(crate) struct PrivateTemp<'directory> {
    directory: &'directory BoundDir,
    name: OsString,
    file: File,
    cleanup_on_drop: bool,
}

impl PrivateTemp<'_> {
    pub(crate) fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }

    pub(crate) fn file(&self) -> &File {
        &self.file
    }

    /// Remove the name explicitly. On failure, Drop is disarmed so callers can
    /// accurately report that the named entry remains rather than racing a
    /// silent retry.
    pub(crate) fn cleanup(mut self) -> Result<(), TemporaryCleanupError> {
        self.cleanup_on_drop = false;
        fs::unlinkat(&self.directory.fd, &self.name, AtFlags::empty()).map_err(|source| {
            TemporaryCleanupError {
                temporary_name: self.name.clone(),
                source: source.into(),
            }
        })
    }
}

impl Drop for PrivateTemp<'_> {
    fn drop(&mut self) {
        if self.cleanup_on_drop {
            let _ = fs::unlinkat(&self.directory.fd, &self.name, AtFlags::empty());
        }
    }
}

pub(crate) fn file_type(metadata: &Stat) -> FileType {
    FileType::from_raw_mode(metadata.st_mode)
}

pub(crate) fn same_file(first: &Stat, second: &Stat) -> bool {
    first.st_dev == second.st_dev && first.st_ino == second.st_ino
}

pub(crate) fn mode(metadata: &Stat) -> u32 {
    metadata.st_mode & 0o7777
}

pub(crate) fn owner(metadata: &Stat) -> u32 {
    metadata.st_uid
}

pub(crate) fn effective_user_id() -> u32 {
    geteuid().as_raw()
}

pub(crate) fn size(metadata: &Stat) -> Option<u64> {
    u64::try_from(metadata.st_size).ok()
}

fn random_temporary_name(prefix: &str) -> Result<OsString, CreateTemporaryError> {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut random = [0_u8; TEMP_NAME_RANDOM_BYTES];
    getrandom::fill(&mut random).map_err(|_| CreateTemporaryError::Random)?;
    let mut name = String::with_capacity(prefix.len() + TEMP_NAME_RANDOM_BYTES * 2);
    name.push_str(prefix);
    for byte in random {
        name.push(char::from(HEX[usize::from(byte >> 4)]));
        name.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(name.into())
}

fn before_install_failure(temporary: PrivateTemp<'_>, failure: PreInstallFailure) -> PublishError {
    let cleanup = temporary.cleanup().err();
    PublishError::BeforeInstall { failure, cleanup }
}
