#[cfg(unix)]
use std::{
    ffi::OsStr,
    io::{Read, Write},
    path::PathBuf,
};

use zeroize::Zeroizing;

#[cfg(unix)]
use rustix::fs::FileType;

use crate::{algorithms::Algorithm, error::AppError};

#[cfg(unix)]
use crate::unix_fs::{
    self, BindDirectoryError, BoundDir, CreateTemporaryError, PreInstallFailure, PrivateTemp,
    PublishError, TemporaryCleanupError,
};

#[cfg(unix)]
const ALL_ALGORITHMS: [Algorithm; 4] = [
    Algorithm::Aes256GcmSiv,
    Algorithm::Serpent256,
    Algorithm::XChaCha20Poly1305,
    Algorithm::Threefish1024,
];

#[derive(Debug)]
pub struct KeyStore {
    #[cfg(unix)]
    directory: PathBuf,
    #[cfg(unix)]
    bound_directory: BoundDir,
}

impl KeyStore {
    pub fn beside_current_executable() -> Result<Self, AppError> {
        #[cfg(unix)]
        {
            let executable = std::env::current_exe().map_err(AppError::Executable)?;
            let directory = executable
                .parent()
                .ok_or(AppError::ExecutableDirectory)?
                .to_path_buf();
            Self::bind(directory)
        }

        #[cfg(not(unix))]
        {
            Err(AppError::UnsupportedPlatform)
        }
    }

    #[cfg(all(test, unix))]
    pub(crate) fn in_directory(directory: PathBuf) -> Result<Self, AppError> {
        Self::bind(directory)
    }

    pub fn read(&self, algorithm: Algorithm) -> Result<Zeroizing<Vec<u8>>, AppError> {
        #[cfg(unix)]
        {
            self.read_unix(algorithm)
        }

        #[cfg(not(unix))]
        {
            let _ = algorithm;
            Err(AppError::UnsupportedPlatform)
        }
    }

    /// Generate all four key files without overwriting an existing entry.
    ///
    /// Ordinary failures trigger a best-effort rollback of files installed by
    /// this invocation. The operation is intentionally not advertised as
    /// crash-atomic: a process or system crash can leave a partial new set.
    pub fn generate_all(&self) -> Result<(), AppError> {
        #[cfg(unix)]
        {
            self.generate_all_unix()
        }

        #[cfg(not(unix))]
        {
            Err(AppError::UnsupportedPlatform)
        }
    }

    #[cfg(unix)]
    fn bind(directory: PathBuf) -> Result<Self, AppError> {
        let bound_directory = BoundDir::open_private(&directory).map_err(|error| match error {
            BindDirectoryError::Io(source) => AppError::Metadata {
                path: directory.clone(),
                source,
            },
            BindDirectoryError::NotDirectory => AppError::NotDirectory(directory.clone()),
            BindDirectoryError::WrongOwner { expected, actual } => {
                AppError::WrongKeyDirectoryOwner {
                    path: directory.clone(),
                    expected,
                    actual,
                }
            }
            BindDirectoryError::InsecureMode { mode } => AppError::InsecureKeyDirectory {
                path: directory.clone(),
                mode,
            },
        })?;
        Ok(Self {
            directory,
            bound_directory,
        })
    }

    #[cfg(unix)]
    fn read_unix(&self, algorithm: Algorithm) -> Result<Zeroizing<Vec<u8>>, AppError> {
        let name = OsStr::new(algorithm.key_filename());
        let path = self.directory.join(name);
        let before =
            self.bound_directory
                .stat_nofollow(name)
                .map_err(|source| AppError::Metadata {
                    path: path.clone(),
                    source,
                })?;
        if unix_fs::file_type(&before) == FileType::Symlink {
            return Err(AppError::SymlinkKey(path));
        }
        // This descriptor-relative precheck avoids opening obvious devices and
        // FIFOs. O_NOFOLLOW and O_NONBLOCK constrain a final-entry race, and
        // fstat below validates the object actually opened.
        if unix_fs::file_type(&before) != FileType::RegularFile {
            return Err(AppError::NotRegularFile(path));
        }

        let mut file = self
            .bound_directory
            .open_read_nofollow_nonblock(name)
            .map_err(|source| AppError::Open {
                path: path.clone(),
                source,
            })?;
        let opened = BoundDir::metadata(&file).map_err(|source| AppError::Metadata {
            path: path.clone(),
            source,
        })?;
        if unix_fs::file_type(&opened) != FileType::RegularFile {
            return Err(AppError::NotRegularFile(path));
        }
        if !unix_fs::same_file(&before, &opened) {
            return Err(AppError::FileChangedDuringOpen(path));
        }

        let actual_length = unix_fs::size(&opened).ok_or_else(|| AppError::Metadata {
            path: path.clone(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "key file reported a negative length",
            ),
        })?;
        if actual_length != algorithm.key_len() as u64 {
            return Err(AppError::KeyLength {
                path,
                expected: algorithm.key_len(),
                actual: actual_length,
            });
        }

        let expected_owner = unix_fs::effective_user_id();
        let actual_owner = unix_fs::owner(&opened);
        if actual_owner != expected_owner {
            return Err(AppError::WrongKeyOwner {
                path,
                expected: expected_owner,
                actual: actual_owner,
            });
        }
        let mode = unix_fs::mode(&opened);
        if mode & 0o077 != 0 {
            return Err(AppError::InsecureKeyPermissions { path, mode });
        }

        let mut key = Zeroizing::new(vec![0_u8; algorithm.key_len()]);
        file.read_exact(&mut key).map_err(|source| AppError::Read {
            path: path.clone(),
            source,
        })?;
        let mut extra = [0_u8; 1];
        if file.read(&mut extra).map_err(|source| AppError::Read {
            path: path.clone(),
            source,
        })? != 0
        {
            return Err(AppError::KeyLength {
                path,
                expected: algorithm.key_len(),
                actual: actual_length.saturating_add(1),
            });
        }
        Ok(key)
    }

    #[cfg(unix)]
    fn generate_all_unix(&self) -> Result<(), AppError> {
        for algorithm in ALL_ALGORITHMS {
            let name = OsStr::new(algorithm.key_filename());
            let path = self.directory.join(name);
            match self.bound_directory.stat_nofollow(name) {
                Ok(_) => return Err(AppError::KeyExists(path)),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(source) => return Err(AppError::Metadata { path, source }),
            }
        }

        let mut temporary_keys = Vec::with_capacity(ALL_ALGORITHMS.len());
        for algorithm in ALL_ALGORITHMS {
            let mut key = Zeroizing::new(vec![0_u8; algorithm.key_len()]);
            if getrandom::fill(&mut key).is_err() {
                return match cleanup_temporaries(temporary_keys) {
                    Some(cleanup) => Err(self.temporary_cleanup_failure(
                        "secure key generation failed".to_owned(),
                        cleanup,
                    )),
                    None => Err(AppError::Random),
                };
            }

            let create_result = self.bound_directory.create_private_temp(".cascade-key-");
            let mut temporary = match create_result {
                Ok(temporary) => temporary,
                Err(error) => {
                    let (primary_error, primary, current_cleanup) = match error {
                        CreateTemporaryError::Random => (
                            AppError::Random,
                            "secure temporary-key name generation failed".to_owned(),
                            None,
                        ),
                        CreateTemporaryError::Io(source) => (
                            AppError::KeyGeneration {
                                path: self.directory.clone(),
                                source,
                            },
                            "could not create or secure a temporary key".to_owned(),
                            None,
                        ),
                        CreateTemporaryError::IoAndCleanupFailed { source, cleanup } => (
                            AppError::KeyGeneration {
                                path: self.directory.clone(),
                                source,
                            },
                            "could not secure a temporary key".to_owned(),
                            Some(cleanup),
                        ),
                    };
                    let pending_cleanup = cleanup_temporaries(temporary_keys);
                    let cleanup = current_cleanup.or(pending_cleanup);
                    return match cleanup {
                        Some(cleanup) => Err(self.temporary_cleanup_failure(primary, cleanup)),
                        None => Err(primary_error),
                    };
                }
            };

            let write_result = temporary.file_mut().write_all(&key);
            let write_result = match write_result {
                Ok(()) => temporary.file().sync_all(),
                Err(error) => Err(error),
            };
            if let Err(source) = write_result {
                let primary = format!("could not write and sync a temporary key: {source}");
                let current_cleanup = temporary.cleanup().err();
                let pending_cleanup = cleanup_temporaries(temporary_keys);
                let cleanup = current_cleanup.or(pending_cleanup);
                return match cleanup {
                    Some(cleanup) => Err(self.temporary_cleanup_failure(primary, cleanup)),
                    None => Err(AppError::KeyGeneration {
                        path: self.directory.clone(),
                        source,
                    }),
                };
            }
            temporary_keys.push((algorithm, temporary));
        }

        let mut created = Vec::with_capacity(ALL_ALGORITHMS.len());
        let mut pending = temporary_keys.into_iter();
        while let Some((algorithm, temporary)) = pending.next() {
            let name = OsStr::new(algorithm.key_filename());
            let path = self.directory.join(name);
            match self.bound_directory.publish_noclobber(temporary, name) {
                Ok(()) => created.push(algorithm),
                Err(PublishError::BeforeInstall { failure, cleanup }) => {
                    let pending_cleanup = cleanup_temporaries(pending);
                    let cleanup = cleanup.or(pending_cleanup);
                    let rollback_error = self.rollback_created(&created).err();
                    if let Some(cleanup) = cleanup {
                        let mut primary = match &failure {
                            PreInstallFailure::Exists => {
                                format!("key target {path:?} already existed")
                            }
                            PreInstallFailure::Io(source) => {
                                format!("could not publish key {path:?}: {source}")
                            }
                        };
                        if let Some(source) = rollback_error {
                            primary.push_str(&format!("; rollback also failed: {source}"));
                        }
                        return Err(self.temporary_cleanup_failure(primary, cleanup));
                    }
                    if let Some(source) = rollback_error {
                        return Err(AppError::KeyRollbackIncomplete {
                            path: self.directory.clone(),
                            source,
                        });
                    }
                    return match failure {
                        PreInstallFailure::Exists => Err(AppError::KeyExists(path)),
                        PreInstallFailure::Io(source) => {
                            Err(AppError::KeyGeneration { path, source })
                        }
                    };
                }
                Err(PublishError::InstalledButTemporaryRemains(cleanup)) => {
                    if let Some(additional_cleanup) = cleanup_temporaries(pending) {
                        let primary = format!(
                            "key {path:?} was installed, but temporary entry {:?} also remains because cleanup failed: {}",
                            cleanup.temporary_name, cleanup.source
                        );
                        return Err(self.temporary_cleanup_failure(primary, additional_cleanup));
                    }
                    return Err(AppError::KeyInstalledButTemporaryRemains {
                        path,
                        temporary_name: cleanup.temporary_name,
                        source: cleanup.source,
                    });
                }
            }
        }

        self.bound_directory
            .sync()
            .map_err(|source| AppError::KeysInstalledButNotSynced {
                path: self.directory.clone(),
                source,
            })
    }

    #[cfg(unix)]
    fn rollback_created(&self, created: &[Algorithm]) -> std::io::Result<()> {
        let mut first_error = None;
        for algorithm in created {
            if let Err(error) = self
                .bound_directory
                .unlink(OsStr::new(algorithm.key_filename()))
            {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
        if first_error.is_none() && !created.is_empty() {
            first_error = self.bound_directory.sync().err();
        }
        first_error.map_or(Ok(()), Err)
    }

    #[cfg(unix)]
    fn temporary_cleanup_failure(
        &self,
        primary: String,
        cleanup: TemporaryCleanupError,
    ) -> AppError {
        AppError::KeyTemporaryCleanupFailed {
            path: self.directory.clone(),
            temporary_name: cleanup.temporary_name,
            primary,
            cleanup_source: cleanup.source,
        }
    }
}

#[cfg(unix)]
fn cleanup_temporaries<'directory>(
    temporaries: impl IntoIterator<Item = (Algorithm, PrivateTemp<'directory>)>,
) -> Option<TemporaryCleanupError> {
    let mut first_error = None;
    for (_, temporary) in temporaries {
        if let Err(error) = temporary.cleanup() {
            if first_error.is_none() {
                first_error = Some(error);
            }
        }
    }
    first_error
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn generates_and_reads_every_exact_key() {
        use std::os::unix::fs::MetadataExt;

        let directory = tempfile::tempdir().unwrap();
        let store = KeyStore::in_directory(directory.path().to_path_buf()).unwrap();
        store.generate_all().unwrap();

        for algorithm in ALL_ALGORITHMS {
            let key = store.read(algorithm).unwrap();
            assert_eq!(key.len(), algorithm.key_len());
            assert!(key.iter().any(|byte| *byte != 0));
            assert_eq!(
                fs::metadata(directory.path().join(algorithm.key_filename()))
                    .unwrap()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn generation_never_overwrites() {
        let directory = tempfile::tempdir().unwrap();
        let store = KeyStore::in_directory(directory.path().to_path_buf()).unwrap();
        store.generate_all().unwrap();
        let original = fs::read(directory.path().join("aes.key")).unwrap();

        assert!(matches!(store.generate_all(), Err(AppError::KeyExists(_))));
        assert_eq!(
            fs::read(directory.path().join("aes.key")).unwrap(),
            original
        );
    }

    #[test]
    fn rejects_insecure_key_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let store = KeyStore::in_directory(directory.path().to_path_buf()).unwrap();
        store.generate_all().unwrap();
        let path = directory.path().join("aes.key");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        assert!(matches!(
            store.read(Algorithm::Aes256GcmSiv),
            Err(AppError::InsecureKeyPermissions { .. })
        ));
    }

    #[test]
    fn rejects_insecure_key_directory_before_generation() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o770)).unwrap();
        assert!(matches!(
            KeyStore::in_directory(directory.path().to_path_buf()),
            Err(AppError::InsecureKeyDirectory { .. })
        ));
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    #[test]
    fn rejects_key_symlinks() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target");
        fs::write(&target, [7_u8; 32]).unwrap();
        symlink(&target, directory.path().join("aes.key")).unwrap();
        let store = KeyStore::in_directory(directory.path().to_path_buf()).unwrap();

        assert!(matches!(
            store.read(Algorithm::Aes256GcmSiv),
            Err(AppError::SymlinkKey(_))
        ));
    }

    #[test]
    fn rejects_fifo_key_before_opening_it() {
        let directory = tempfile::tempdir().unwrap();
        let fifo = directory.path().join("aes.key");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        let store = KeyStore::in_directory(directory.path().to_path_buf()).unwrap();

        assert!(matches!(
            store.read(Algorithm::Aes256GcmSiv),
            Err(AppError::NotRegularFile(_))
        ));
    }

    #[test]
    fn retained_directory_reads_original_keys_after_path_replacement() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().unwrap();
        let original = root.path().join("keys");
        let moved = root.path().join("moved-keys");
        fs::create_dir(&original).unwrap();
        let store = KeyStore::in_directory(original.clone()).unwrap();
        store.generate_all().unwrap();
        let expected = store.read(Algorithm::Aes256GcmSiv).unwrap();

        fs::rename(&original, &moved).unwrap();
        fs::create_dir(&original).unwrap();
        let replacement = original.join("aes.key");
        fs::write(&replacement, [0xa5_u8; 32]).unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();

        assert_eq!(
            store.read(Algorithm::Aes256GcmSiv).unwrap().as_slice(),
            expected.as_slice()
        );
        assert_eq!(fs::read(replacement).unwrap(), [0xa5_u8; 32]);
    }

    #[test]
    fn retained_directory_generates_only_in_original_inode_after_path_replacement() {
        let root = tempfile::tempdir().unwrap();
        let original = root.path().join("keys");
        let moved = root.path().join("moved-keys");
        fs::create_dir(&original).unwrap();
        let store = KeyStore::in_directory(original.clone()).unwrap();

        fs::rename(&original, &moved).unwrap();
        fs::create_dir(&original).unwrap();
        store.generate_all().unwrap();

        for algorithm in ALL_ALGORITHMS {
            assert!(moved.join(algorithm.key_filename()).is_file());
            assert!(!original.join(algorithm.key_filename()).exists());
        }
        assert_eq!(fs::read_dir(&moved).unwrap().count(), ALL_ALGORITHMS.len());
        assert_eq!(fs::read_dir(&original).unwrap().count(), 0);
    }
}
