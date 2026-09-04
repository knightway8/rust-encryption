use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::atomic_io::{self, AtomicWriteError};
use crate::{Algorithm, Error};

const KEY_MAGIC: [u8; 8] = *b"MCKEYF\0\0";
const KEY_VERSION_MAJOR: u8 = 1;
const KEY_VERSION_MINOR: u8 = 0;
const MASTER_KEY_LEN: usize = 32;
const KEY_FILE_LEN: usize = 16 + MASTER_KEY_LEN;

pub(crate) fn directory_for_executable(executable: &Path) -> Result<&Path, Error> {
    executable
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or(Error::MissingExecutableDirectory)
}

pub(crate) fn generate_all(directory: &Path) -> Result<Vec<PathBuf>, Error> {
    let mut created = Vec::with_capacity(Algorithm::ALL.len());
    for algorithm in Algorithm::ALL {
        let path = directory.join(algorithm.key_filename());
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                load(directory, algorithm)?;
                continue;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(Error::io("checking key file", path, error)),
        }

        let mut master = Zeroizing::new([0_u8; MASTER_KEY_LEN]);
        getrandom::fill(master.as_mut()).map_err(|error| Error::Random(error.to_string()))?;
        let encoded = Zeroizing::new(encode(algorithm, &master));

        match atomic_io::write_noclobber(&path, &encoded, true) {
            Ok(()) => created.push(path),
            Err(AtomicWriteError::AlreadyExists) => {
                return Err(Error::KeyAlreadyExists(path));
            }
            Err(AtomicWriteError::Io(error)) => {
                return Err(Error::io("creating key file", path, error));
            }
            #[cfg(unix)]
            Err(AtomicWriteError::PublishedButNotDurable(source)) => {
                return Err(Error::PublishedButNotDurable { path, source });
            }
        }
    }
    Ok(created)
}

pub(crate) fn load(
    directory: &Path,
    algorithm: Algorithm,
) -> Result<Zeroizing<[u8; MASTER_KEY_LEN]>, Error> {
    let path = directory.join(algorithm.key_filename());
    let path_metadata =
        fs::symlink_metadata(&path).map_err(|error| Error::io("opening key file", &path, error))?;
    if path_metadata.file_type().is_symlink() {
        return Err(Error::SymlinkKey(path));
    }
    let file =
        fs::File::open(&path).map_err(|error| Error::io("opening key file", &path, error))?;
    let metadata = file
        .metadata()
        .map_err(|error| Error::io("inspecting key file", &path, error))?;
    if !metadata.is_file() {
        return Err(Error::InvalidKey {
            algorithm,
            reason: "not a regular file",
        });
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(Error::InsecureKeyPermissions(path));
        }
    }

    let mut encoded = Zeroizing::new(Vec::new());
    encoded
        .try_reserve_exact(KEY_FILE_LEN)
        .map_err(|_| Error::OutOfMemory)?;
    file.take((KEY_FILE_LEN + 1) as u64)
        .read_to_end(&mut encoded)
        .map_err(|error| Error::io("reading key file", &path, error))?;
    decode(algorithm, &encoded)
}

fn encode(algorithm: Algorithm, master: &[u8; MASTER_KEY_LEN]) -> Vec<u8> {
    let mut result = Vec::with_capacity(KEY_FILE_LEN);
    result.extend_from_slice(&KEY_MAGIC);
    result.push(KEY_VERSION_MAJOR);
    result.push(KEY_VERSION_MINOR);
    result.extend_from_slice(&algorithm.id().to_be_bytes());
    result.extend_from_slice(&(MASTER_KEY_LEN as u16).to_be_bytes());
    result.extend_from_slice(&0_u16.to_be_bytes());
    result.extend_from_slice(master);
    result
}

fn decode(algorithm: Algorithm, encoded: &[u8]) -> Result<Zeroizing<[u8; MASTER_KEY_LEN]>, Error> {
    let invalid = |reason| Error::InvalidKey { algorithm, reason };
    if encoded.len() != KEY_FILE_LEN {
        return Err(invalid("wrong file length"));
    }
    if encoded[..8] != KEY_MAGIC {
        return Err(invalid("bad magic"));
    }
    if encoded[8] != KEY_VERSION_MAJOR || encoded[9] != KEY_VERSION_MINOR {
        return Err(invalid("unsupported key format version"));
    }
    if u16::from_be_bytes([encoded[10], encoded[11]]) != algorithm.id() {
        return Err(invalid("key belongs to a different algorithm"));
    }
    if u16::from_be_bytes([encoded[12], encoded[13]]) != MASTER_KEY_LEN as u16 {
        return Err(invalid("wrong master-key length"));
    }
    if encoded[14] != 0 || encoded[15] != 0 {
        return Err(invalid("reserved field is not zero"));
    }

    let mut master = Zeroizing::new([0_u8; MASTER_KEY_LEN]);
    master.copy_from_slice(&encoded[16..]);
    Ok(master)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_key_format_round_trips_for_every_algorithm() {
        for algorithm in Algorithm::ALL {
            let master = [algorithm.id() as u8; MASTER_KEY_LEN];
            let encoded = encode(algorithm, &master);
            assert_eq!(*decode(algorithm, &encoded).unwrap(), master);

            for other in Algorithm::ALL {
                if other != algorithm {
                    assert!(decode(other, &encoded).is_err());
                }
            }
        }
    }

    #[test]
    fn decoder_rejects_corruptions() {
        let algorithm = Algorithm::Aes256GcmSiv;
        let original = encode(algorithm, &[7; MASTER_KEY_LEN]);
        for offset in 0..16 {
            let mut changed = original.clone();
            changed[offset] ^= 0x80;
            assert!(decode(algorithm, &changed).is_err(), "offset={offset}");
        }
        assert!(decode(algorithm, &original[..original.len() - 1]).is_err());
        let mut extended = original;
        extended.push(0);
        assert!(decode(algorithm, &extended).is_err());
    }

    #[test]
    fn keygen_creates_missing_keys_and_never_overwrites() {
        let directory = tempfile::tempdir().unwrap();
        let created = generate_all(directory.path()).unwrap();
        assert_eq!(created.len(), Algorithm::ALL.len());
        for algorithm in Algorithm::ALL {
            assert_eq!(
                load(directory.path(), algorithm).unwrap().len(),
                MASTER_KEY_LEN
            );
        }

        let first_path = directory.path().join(Algorithm::ALL[0].key_filename());
        let before = fs::read(&first_path).unwrap();
        assert!(generate_all(directory.path()).unwrap().is_empty());
        assert_eq!(fs::read(&first_path).unwrap(), before);

        let missing_algorithm = Algorithm::Aegis128L;
        let missing_path = directory.path().join(missing_algorithm.key_filename());
        fs::remove_file(&missing_path).unwrap();
        let regenerated = generate_all(directory.path()).unwrap();
        assert_eq!(regenerated.len(), 1);
        assert_eq!(regenerated[0], missing_path);
        assert!(load(directory.path(), missing_algorithm).is_ok());
        assert_eq!(fs::read(&first_path).unwrap(), before);
    }

    #[test]
    fn keygen_never_replaces_an_invalid_existing_key() {
        let directory = tempfile::tempdir().unwrap();
        generate_all(directory.path()).unwrap();

        let algorithm = Algorithm::Aes256GcmSiv;
        let path = directory.path().join(algorithm.key_filename());
        let mut invalid = fs::read(&path).unwrap();
        invalid[0] ^= 0x80;
        fs::write(&path, &invalid).unwrap();

        assert!(matches!(
            generate_all(directory.path()),
            Err(Error::InvalidKey {
                algorithm: Algorithm::Aes256GcmSiv,
                ..
            })
        ));
        assert_eq!(fs::read(path).unwrap(), invalid);
    }

    #[cfg(unix)]
    #[test]
    fn loader_rejects_a_symbolic_link_to_a_valid_key() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        generate_all(directory.path()).unwrap();

        let algorithm = Algorithm::Aes256GcmSiv;
        let path = directory.path().join(algorithm.key_filename());
        let target = directory.path().join("valid-key-target");
        fs::rename(&path, &target).unwrap();
        symlink(&target, &path).unwrap();

        assert!(
            matches!(load(directory.path(), algorithm), Err(Error::SymlinkKey(found)) if found == path)
        );
    }

    #[cfg(unix)]
    #[test]
    fn generated_keys_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        generate_all(directory.path()).unwrap();
        for algorithm in Algorithm::ALL {
            let mode = fs::metadata(directory.path().join(algorithm.key_filename()))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o077, 0);
        }
    }

    #[cfg(unix)]
    #[test]
    fn loader_rejects_broad_key_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        generate_all(directory.path()).unwrap();
        let algorithm = Algorithm::Aes256GcmSiv;
        let path = directory.path().join(algorithm.key_filename());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            load(directory.path(), algorithm),
            Err(Error::InsecureKeyPermissions(_))
        ));
    }
}
