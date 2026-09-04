use std::fs;
use std::io::Read;
use std::path::Path;

use zeroize::Zeroizing;

use crate::atomic_io::{self, AtomicWriteError};
use crate::{Algorithm, Error, crypto, keys};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Operation {
    Encrypt,
    Decrypt,
}

pub(crate) fn process_file(
    algorithm: Algorithm,
    operation: Operation,
    input: &Path,
    output: &Path,
    key_directory: &Path,
) -> Result<(), Error> {
    let mut input_file =
        fs::File::open(input).map_err(|error| Error::io("opening input", input, error))?;
    let metadata = input_file
        .metadata()
        .map_err(|error| Error::io("inspecting input", input, error))?;
    if !metadata.is_file() {
        return Err(Error::NotARegularFile(input.to_path_buf()));
    }

    match fs::symlink_metadata(output) {
        Ok(_) => return Err(Error::OutputExists(output.to_path_buf())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(Error::io("checking output", output, error)),
    }

    let master_key = keys::load(key_directory, algorithm)?;
    let input_bytes = read_opened_file(&mut input_file, metadata.len(), input)?;
    match operation {
        Operation::Encrypt => {
            let encrypted = crypto::seal(algorithm, &input_bytes, &master_key)?;
            publish(output, &encrypted)
        }
        Operation::Decrypt => {
            let plaintext = crypto::open(algorithm, &input_bytes, &master_key)?;
            publish(output, &plaintext)
        }
    }
}

fn read_opened_file(
    file: &mut fs::File,
    expected_len: u64,
    path: &Path,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let expected_len = usize::try_from(expected_len).map_err(|_| Error::InputTooLarge)?;
    let mut contents = Zeroizing::new(Vec::new());
    contents
        .try_reserve_exact(expected_len)
        .map_err(|_| Error::OutOfMemory)?;
    file.read_to_end(&mut contents)
        .map_err(|error| Error::io("reading input", path, error))?;
    Ok(contents)
}

fn publish(output: &Path, contents: &[u8]) -> Result<(), Error> {
    match atomic_io::write_noclobber(output, contents, false) {
        Ok(()) => Ok(()),
        Err(AtomicWriteError::AlreadyExists) => Err(Error::OutputExists(output.to_path_buf())),
        Err(AtomicWriteError::Io(error)) => Err(Error::io("publishing output", output, error)),
        #[cfg(unix)]
        Err(AtomicWriteError::PublishedButNotDurable(source)) => {
            Err(Error::PublishedButNotDurable {
                path: output.to_path_buf(),
                source,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn existing_output_is_never_replaced() {
        let directory = tempfile::tempdir().unwrap();
        keys::generate_all(directory.path()).unwrap();
        let input = directory.path().join("input.bin");
        let output = directory.path().join("output.bin");
        fs::write(&input, b"secret").unwrap();
        fs::write(&output, b"keep me").unwrap();

        assert!(matches!(
            process_file(
                Algorithm::Aes256GcmSiv,
                Operation::Encrypt,
                &input,
                &output,
                directory.path(),
            ),
            Err(Error::OutputExists(_))
        ));
        assert_eq!(fs::read(output).unwrap(), b"keep me");
    }

    #[test]
    fn authentication_failure_creates_no_output() {
        let directory = tempfile::tempdir().unwrap();
        keys::generate_all(directory.path()).unwrap();
        let input = directory.path().join("input.bin");
        let encrypted = directory.path().join("encrypted.bin");
        let output = directory.path().join("output.bin");
        fs::write(&input, b"secret").unwrap();
        process_file(
            Algorithm::Aes256GcmSiv,
            Operation::Encrypt,
            &input,
            &encrypted,
            directory.path(),
        )
        .unwrap();

        let mut bytes = fs::read(&encrypted).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        fs::write(&encrypted, bytes).unwrap();
        assert!(matches!(
            process_file(
                Algorithm::Aes256GcmSiv,
                Operation::Decrypt,
                &encrypted,
                &output,
                directory.path(),
            ),
            Err(Error::AuthenticationFailed)
        ));
        assert!(!output.exists());
    }

    #[test]
    fn malformed_container_creates_no_output() {
        let directory = tempfile::tempdir().unwrap();
        keys::generate_all(directory.path()).unwrap();
        let input = directory.path().join("truncated.mcrypt");
        let output = directory.path().join("output.bin");
        fs::write(&input, b"MCRYPTF\0").unwrap();

        assert!(matches!(
            process_file(
                Algorithm::Aes256GcmSiv,
                Operation::Decrypt,
                &input,
                &output,
                directory.path(),
            ),
            Err(Error::InvalidContainer("truncated header"))
        ));
        assert!(!output.exists());
    }

    #[test]
    fn using_the_input_path_as_output_preserves_the_input() {
        let directory = tempfile::tempdir().unwrap();
        keys::generate_all(directory.path()).unwrap();
        let input = directory.path().join("input.bin");
        fs::write(&input, b"must remain unchanged").unwrap();

        assert!(matches!(
            process_file(
                Algorithm::Aes256GcmSiv,
                Operation::Encrypt,
                &input,
                &input,
                directory.path(),
            ),
            Err(Error::OutputExists(_))
        ));
        assert_eq!(fs::read(input).unwrap(), b"must remain unchanged");
    }
}
