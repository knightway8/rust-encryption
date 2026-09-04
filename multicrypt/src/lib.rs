mod algorithm;
mod atomic_io;
mod container;
mod crypto;
mod error;
mod file_ops;
mod keys;

use std::ffi::OsString;
use std::path::{Path, PathBuf};

pub use algorithm::Algorithm;
pub use error::Error;
use file_ops::Operation;

pub const USAGE: &str = "Usage:
  multicrypt keygen
  multicrypt <ALGORITHM> <E|D> <INPUT> <OUTPUT>

Algorithms:
  AES-256-GCM-SIV
  SERPENT-256-CTR-HMAC-SHA-512
  THREEFISH-1024-CTR-HMAC-SHA-512
  ASCON-AEAD128
  RABBIT-HMAC-SHA-512
  AEGIS-256
  AEGIS-128L

E encrypts and D decrypts. Operation letters must be uppercase.
Keys are loaded from the directory containing the executable.
Existing output files and existing key files are never overwritten.";

pub fn run_cli() -> Result<String, Error> {
    let executable =
        std::env::current_exe().map_err(|error| Error::io("locating executable", ".", error))?;
    run_cli_with(std::env::args_os().skip(1), &executable)
}

pub fn run_cli_with<I>(arguments: I, executable: &Path) -> Result<String, Error>
where
    I: IntoIterator<Item = OsString>,
{
    let arguments: Vec<OsString> = arguments.into_iter().collect();
    if arguments.len() == 1 && matches!(arguments[0].to_str(), Some("-h" | "--help" | "help")) {
        return Ok(USAGE.to_owned());
    }

    let key_directory = keys::directory_for_executable(executable)?;
    if arguments.len() == 1 && arguments[0] == "keygen" {
        let created = keys::generate_all(key_directory)?;
        if created.is_empty() {
            return Ok(format!(
                "All {} key files already exist in '{}'; nothing changed.",
                Algorithm::ALL.len(),
                key_directory.display()
            ));
        }
        return Ok(format!(
            "Created {} missing independent key files in '{}'. Back them up securely.",
            created.len(),
            key_directory.display()
        ));
    }

    if arguments.len() != 4 {
        return Err(Error::Usage(format!(
            "expected 4 arguments for processing, got {}",
            arguments.len()
        )));
    }

    let algorithm_text = arguments[0]
        .to_str()
        .ok_or_else(|| Error::UnknownAlgorithm("<non-UTF-8>".to_owned()))?;
    let algorithm = algorithm_text.parse::<Algorithm>()?;
    let operation_text = arguments[1]
        .to_str()
        .ok_or_else(|| Error::InvalidOperation("<non-UTF-8>".to_owned()))?;
    let operation = match operation_text {
        "E" => Operation::Encrypt,
        "D" => Operation::Decrypt,
        other => return Err(Error::InvalidOperation(other.to_owned())),
    };
    let input = PathBuf::from(&arguments[2]);
    let output = PathBuf::from(&arguments[3]);

    file_ops::process_file(algorithm, operation, &input, &output, key_directory)?;
    Ok(format!(
        "{} '{}' to '{}' with {}.",
        match operation {
            Operation::Encrypt => "Encrypted",
            Operation::Decrypt => "Decrypted",
        },
        input.display(),
        output.display(),
        algorithm
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_requires_exact_uppercase_operation() {
        let executable = Path::new("bin/multicrypt");
        for operation in ["e", "d", "Encrypt", ""] {
            let result = run_cli_with(
                [
                    OsString::from("AES-256-GCM-SIV"),
                    OsString::from(operation),
                    OsString::from("in"),
                    OsString::from("out"),
                ],
                executable,
            );
            assert!(matches!(result, Err(Error::InvalidOperation(_))));
        }
    }

    #[test]
    fn help_does_not_require_keys() {
        let result = run_cli_with([OsString::from("--help")], Path::new("bin/multicrypt")).unwrap();
        assert!(result.contains("multicrypt keygen"));
        assert!(result.contains("AEGIS-128L"));
    }
}
