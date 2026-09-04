use std::{ffi::OsString, fmt, path::PathBuf};

use crate::algorithms::Algorithm;

pub const USAGE: &str = "Usage:
  cascade keygen
  cascade <A|S|X|T> <E|D> <INPUT> <OUTPUT>
  cascade --help
  cascade --version

Algorithms (uppercase selectors only):
  A  AES-256-GCM-SIV       aes.key
  S  Serpent-256           ser.key
  X  XChaCha20-Poly1305    cha.key
  T  Threefish-1024        thr.key

Operations (uppercase only):
  E  encrypt one file and exit
  D  decrypt one file and exit

Key files are raw binary files stored beside the executable. `keygen` creates
all four and refuses to overwrite any existing key.";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    Encrypt,
    Decrypt,
}

#[derive(Debug, Eq, PartialEq)]
pub enum Command {
    Help,
    Version,
    Keygen,
    Transform {
        algorithm: Algorithm,
        operation: Operation,
        input: PathBuf,
        output: PathBuf,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CliError(&'static str);

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

pub fn parse(arguments: impl IntoIterator<Item = OsString>) -> Result<Command, CliError> {
    let arguments: Vec<OsString> = arguments.into_iter().collect();
    match arguments.as_slice() {
        [command] if command == "--help" || command == "-h" => Ok(Command::Help),
        [command] if command == "--version" || command == "-V" => Ok(Command::Version),
        [command] if command == "keygen" => Ok(Command::Keygen),
        [algorithm, operation, input, output] => {
            let algorithm = algorithm
                .to_str()
                .and_then(Algorithm::from_selector)
                .ok_or(CliError("algorithm must be exactly one of A, S, X, or T"))?;
            let operation = match operation.to_str() {
                Some("E") => Operation::Encrypt,
                Some("D") => Operation::Decrypt,
                _ => return Err(CliError("operation must be exactly E or D")),
            };
            Ok(Command::Transform {
                algorithm,
                operation,
                input: PathBuf::from(input),
                output: PathBuf::from(output),
            })
        }
        _ => Err(CliError("invalid arguments")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn parses_every_algorithm_and_operation() {
        for selector in ["A", "S", "X", "T"] {
            for operation in ["E", "D"] {
                assert!(matches!(
                    parse(args(&[selector, operation, "in", "out"])),
                    Ok(Command::Transform { .. })
                ));
            }
        }
    }

    #[test]
    fn rejects_lowercase_and_aliases() {
        for selector in ["a", "s", "x", "t", "AES", "", "Ａ"] {
            assert!(parse(args(&[selector, "E", "in", "out"])).is_err());
        }
        for operation in ["e", "d", "ENCRYPT", "", "Ｅ"] {
            assert!(parse(args(&["A", operation, "in", "out"])).is_err());
        }
    }

    #[test]
    fn keygen_is_exact_and_standalone() {
        assert_eq!(parse(args(&["keygen"])), Ok(Command::Keygen));
        for invalid in ["KEYGEN", "Keygen", "k", "keygen "] {
            assert!(parse(args(&[invalid])).is_err());
        }
        assert!(parse(args(&["keygen", "extra"])).is_err());
    }

    #[test]
    fn rejects_wrong_argument_counts() {
        for values in [
            args(&[]),
            args(&["A"]),
            args(&["A", "E"]),
            args(&["A", "E", "in"]),
            args(&["A", "E", "in", "out", "extra"]),
        ] {
            assert!(parse(values).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn paths_may_be_non_utf8() {
        use std::os::unix::ffi::OsStringExt;

        let input = OsString::from_vec(vec![b'i', b'n', 0xff]);
        let output = OsString::from_vec(vec![b'o', b'u', b't', 0xfe]);
        assert!(matches!(
            parse(vec![
                OsString::from("A"),
                OsString::from("E"),
                input,
                output
            ]),
            Ok(Command::Transform { .. })
        ));
    }
}
