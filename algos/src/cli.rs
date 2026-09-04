//! Uniform command-line contract shared by every algorithm-specific binary.

use std::fs::File;
use std::io::{Read, Take};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand};
use zeroize::Zeroizing;

use crate::envelope::{decrypt_file, encrypt_file};
use crate::{Error, Result, Suite};

const MAX_PASSWORD_BYTES: usize = 1024 * 1024;

#[derive(Debug, Parser)]
struct Cli {
    #[command(subcommand)]
    command: Operation,
}

#[derive(Debug, Subcommand)]
enum Operation {
    /// Encrypt a regular file into a new authenticated container.
    Encrypt(FileArguments),
    /// Authenticate and decrypt a container into a new file.
    Decrypt(FileArguments),
}

#[derive(Debug, Args)]
struct FileArguments {
    /// Input file. Standard input is intentionally unsupported.
    #[arg(short, long, value_name = "PATH")]
    input: PathBuf,
    /// New output file. Existing paths are never overwritten.
    #[arg(short, long, value_name = "PATH")]
    output: PathBuf,
    /// Read exact password bytes from this file (newlines are not stripped).
    #[arg(long, value_name = "PATH")]
    password_file: Option<PathBuf>,
}

/// Run the CLI pinned to one suite. Thin binaries call only this function.
#[must_use]
pub fn run(suite: Suite) -> ExitCode {
    let about = if suite.is_native_aead() {
        format!("Authenticated file encryption using {}", suite.name())
    } else {
        format!(
            "File encryption using {} (educational/niche Encrypt-then-MAC suite)",
            suite.name()
        )
    };
    let matches = Cli::command()
        .name(suite.binary_name())
        .version(env!("CARGO_PKG_VERSION"))
        .about(about)
        .get_matches();
    let cli = match Cli::from_arg_matches(&matches) {
        Ok(cli) => cli,
        Err(error) => error.exit(),
    };

    match execute(suite, cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn execute(suite: Suite, cli: Cli) -> Result<()> {
    match cli.command {
        Operation::Encrypt(arguments) => {
            ensure_distinct(&arguments.input, &arguments.output)?;
            let password = password_for_encryption(arguments.password_file.as_deref())?;
            encrypt_file(
                suite,
                &arguments.input,
                &arguments.output,
                password.as_slice(),
            )
        }
        Operation::Decrypt(arguments) => {
            ensure_distinct(&arguments.input, &arguments.output)?;
            let password = password_for_decryption(arguments.password_file.as_deref())?;
            decrypt_file(
                suite,
                &arguments.input,
                &arguments.output,
                password.as_slice(),
            )
        }
    }
}

fn password_for_encryption(path: Option<&Path>) -> Result<Zeroizing<Vec<u8>>> {
    if let Some(path) = path {
        return read_password_file(path);
    }
    let first = Zeroizing::new(rpassword::prompt_password("Password: ")?);
    validate_password(first.as_bytes())?;
    let second = Zeroizing::new(rpassword::prompt_password("Confirm password: ")?);
    if first.as_bytes() != second.as_bytes() {
        return Err(Error::PasswordMismatch);
    }
    Ok(Zeroizing::new(first.as_bytes().to_vec()))
}

fn password_for_decryption(path: Option<&Path>) -> Result<Zeroizing<Vec<u8>>> {
    if let Some(path) = path {
        return read_password_file(path);
    }
    let password = Zeroizing::new(rpassword::prompt_password("Password: ")?);
    validate_password(password.as_bytes())?;
    Ok(Zeroizing::new(password.as_bytes().to_vec()))
}

fn read_password_file(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let file = File::open(path)?;
    let limit = u64::try_from(MAX_PASSWORD_BYTES)
        .map_err(|_| Error::PasswordTooLong)?
        .checked_add(1)
        .ok_or(Error::PasswordTooLong)?;
    let mut limited: Take<File> = file.take(limit);
    let mut bytes = Zeroizing::new(Vec::new());
    limited.read_to_end(bytes.as_mut())?;
    validate_password(bytes.as_slice())?;
    Ok(bytes)
}

fn validate_password(password: &[u8]) -> Result<()> {
    if password.is_empty() {
        Err(Error::EmptyPassword)
    } else if password.len() > MAX_PASSWORD_BYTES {
        Err(Error::PasswordTooLong)
    } else {
        Ok(())
    }
}

fn ensure_distinct(input: &Path, output: &Path) -> Result<()> {
    let same_existing_file =
        input.try_exists()? && output.try_exists()? && same_file::is_same_file(input, output)?;
    if input == output || same_existing_file {
        Err(Error::SameFile)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    #[test]
    fn password_file_bytes_are_exact_including_newlines() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"password\r\n").unwrap();
        let password = read_password_file(file.path()).unwrap();
        assert_eq!(password.as_slice(), b"password\r\n");
    }

    #[test]
    fn empty_and_overlong_passwords_are_rejected() {
        assert!(matches!(validate_password(b""), Err(Error::EmptyPassword)));
        let too_long = vec![0_u8; MAX_PASSWORD_BYTES + 1];
        assert!(matches!(
            validate_password(&too_long),
            Err(Error::PasswordTooLong)
        ));
    }

    #[test]
    fn same_literal_path_is_rejected() {
        assert!(matches!(
            ensure_distinct(Path::new("file"), Path::new("file")),
            Err(Error::SameFile)
        ));
    }

    #[test]
    fn hard_link_alias_is_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("input");
        let alias = directory.path().join("alias");
        std::fs::write(&input, b"data").unwrap();
        std::fs::hard_link(&input, &alias).unwrap();
        assert!(matches!(
            ensure_distinct(&input, &alias),
            Err(Error::SameFile)
        ));
    }
}
