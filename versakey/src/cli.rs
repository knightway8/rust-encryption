//! Shared interactive command-line interface for the VersaKey binaries.

use crate::{
    GeneratorConfig, GeneratorSuite, MAX_KEY_BYTES, OUTPUT_FILENAME, generate_key_file_with_suite,
    parse_size,
};
use std::error::Error;
use std::fmt;
use std::io::{self, BufRead, Read, Write};
use std::path::Path;
use std::process::ExitCode;
use zeroize::Zeroizing;

const MAX_SIZE_INPUT_BYTES: u64 = 128;

#[derive(Debug)]
enum CliError {
    Io(io::Error),
    Size(crate::SizeError),
    SizeInputTooLong,
    EmptyPassword,
    PasswordMismatch,
    Generate(crate::GenerateError),
    CommittedButStatusWriteFailed(io::Error),
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "console input/output failed: {error}"),
            Self::Size(error) => error.fmt(formatter),
            Self::SizeInputTooLong => write!(formatter, "key size input is too long"),
            Self::EmptyPassword => write!(formatter, "password cannot be empty"),
            Self::PasswordMismatch => write!(formatter, "passwords did not match"),
            Self::Generate(error) => error.fmt(formatter),
            Self::CommittedButStatusWriteFailed(error) => write!(
                formatter,
                "key.key was created, but reporting success to the console failed: {error}"
            ),
        }
    }
}

impl Error for CliError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Size(error) => Some(error),
            Self::Generate(error) => Some(error),
            Self::CommittedButStatusWriteFailed(error) => Some(error),
            Self::SizeInputTooLong | Self::EmptyPassword | Self::PasswordMismatch => None,
        }
    }
}

impl From<io::Error> for CliError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<crate::SizeError> for CliError {
    fn from(error: crate::SizeError) -> Self {
        Self::Size(error)
    }
}

impl From<crate::GenerateError> for CliError {
    fn from(error: crate::GenerateError) -> Self {
        Self::Generate(error)
    }
}

/// Run the interactive CLI for one deterministic generator configuration.
///
/// Every byte in `config` is part of the deterministic input and must remain
/// stable for a released binary whose output needs to stay reproducible.
pub fn run_cli(suite: GeneratorSuite, config: GeneratorConfig<'_>) -> ExitCode {
    match run(suite, config) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let stderr = io::stderr();
            let mut error_output = stderr.lock();
            let _ = writeln!(error_output, "Error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(suite: GeneratorSuite, config: GeneratorConfig<'_>) -> Result<(), CliError> {
    let current_directory = std::env::current_dir()?;
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let stdout = io::stdout();
    let mut output = stdout.lock();
    writeln!(output, "VersaKey suite: {}", suite.display_name())?;

    run_with(
        &mut input,
        &mut output,
        |prompt| rpassword::prompt_password(prompt),
        |size, password| {
            generate_key_file_with_suite(
                Path::new(&current_directory),
                password,
                size,
                config,
                suite,
            )?;
            Ok(())
        },
    )
}

fn run_with<R, W, P, G>(
    input: &mut R,
    output: &mut W,
    mut prompt_password: P,
    generate: G,
) -> Result<(), CliError>
where
    R: BufRead,
    W: Write,
    P: FnMut(&str) -> io::Result<String>,
    G: FnOnce(u64, Zeroizing<String>) -> Result<(), crate::GenerateError>,
{
    writeln!(
        output,
        "VersaKey deterministic key maker (1 to {MAX_KEY_BYTES} bytes)"
    )?;
    write!(output, "Key size in bytes: ")?;
    output.flush()?;

    let mut size_input = String::new();
    let bytes_read = input
        .take(MAX_SIZE_INPUT_BYTES + 1)
        .read_line(&mut size_input)?;
    if bytes_read == 0 {
        return Err(CliError::Io(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "no key size was provided",
        )));
    }
    if bytes_read as u64 > MAX_SIZE_INPUT_BYTES {
        return Err(CliError::SizeInputTooLong);
    }
    let size = parse_size(&size_input)?;

    let password = Zeroizing::new(prompt_password("Password: ")?);
    let confirmation = Zeroizing::new(prompt_password("Confirm password: ")?);
    if password.is_empty() {
        return Err(CliError::EmptyPassword);
    }
    if password.as_bytes() != confirmation.as_bytes() {
        return Err(CliError::PasswordMismatch);
    }
    drop(confirmation);

    writeln!(output, "Generating {OUTPUT_FILENAME}...")?;
    output.flush()?;
    generate(size, password)?;
    writeln!(output, "Created {OUTPUT_FILENAME} ({size} bytes).")
        .map_err(CliError::CommittedButStatusWriteFailed)?;
    Ok(())
}

#[cfg(test)]
#[path = "cli_tests.rs"]
mod tests;
