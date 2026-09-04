#![forbid(unsafe_code)]

use std::{
    env,
    error::Error as StdError,
    fmt,
    io::{self, Write},
    process::ExitCode,
};
use subtle::ConstantTimeEq;
use x2::{
    Command, CryptoError, HELP, Operation, ParsedCommand, execute_prepared_file_operation,
    parse_cli_args, prepare_file_operation,
};
use zeroize::Zeroizing;

const MAX_PASSWORD_BYTES: usize = 1_024;

fn main() -> ExitCode {
    let parsed = match parse_cli_args(env::args_os().skip(1)) {
        Ok(parsed) => parsed,
        Err(error) => {
            let mut stderr = io::stderr().lock();
            let _ = writeln!(stderr, "x2: {error}\nTry 'x2 --help' for usage.");
            return ExitCode::from(2);
        }
    };

    match parsed {
        ParsedCommand::Help => {
            let mut stdout = io::stdout().lock();
            exit_for_output(stdout.write_all(HELP.as_bytes()))
        }
        ParsedCommand::Version => {
            let mut stdout = io::stdout().lock();
            exit_for_output(writeln!(stdout, "x2 {}", env!("CARGO_PKG_VERSION")))
        }
        ParsedCommand::Run(command) => match run(command) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                let mut stderr = io::stderr().lock();
                let _ = writeln!(stderr, "x2: {error}");
                ExitCode::FAILURE
            }
        },
    }
}

fn exit_for_output(result: io::Result<()>) -> ExitCode {
    if result.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn run(command: Command) -> Result<(), RunError> {
    let operation = command.operation;
    let prepared = prepare_file_operation(command)?;
    let password = password_for_operation(operation)?;
    execute_prepared_file_operation(prepared, password.as_bytes())?;
    Ok(())
}

fn password_for_operation(operation: Operation) -> Result<Zeroizing<String>, RunError> {
    password_for_operation_with(operation, prompt_password)
}

fn password_for_operation_with<P>(
    operation: Operation,
    mut prompt: P,
) -> Result<Zeroizing<String>, RunError>
where
    P: FnMut(&str) -> Result<Zeroizing<String>, RunError>,
{
    match operation {
        Operation::Encrypt => confirmed_password_with(&mut prompt),
        Operation::Decrypt => {
            let password = prompt("Password: ")?;
            validate_password(&password)?;
            Ok(password)
        }
    }
}

fn confirmed_password_with<P>(mut prompt: P) -> Result<Zeroizing<String>, RunError>
where
    P: FnMut(&str) -> Result<Zeroizing<String>, RunError>,
{
    let password = prompt("Password: ")?;
    let confirmation = prompt("Confirm password: ")?;
    validate_password(&password)?;
    validate_password(&confirmation)?;
    if !passwords_match(&password, &confirmation) {
        return Err(RunError::PasswordMismatch);
    }
    Ok(password)
}

fn passwords_match(password: &str, confirmation: &str) -> bool {
    bool::from(password.as_bytes().ct_eq(confirmation.as_bytes()))
}

fn validate_password(password: &str) -> Result<(), RunError> {
    if password.is_empty() {
        return Err(RunError::EmptyPassword);
    }
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(RunError::PasswordTooLong);
    }
    Ok(())
}

fn prompt_password(prompt: &str) -> Result<Zeroizing<String>, RunError> {
    rpassword::prompt_password(prompt)
        .map(Zeroizing::new)
        .map_err(RunError::PasswordPrompt)
}

#[derive(Debug)]
enum RunError {
    PasswordPrompt(io::Error),
    PasswordMismatch,
    EmptyPassword,
    PasswordTooLong,
    Crypto(CryptoError),
}

impl fmt::Display for RunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PasswordPrompt(error) => write!(formatter, "cannot read password: {error}"),
            Self::PasswordMismatch => formatter.write_str("passwords do not match"),
            Self::EmptyPassword => formatter.write_str("password must not be empty"),
            Self::PasswordTooLong => write!(
                formatter,
                "password must not exceed {MAX_PASSWORD_BYTES} UTF-8 bytes"
            ),
            Self::Crypto(error) => error.fmt(formatter),
        }
    }
}

impl StdError for RunError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::PasswordPrompt(error) => Some(error),
            Self::Crypto(error) => Some(error),
            Self::PasswordMismatch | Self::EmptyPassword | Self::PasswordTooLong => None,
        }
    }
}

impl From<CryptoError> for RunError {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    struct FailedWriter;

    impl Write for FailedWriter {
        fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("injected output failure"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other("injected output failure"))
        }
    }

    #[test]
    fn password_confirmation_is_exact() {
        assert!(passwords_match("a passphrase 🦀", "a passphrase 🦀"));
        assert!(!passwords_match("passphrase", "Passphrase"));
        assert!(!passwords_match("passphrase", "passphrase "));
        assert!(!passwords_match("", "different"));
    }

    #[test]
    fn encryption_confirmation_prompts_exactly_twice() {
        let mut prompts = Vec::new();
        let password = password_for_operation_with(Operation::Encrypt, |prompt| {
            prompts.push(prompt.to_owned());
            Ok(Zeroizing::new("secret".to_owned()))
        })
        .expect("matching passwords");

        assert_eq!(&*password, "secret");
        assert_eq!(prompts, ["Password: ", "Confirm password: "]);
    }

    #[test]
    fn decryption_prompts_exactly_once() {
        let mut prompts = Vec::new();
        let password = password_for_operation_with(Operation::Decrypt, |prompt| {
            prompts.push(prompt.to_owned());
            Ok(Zeroizing::new("secret".to_owned()))
        })
        .expect("nonempty password");

        assert_eq!(&*password, "secret");
        assert_eq!(prompts, ["Password: "]);
    }

    #[test]
    fn password_acceptance_is_bounded() {
        assert!(validate_password("a").is_ok());
        assert!(matches!(
            validate_password(""),
            Err(RunError::EmptyPassword)
        ));
        let too_long = "x".repeat(MAX_PASSWORD_BYTES + 1);
        assert!(matches!(
            validate_password(&too_long),
            Err(RunError::PasswordTooLong)
        ));
    }

    #[test]
    fn failed_standard_output_is_an_error_not_a_panic() {
        assert_eq!(
            exit_for_output(FailedWriter.write_all(HELP.as_bytes())),
            ExitCode::FAILURE
        );
    }
}
