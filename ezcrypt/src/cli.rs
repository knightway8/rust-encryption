use crate::crypto::validate_password;
use crate::{EzError, Operation};
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io;
use std::path::PathBuf;
use zeroize::Zeroizing;

pub const USAGE: &str = concat!(
    "Usage:\n",
    "  ezcrypt <FILE>\n",
    "  ezcrypt -- <FILE>\n",
    "  ezcrypt --help\n",
    "  ezcrypt --version\n",
    "\n",
    "Encrypts FILE to FILE.ez, or decrypts a name ending in .ez.\n",
    "Use -- before a file name that starts with '-'.\n",
    "The password is requested securely and is never accepted on the command line.\n",
    "\n",
    "Options:\n",
    "  -h, --help       Print help.\n",
    "  -V, --version    Print version."
);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CliCommand {
    Help,
    Version,
    Transform(PathBuf),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CliError(pub &'static str);

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for CliError {}

pub fn parse_args<I>(args: I) -> Result<CliCommand, CliError>
where
    I: IntoIterator<Item = OsString>,
{
    let args: Vec<OsString> = args.into_iter().collect();
    match args.as_slice() {
        [] => Err(CliError("exactly one file name is required")),
        [only] if only == OsStr::new("--help") || only == OsStr::new("-h") => Ok(CliCommand::Help),
        [only] if only == OsStr::new("--version") || only == OsStr::new("-V") => {
            Ok(CliCommand::Version)
        }
        [separator, path] if separator == OsStr::new("--") => {
            Ok(CliCommand::Transform(PathBuf::from(path)))
        }
        [separator] if separator == OsStr::new("--") => {
            Err(CliError("exactly one file name is required"))
        }
        [only] if starts_with_dash(only) => Err(CliError(
            "unknown option; use -- before a file name that starts with '-'",
        )),
        [only] => Ok(CliCommand::Transform(PathBuf::from(only))),
        _ => Err(CliError("exactly one file name is required")),
    }
}

pub trait PasswordPrompter {
    fn prompt(&mut self, prompt: &str) -> io::Result<String>;
}

pub struct ConsolePrompter;

impl PasswordPrompter for ConsolePrompter {
    fn prompt(&mut self, prompt: &str) -> io::Result<String> {
        rpassword::prompt_password(prompt)
    }
}

pub fn request_password<P: PasswordPrompter>(
    operation: Operation,
    prompter: &mut P,
) -> Result<Zeroizing<String>, EzError> {
    let password = Zeroizing::new(
        prompter
            .prompt("Password: ")
            .map_err(EzError::PasswordPrompt)?,
    );
    validate_password(password.as_bytes())?;
    if operation == Operation::Encrypt {
        let confirmation = Zeroizing::new(
            prompter
                .prompt("Confirm password: ")
                .map_err(EzError::PasswordPrompt)?,
        );
        if password.as_bytes() != confirmation.as_bytes() {
            return Err(EzError::InvalidPassword("confirmation does not match"));
        }
    }
    Ok(password)
}

fn starts_with_dash(value: &OsStr) -> bool {
    value.to_string_lossy().starts_with('-')
}
