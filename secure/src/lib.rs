#![forbid(unsafe_code)]
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

#[cfg(not(target_os = "linux"))]
compile_error!("secure intentionally supports Linux only");

mod cancel;
mod cli;
mod crypto;
mod error;
mod linux_fs;
mod tty;

pub use cancel::Cancellation;
pub use cli::{Config, Operation, ParseOutcome, USAGE, parse_args, read_password};
pub use error::Error;
pub use tty::read_password_from_terminal;

use age::secrecy::SecretString;

/// Disables core dumps and same-UID process inspection before a password is read.
///
/// # Errors
///
/// Returns [`Error::ProcessHardening`] if Linux refuses either protection.
pub fn harden_process() -> Result<(), Error> {
    use rustix::process::{
        DumpableBehavior, Resource, Rlimit, getrlimit, set_dumpable_behavior, setrlimit,
    };

    set_dumpable_behavior(DumpableBehavior::NotDumpable)
        .map_err(|error| Error::ProcessHardening(std::io::Error::from(error)))?;
    let current = getrlimit(Resource::Core);
    setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: current.maximum,
        },
    )
    .map_err(|error| Error::ProcessHardening(std::io::Error::from(error)))
}

/// Encrypts or decrypts one regular file according to `config`.
///
/// The destination is created with private permissions and is published only
/// after the complete operation succeeds. An existing destination is never
/// overwritten.
///
/// # Errors
///
/// Returns an [`Error`] if path validation, authenticated streaming, durable
/// writing, or atomic publication fails.
pub fn execute(config: &Config, password: SecretString) -> Result<(), Error> {
    execute_cancellable(config, password, &Cancellation::never())
}

/// Runs one operation while observing termination requests installed through
/// [`Cancellation::install`].
///
/// # Errors
///
/// Returns [`Error::Interrupted`] before publication when a handled termination
/// signal arrives, or another [`Error`] for normal operation failures.
pub fn execute_cancellable(
    config: &Config,
    password: SecretString,
    cancellation: &Cancellation,
) -> Result<(), Error> {
    match config.operation {
        Operation::Encrypt => linux_fs::encrypt_file_cancellable(
            &config.input,
            &config.output,
            password,
            cancellation,
        ),
        Operation::Decrypt => linux_fs::decrypt_file_cancellable(
            &config.input,
            &config.output,
            password,
            cancellation,
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use rustix::process::{DumpableBehavior, Resource, dumpable_behavior, getrlimit};

    use super::harden_process;

    const HARDENING_CHILD: &str = "SECURE_TEST_HARDENING_CHILD";

    #[test]
    fn process_hardening_disables_dumpability_and_core_dumps() {
        if std::env::var_os(HARDENING_CHILD).is_some() {
            harden_process().unwrap();
            assert_eq!(dumpable_behavior().unwrap(), DumpableBehavior::NotDumpable);
            assert_eq!(getrlimit(Resource::Core).current, Some(0));
            return;
        }

        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::process_hardening_disables_dumpability_and_core_dumps",
                "--nocapture",
            ])
            .env(HARDENING_CHILD, "1")
            .status()
            .unwrap();
        assert!(status.success());
    }
}
