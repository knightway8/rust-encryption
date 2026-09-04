use std::env;
use std::ffi::{OsStr, OsString};
use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;

use otp1::auth::{
    AuthError, AuthOutcome, auth_key_path_next_to_current_exe, generate_key_next_to_current_exe,
    seal_in_place, seal_raw_in_place, unwrap_in_place, verify_file,
};

const USAGE: &str = "Usage:\n\
  otp1-auth keygen\n\
  otp1-auth seal [--force-raw] [--] <file>\n\
  otp1-auth verify [--] <file>\n\
  otp1-auth unwrap [--] <file>\n\
\n\
Add or check an authenticated envelope without changing otp1's raw XOR format.\n\
The authentication key is auth.key beside the otp1-auth executable.\n\
\n\
Commands:\n\
  keygen          Create auth.key on Unix without replacing an existing key\n\
  seal <file>     Atomically wrap a file in an authenticated envelope\n\
  verify <file>   Check without changing file contents or replacing its path\n\
  unwrap <file>   Verify and atomically restore the enclosed file\n\
\n\
Use '--force-raw' only to seal legitimate raw bytes beginning with OTP1AUTH.\n\
Use '--' before a filename beginning with '-'.\n";

fn main() -> ExitCode {
    match parse_arguments(env::args_os().skip(1)) {
        ParseResult::Help => write_help(),
        ParseResult::UsageError(message) => {
            report_stderr(&format!("otp1-auth: {message}\n\n{USAGE}"));
            ExitCode::from(2)
        }
        ParseResult::Command(Command::Keygen) => finish_mutating_operation(
            "authentication key was created",
            generate_key_next_to_current_exe(),
        ),
        ParseResult::Command(command) => run_file_command(command),
    }
}

fn run_file_command(command: Command) -> ExitCode {
    let (operation, path, force_raw) = match command {
        Command::Seal { path, force_raw } => (Operation::Seal, path, force_raw),
        Command::Verify(path) => (Operation::Verify, path, false),
        Command::Unwrap(path) => (Operation::Unwrap, path, false),
        Command::Keygen => unreachable!("keygen is handled before file commands"),
    };

    let key_path = match auth_key_path_next_to_current_exe() {
        Ok(path) => path,
        Err(error) => {
            report_stderr(&format!("otp1-auth: {error}"));
            return ExitCode::from(1);
        }
    };

    let path = Path::new(&path);
    match operation {
        Operation::Seal => {
            let result = if force_raw {
                seal_raw_in_place(path, &key_path)
            } else {
                seal_in_place(path, &key_path)
            };
            finish_mutating_operation("file was sealed", result)
        }
        Operation::Verify => match verify_file(path, &key_path) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => report_operation_error(Operation::Verify, error),
        },
        Operation::Unwrap => finish_unwrap(unwrap_in_place(path, &key_path)),
    }
}

fn finish_unwrap(result: Result<AuthOutcome, AuthError>) -> ExitCode {
    match result {
        Ok(outcome) => finish_outcome("file was authenticated and unwrapped", outcome),
        Err(error) => report_operation_error(Operation::Unwrap, error),
    }
}

fn finish_mutating_operation(
    completed_description: &str,
    result: Result<AuthOutcome, AuthError>,
) -> ExitCode {
    match result {
        Ok(outcome) => finish_outcome(completed_description, outcome),
        Err(error) => {
            report_stderr(&format!("otp1-auth: {error}"));
            ExitCode::from(1)
        }
    }
}

fn finish_outcome(completed_description: &str, outcome: AuthOutcome) -> ExitCode {
    match outcome {
        AuthOutcome::Committed => ExitCode::SUCCESS,
        AuthOutcome::CommittedButDurabilityUncertain(error) => {
            report_stderr(&format!(
                "otp1-auth: the {completed_description}, but crash durability could not be \
                 confirmed: {error}. DO NOT RETRY automatically; the operation already \
                 completed"
            ));
            ExitCode::from(3)
        }
    }
}

fn report_operation_error(operation: Operation, error: AuthError) -> ExitCode {
    report_stderr(&format!("otp1-auth: {error}"));
    if matches!(operation, Operation::Verify | Operation::Unwrap)
        && error.is_authentication_failure()
    {
        ExitCode::from(4)
    } else {
        ExitCode::from(1)
    }
}

fn write_help() -> ExitCode {
    match io::stdout().lock().write_all(USAGE.as_bytes()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            report_stderr(&format!("otp1-auth: cannot write help output: {error}"));
            ExitCode::from(1)
        }
    }
}

fn report_stderr(message: &str) {
    let mut stderr = io::stderr().lock();
    let _ = stderr.write_all(message.as_bytes());
    let _ = stderr.write_all(b"\n");
}

#[derive(Clone, Copy)]
enum Operation {
    Seal,
    Verify,
    Unwrap,
}

enum Command {
    Keygen,
    Seal { path: OsString, force_raw: bool },
    Verify(OsString),
    Unwrap(OsString),
}

enum ParseResult {
    Help,
    Command(Command),
    UsageError(&'static str),
}

fn parse_arguments(mut arguments: impl Iterator<Item = OsString>) -> ParseResult {
    let Some(command) = arguments.next() else {
        return ParseResult::UsageError("missing command");
    };

    if command == OsStr::new("-h") || command == OsStr::new("--help") {
        return if arguments.next().is_none() {
            ParseResult::Help
        } else {
            ParseResult::UsageError("help does not accept additional arguments")
        };
    }

    if command == OsStr::new("keygen") {
        return if arguments.next().is_none() {
            ParseResult::Command(Command::Keygen)
        } else {
            ParseResult::UsageError("keygen does not accept additional arguments")
        };
    }

    let command_kind = if command == OsStr::new("seal") {
        Operation::Seal
    } else if command == OsStr::new("verify") {
        Operation::Verify
    } else if command == OsStr::new("unwrap") {
        Operation::Unwrap
    } else {
        return ParseResult::UsageError("unknown command");
    };

    parse_file_argument(command_kind, arguments)
}

fn parse_file_argument(
    operation: Operation,
    mut arguments: impl Iterator<Item = OsString>,
) -> ParseResult {
    let Some(first) = arguments.next() else {
        return ParseResult::UsageError("missing filename");
    };

    let (first, force_raw) =
        if matches!(operation, Operation::Seal) && first == OsStr::new("--force-raw") {
            let Some(path) = arguments.next() else {
                return ParseResult::UsageError("missing filename after '--force-raw'");
            };
            (path, true)
        } else {
            (first, false)
        };

    let path = if first == OsStr::new("--") {
        let Some(path) = arguments.next() else {
            return ParseResult::UsageError("missing filename after '--'");
        };
        path
    } else {
        if first.as_encoded_bytes().first() == Some(&b'-') {
            return ParseResult::UsageError(
                "unknown option (use '--' before a dash-prefixed filename)",
            );
        }
        first
    };

    if arguments.next().is_some() {
        return ParseResult::UsageError("expected exactly one filename");
    }

    ParseResult::Command(match operation {
        Operation::Seal => Command::Seal { path, force_raw },
        Operation::Verify => Command::Verify(path),
        Operation::Unwrap => Command::Unwrap(path),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(arguments: &[&str]) -> ParseResult {
        parse_arguments(arguments.iter().map(OsString::from))
    }

    fn command_path(result: ParseResult) -> (&'static str, OsString) {
        match result {
            ParseResult::Command(Command::Seal { path, .. }) => ("seal", path),
            ParseResult::Command(Command::Verify(path)) => ("verify", path),
            ParseResult::Command(Command::Unwrap(path)) => ("unwrap", path),
            _ => panic!("expected a file command"),
        }
    }

    #[test]
    fn every_file_command_accepts_exactly_one_path() {
        assert_eq!(
            command_path(parse(&["seal", "a.bin"])),
            ("seal", "a.bin".into())
        );
        assert_eq!(
            command_path(parse(&["verify", "a.bin"])),
            ("verify", "a.bin".into())
        );
        assert_eq!(
            command_path(parse(&["unwrap", "a.bin"])),
            ("unwrap", "a.bin".into())
        );
    }

    #[test]
    fn force_raw_is_an_explicit_seal_only_option() {
        assert!(matches!(
            parse(&["seal", "--force-raw", "raw.bin"]),
            ParseResult::Command(Command::Seal { path, force_raw })
                if path == OsStr::new("raw.bin") && force_raw
        ));
        assert!(matches!(
            parse(&["verify", "--force-raw", "raw.bin"]),
            ParseResult::UsageError(_)
        ));
        assert!(matches!(
            parse(&["unwrap", "--force-raw", "raw.bin"]),
            ParseResult::UsageError(_)
        ));
    }

    #[test]
    fn keygen_is_accepted_without_a_path() {
        assert!(matches!(
            parse(&["keygen"]),
            ParseResult::Command(Command::Keygen)
        ));
    }

    #[test]
    fn separator_allows_dash_prefixed_paths_for_every_file_command() {
        for command in ["seal", "verify", "unwrap"] {
            let (parsed_command, path) = command_path(parse(&[command, "--", "--help"]));
            assert_eq!(parsed_command, command);
            assert_eq!(path, "--help");
        }
    }

    #[test]
    fn help_flags_are_accepted_alone() {
        assert!(matches!(parse(&["-h"]), ParseResult::Help));
        assert!(matches!(parse(&["--help"]), ParseResult::Help));
    }

    #[test]
    fn missing_and_unknown_commands_are_rejected() {
        assert!(matches!(parse(&[]), ParseResult::UsageError(_)));
        assert!(matches!(parse(&["unknown"]), ParseResult::UsageError(_)));
        assert!(matches!(parse(&["--unknown"]), ParseResult::UsageError(_)));
    }

    #[test]
    fn invalid_file_argument_counts_are_rejected() {
        for command in ["seal", "verify", "unwrap"] {
            assert!(matches!(parse(&[command]), ParseResult::UsageError(_)));
            assert!(matches!(
                parse(&[command, "--"]),
                ParseResult::UsageError(_)
            ));
            assert!(matches!(
                parse(&[command, "one", "two"]),
                ParseResult::UsageError(_)
            ));
            assert!(matches!(
                parse(&[command, "--unknown"]),
                ParseResult::UsageError(_)
            ));
        }
    }

    #[test]
    fn help_and_keygen_reject_extra_arguments() {
        assert!(matches!(
            parse(&["--help", "extra"]),
            ParseResult::UsageError(_)
        ));
        assert!(matches!(
            parse(&["keygen", "extra"]),
            ParseResult::UsageError(_)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_paths_are_preserved() {
        use std::os::unix::ffi::OsStringExt;

        let path = OsString::from_vec(vec![b'f', 0x80]);
        let (_, parsed) = command_path(parse_arguments(
            [OsString::from("seal"), path.clone()].into_iter(),
        ));
        assert_eq!(parsed, path);
    }
}
