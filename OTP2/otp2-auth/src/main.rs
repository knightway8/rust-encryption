use std::env;
use std::ffi::{OsStr, OsString};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use otp2_auth::{
    AuthError, AuthOutcome, auth_key_path_next_to_current_exe, create_tag, default_tag_path,
    generate_key_next_to_current_exe, verify_file,
};

const USAGE: &str = r#"Usage:
  otp2-auth keygen
  otp2-auth tag [--replace] [--output <sidecar>] [--] <file>
  otp2-auth verify [--tag <sidecar>] [--] <file>

Create or verify a detached authentication sidecar without modifying the file.
The secret key is auth.key beside the otp2-auth executable.

Commands:
  keygen          Create a new private auth.key; never replace an existing path
  tag <file>      Create <file>.otp2auth, or the path selected by --output
  verify <file>   Verify <file> using its default sidecar, or --tag <sidecar>

Options:
  --replace       Atomically replace an existing regular sidecar
  --output PATH   Select the sidecar created by tag
  --tag PATH      Select the sidecar read by verify
  --              Treat the remaining argument as a filename
"#;

fn main() -> ExitCode {
    match parse_arguments(env::args_os().skip(1)) {
        ParseResult::Help => write_help(),
        ParseResult::UsageError(message) => {
            report_stderr(&format!("otp2-auth: {message}\n\n{USAGE}"));
            ExitCode::from(2)
        }
        ParseResult::Command(Command::Keygen) => finish_commit(
            "authentication key was created",
            generate_key_next_to_current_exe(),
        ),
        ParseResult::Command(command) => run_file_command(command),
    }
}

fn run_file_command(command: Command) -> ExitCode {
    let key_path = match auth_key_path_next_to_current_exe() {
        Ok(path) => path,
        Err(error) => return report_runtime_error(error),
    };
    match command {
        Command::Tag {
            file,
            sidecar,
            replace,
        } => {
            let sidecar = match selected_or_default_sidecar(sidecar, &file) {
                Ok(path) => path,
                Err(error) => return report_runtime_error(error),
            };
            finish_commit(
                "sidecar was created",
                create_tag(&file, sidecar, key_path, replace),
            )
        }
        Command::Verify { file, sidecar } => {
            let sidecar = match selected_or_default_sidecar(sidecar, &file) {
                Ok(path) => path,
                Err(error) => return report_runtime_error(error),
            };
            match verify_file(file, sidecar, key_path) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) if error.is_authentication_failure() => {
                    report_stderr(&format!("otp2-auth: {error}"));
                    ExitCode::from(4)
                }
                Err(error) => report_runtime_error(error),
            }
        }
        Command::Keygen => unreachable!("keygen is handled before file commands"),
    }
}

fn selected_or_default_sidecar(
    selected: Option<OsString>,
    file: &OsStr,
) -> Result<PathBuf, AuthError> {
    selected
        .map(PathBuf::from)
        .map(Ok)
        .unwrap_or_else(|| default_tag_path(Path::new(file)))
}

fn finish_commit(description: &str, result: Result<AuthOutcome, AuthError>) -> ExitCode {
    match result {
        Ok(AuthOutcome::Committed) => ExitCode::SUCCESS,
        Ok(AuthOutcome::CommittedButDurabilityUncertain(error)) => {
            report_stderr(&format!(
                "otp2-auth: the {description}, but crash durability could not be confirmed: \
                 {error}. DO NOT RETRY automatically; inspect the resulting path first"
            ));
            ExitCode::from(3)
        }
        Err(error @ AuthError::CommitOutcomeUncertain { .. }) => {
            report_stderr(&format!("otp2-auth: {error}"));
            ExitCode::from(3)
        }
        Err(error) => report_runtime_error(error),
    }
}

fn report_runtime_error(error: AuthError) -> ExitCode {
    report_stderr(&format!("otp2-auth: {error}"));
    ExitCode::from(1)
}

fn write_help() -> ExitCode {
    match io::stdout().lock().write_all(USAGE.as_bytes()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            report_stderr(&format!("otp2-auth: cannot write help output: {error}"));
            ExitCode::from(1)
        }
    }
}

fn report_stderr(message: &str) {
    let mut stderr = io::stderr().lock();
    let _ = stderr.write_all(message.as_bytes());
    let _ = stderr.write_all(b"\n");
}

#[derive(Debug, Eq, PartialEq)]
enum Command {
    Keygen,
    Tag {
        file: OsString,
        sidecar: Option<OsString>,
        replace: bool,
    },
    Verify {
        file: OsString,
        sidecar: Option<OsString>,
    },
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
    if command == OsStr::new("tag") {
        parse_tag_arguments(arguments)
    } else if command == OsStr::new("verify") {
        parse_verify_arguments(arguments)
    } else {
        ParseResult::UsageError("unknown command")
    }
}

fn parse_tag_arguments(mut arguments: impl Iterator<Item = OsString>) -> ParseResult {
    let mut replace = false;
    let mut sidecar = None;
    let mut file = None;
    let mut options = true;
    while let Some(argument) = arguments.next() {
        if options && argument == OsStr::new("--") {
            options = false;
            continue;
        }
        if options && argument == OsStr::new("--replace") {
            if replace {
                return ParseResult::UsageError("--replace may be specified only once");
            }
            replace = true;
            continue;
        }
        if options && argument == OsStr::new("--output") {
            if sidecar.is_some() {
                return ParseResult::UsageError("--output may be specified only once");
            }
            let Some(path) = arguments.next() else {
                return ParseResult::UsageError("missing sidecar path after --output");
            };
            sidecar = Some(path);
            continue;
        }
        if options && starts_with_dash(&argument) {
            return ParseResult::UsageError(
                "unknown option (use '--' before a dash-prefixed filename)",
            );
        }
        if file.replace(argument).is_some() {
            return ParseResult::UsageError("expected exactly one filename");
        }
    }
    match file {
        Some(file) => ParseResult::Command(Command::Tag {
            file,
            sidecar,
            replace,
        }),
        None => ParseResult::UsageError("missing filename"),
    }
}

fn parse_verify_arguments(mut arguments: impl Iterator<Item = OsString>) -> ParseResult {
    let mut sidecar = None;
    let mut file = None;
    let mut options = true;
    while let Some(argument) = arguments.next() {
        if options && argument == OsStr::new("--") {
            options = false;
            continue;
        }
        if options && argument == OsStr::new("--tag") {
            if sidecar.is_some() {
                return ParseResult::UsageError("--tag may be specified only once");
            }
            let Some(path) = arguments.next() else {
                return ParseResult::UsageError("missing sidecar path after --tag");
            };
            sidecar = Some(path);
            continue;
        }
        if options && starts_with_dash(&argument) {
            return ParseResult::UsageError(
                "unknown option (use '--' before a dash-prefixed filename)",
            );
        }
        if file.replace(argument).is_some() {
            return ParseResult::UsageError("expected exactly one filename");
        }
    }
    match file {
        Some(file) => ParseResult::Command(Command::Verify { file, sidecar }),
        None => ParseResult::UsageError("missing filename"),
    }
}

fn starts_with_dash(value: &OsStr) -> bool {
    value.as_encoded_bytes().first() == Some(&b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(arguments: &[&str]) -> ParseResult {
        parse_arguments(arguments.iter().map(OsString::from))
    }

    #[test]
    fn parses_keygen_and_help() {
        assert!(matches!(
            parse(&["keygen"]),
            ParseResult::Command(Command::Keygen)
        ));
        assert!(matches!(parse(&["--help"]), ParseResult::Help));
    }

    #[test]
    fn package_binary_and_usage_names_remain_aligned() {
        assert_eq!(env!("CARGO_PKG_NAME"), "otp2-auth");
        assert_eq!(env!("CARGO_BIN_NAME"), env!("CARGO_PKG_NAME"));
        assert!(USAGE.starts_with("Usage:\n  otp2-auth keygen\n"));
    }

    #[test]
    fn parses_default_tag_and_verify_commands() {
        assert!(matches!(
            parse(&["tag", "file"]),
            ParseResult::Command(Command::Tag { file, sidecar: None, replace: false })
                if file == "file"
        ));
        assert!(matches!(
            parse(&["verify", "file"]),
            ParseResult::Command(Command::Verify { file, sidecar: None }) if file == "file"
        ));
    }

    #[test]
    fn parses_explicit_sidecars_and_replacement() {
        assert!(matches!(
            parse(&["tag", "--replace", "--output", "tag", "file"]),
            ParseResult::Command(Command::Tag { file, sidecar: Some(tag), replace: true })
                if file == "file" && tag == "tag"
        ));
        assert!(matches!(
            parse(&["verify", "--tag", "tag", "file"]),
            ParseResult::Command(Command::Verify { file, sidecar: Some(tag) })
                if file == "file" && tag == "tag"
        ));
    }

    #[test]
    fn accepts_dash_prefixed_file_after_separator() {
        assert!(matches!(
            parse(&["tag", "--", "-file"]),
            ParseResult::Command(Command::Tag { file, .. }) if file == "-file"
        ));
        assert!(matches!(
            parse(&["verify", "--", "-file"]),
            ParseResult::Command(Command::Verify { file, .. }) if file == "-file"
        ));
    }

    #[test]
    fn rejects_missing_duplicate_and_unknown_arguments() {
        for arguments in [
            &[][..],
            &["keygen", "extra"],
            &["tag"],
            &["verify"],
            &["tag", "--replace", "--replace", "file"],
            &["tag", "--output", "a", "--output", "b", "file"],
            &["verify", "--tag", "a", "--tag", "b", "file"],
            &["tag", "--bad", "file"],
            &["verify", "file", "extra"],
        ] {
            assert!(matches!(parse(arguments), ParseResult::UsageError(_)));
        }
    }
}
