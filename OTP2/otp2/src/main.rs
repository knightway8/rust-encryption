use std::env;
use std::ffi::{OsStr, OsString};
use std::io::{self, Write};
use std::process::ExitCode;

use otp2::{EncryptOutcome, OtpError, encrypt_in_place, key_path_next_to_current_exe};

const USAGE: &str = "Usage: otp2 [--] <input-file>\n\
\n\
Atomically XOR each input byte with the corresponding byte from key.key,\n\
which must be beside the otp2 executable. Applying the same key twice restores\n\
the original file. The key must be at least as long as the input.\n";

fn main() -> ExitCode {
    match parse_input_path(env::args_os().skip(1)) {
        ParseResult::Help => match io::stdout().lock().write_all(USAGE.as_bytes()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                report_stderr(&format!("otp2: cannot write help output: {error}"));
                ExitCode::from(1)
            }
        },
        ParseResult::UsageError(message) => {
            report_stderr(&format!("otp2: {message}\n\n{USAGE}"));
            ExitCode::from(2)
        }
        ParseResult::Input(input_path) => {
            let key_path = match key_path_next_to_current_exe() {
                Ok(path) => path,
                Err(error) => {
                    report_stderr(&format!("otp2: {error}"));
                    return ExitCode::from(1);
                }
            };

            finish_transform(encrypt_in_place(&input_path, &key_path))
        }
    }
}

fn finish_transform(result: Result<EncryptOutcome, OtpError>) -> ExitCode {
    finish_transform_with_reporter(result, report_stderr)
}

fn finish_transform_with_reporter(
    result: Result<EncryptOutcome, OtpError>,
    report: impl FnOnce(&str),
) -> ExitCode {
    match result {
        Ok(EncryptOutcome::Committed) => ExitCode::SUCCESS,
        Ok(EncryptOutcome::CommittedButDurabilityUncertain(error)) => {
            report(&format!(
                "otp2: the file was atomically transformed, but crash durability could not be \
                 confirmed: {error}. DO NOT RETRY automatically; another XOR would reverse the \
                 completed transformation"
            ));
            ExitCode::from(3)
        }
        Err(error @ OtpError::CommitOutcomeUncertain { .. }) => {
            report(&format!("otp2: {error}"));
            ExitCode::from(3)
        }
        Err(error) => {
            report(&format!("otp2: {error}"));
            ExitCode::from(1)
        }
    }
}

fn report_stderr(message: &str) {
    let mut stderr = io::stderr().lock();
    let _ = stderr.write_all(message.as_bytes());
    let _ = stderr.write_all(b"\n");
}

enum ParseResult {
    Help,
    Input(OsString),
    UsageError(&'static str),
}

fn parse_input_path(mut arguments: impl Iterator<Item = OsString>) -> ParseResult {
    let Some(first) = arguments.next() else {
        return ParseResult::UsageError("missing input filename");
    };

    if first == OsStr::new("-h") || first == OsStr::new("--help") {
        return if arguments.next().is_none() {
            ParseResult::Help
        } else {
            ParseResult::UsageError("help does not accept additional arguments")
        };
    }

    if first != OsStr::new("--") && first.as_encoded_bytes().first() == Some(&b'-') {
        return ParseResult::UsageError(
            "unknown option (use '--' before a dash-prefixed filename)",
        );
    }

    let input = if first == OsStr::new("--") {
        let Some(input) = arguments.next() else {
            return ParseResult::UsageError("missing input filename after '--'");
        };
        input
    } else {
        first
    };

    if arguments.next().is_some() {
        ParseResult::UsageError("expected exactly one input filename")
    } else {
        ParseResult::Input(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(arguments: &[&str]) -> ParseResult {
        parse_input_path(arguments.iter().map(OsString::from))
    }

    #[test]
    fn exactly_one_path_is_accepted() {
        match parse(&["file.bin"]) {
            ParseResult::Input(path) => assert_eq!(path, "file.bin"),
            _ => panic!("path was not accepted"),
        }
    }

    #[test]
    fn separator_allows_dash_prefixed_path() {
        match parse(&["--", "--help"]) {
            ParseResult::Input(path) => assert_eq!(path, "--help"),
            _ => panic!("path after -- was not accepted"),
        }
    }

    #[test]
    fn help_flags_are_accepted_alone() {
        assert!(matches!(parse(&["-h"]), ParseResult::Help));
        assert!(matches!(parse(&["--help"]), ParseResult::Help));
    }

    #[test]
    fn invalid_argument_counts_are_rejected() {
        assert!(matches!(parse(&[]), ParseResult::UsageError(_)));
        assert!(matches!(parse(&["--"]), ParseResult::UsageError(_)));
        assert!(matches!(parse(&["one", "two"]), ParseResult::UsageError(_)));
        assert!(matches!(
            parse(&["--help", "extra"]),
            ParseResult::UsageError(_)
        ));
        assert!(matches!(parse(&["--unknown"]), ParseResult::UsageError(_)));
    }

    #[test]
    fn uncertain_commit_outcome_uses_do_not_retry_exit_status() {
        let error = OtpError::CommitOutcomeUncertain {
            path: "input.bin".into(),
            source: io::Error::from_raw_os_error(libc::EINTR),
        };

        let mut diagnostic = String::new();
        let status = finish_transform_with_reporter(Err(error), |message| {
            diagnostic.push_str(message);
        });

        assert_eq!(status, ExitCode::from(3));
        assert!(diagnostic.contains("DO NOT RETRY"));
    }
}
