use std::{ffi::OsString, io, path::PathBuf};

use age::secrecy::{ExposeSecret, SecretString};

use crate::Error;

pub const USAGE: &str = "Usage:\n  secure E <input-file> <output-file>\n  secure D <input-file> <output-file>\n\nE and D are uppercase. Passwords are read privately from the controlling terminal.\nExisting output files are never overwritten.";

const MIN_PASSWORD_CHARS: usize = 12;
const MAX_PASSWORD_BYTES: usize = 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    Encrypt,
    Decrypt,
}

impl Operation {
    fn parse(value: &std::ffi::OsStr) -> Result<Self, Error> {
        match value.to_str() {
            Some("E") => Ok(Self::Encrypt),
            Some("D") => Ok(Self::Decrypt),
            _ => Err(Error::InvalidOperation),
        }
    }

    #[must_use]
    pub const fn completed_verb(self) -> &'static str {
        match self {
            Self::Encrypt => "Encryption",
            Self::Decrypt => "Decryption",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    pub operation: Operation,
    pub input: PathBuf,
    pub output: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParseOutcome {
    Help,
    Version,
    Run(Config),
}

/// Parses the complete process argument vector into a requested action.
///
/// # Errors
///
/// Returns [`Error::InvalidArguments`] unless the invocation is help, version,
/// or exactly `secure E|D input output`. Returns [`Error::InvalidOperation`]
/// when a complete run invocation does not use uppercase `E` or `D`.
pub fn parse_args<I>(args: I) -> Result<ParseOutcome, Error>
where
    I: IntoIterator<Item = OsString>,
{
    let args: Vec<_> = args.into_iter().collect();

    if args.len() == 2 {
        if args[1] == "-h" || args[1] == "--help" {
            return Ok(ParseOutcome::Help);
        }
        if args[1] == "-V" || args[1] == "--version" {
            return Ok(ParseOutcome::Version);
        }
    }

    if args.len() != 4 {
        return Err(Error::InvalidArguments);
    }

    Ok(ParseOutcome::Run(Config {
        operation: Operation::parse(&args[1])?,
        input: PathBuf::from(&args[2]),
        output: PathBuf::from(&args[3]),
    }))
}

/// Reads and validates the password needed for `operation`.
///
/// Encryption requires a minimum-strength new password and an exact second
/// confirmation. Decryption intentionally accepts short legacy passwords.
///
/// # Errors
///
/// Returns a password policy or confirmation error, or [`Error::PasswordInput`]
/// when the supplied prompt cannot read from the terminal.
pub fn read_password<F>(operation: Operation, mut prompt: F) -> Result<SecretString, Error>
where
    F: FnMut(&str) -> io::Result<String>,
{
    let first_prompt = match operation {
        Operation::Encrypt => "New password: ",
        Operation::Decrypt => "Password: ",
    };
    let password = SecretString::from(prompt(first_prompt).map_err(Error::PasswordInput)?);

    if operation == Operation::Encrypt {
        validate_new_password(&password)?;
        let confirmation =
            SecretString::from(prompt("Confirm password: ").map_err(Error::PasswordInput)?);
        if password.expose_secret() != confirmation.expose_secret() {
            return Err(Error::PasswordMismatch);
        }
    }

    if password.expose_secret().len() > MAX_PASSWORD_BYTES {
        return Err(Error::PasswordTooLong {
            maximum: MAX_PASSWORD_BYTES,
        });
    }

    Ok(password)
}

fn validate_new_password(password: &SecretString) -> Result<(), Error> {
    let value = password.expose_secret();
    let characters = value.chars().count();
    if characters < MIN_PASSWORD_CHARS {
        return Err(Error::PasswordTooShort {
            minimum: MIN_PASSWORD_CHARS,
        });
    }
    if value.len() > MAX_PASSWORD_BYTES {
        return Err(Error::PasswordTooLong {
            maximum: MAX_PASSWORD_BYTES,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        ffi::OsString,
        io,
        path::{Path, PathBuf},
    };

    use age::secrecy::{ExposeSecret, SecretString};

    use super::{
        Config, MAX_PASSWORD_BYTES, MIN_PASSWORD_CHARS, Operation, ParseOutcome, parse_args,
        read_password,
    };
    use crate::Error;

    type PromptLog = std::rc::Rc<std::cell::RefCell<Vec<String>>>;
    type TestPrompt = Box<dyn FnMut(&str) -> io::Result<String>>;

    fn argv(arguments: &[&str]) -> Vec<OsString> {
        std::iter::once(OsString::from("secure"))
            .chain(arguments.iter().map(OsString::from))
            .collect()
    }

    fn expect_parse_error(arguments: &[&str]) -> Error {
        match parse_args(argv(arguments)) {
            Ok(outcome) => panic!("expected parsing to fail, got {outcome:?}"),
            Err(error) => error,
        }
    }

    fn expect_password_error(result: Result<SecretString, Error>) -> Error {
        match result {
            Ok(_) => panic!("expected password reading to fail"),
            Err(error) => error,
        }
    }

    fn scripted_prompt(
        answers: impl IntoIterator<Item = io::Result<String>>,
    ) -> (TestPrompt, PromptLog) {
        let mut answers: VecDeque<_> = answers.into_iter().collect();
        let prompts = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let observed = prompts.clone();
        let prompt = move |message: &str| {
            observed.borrow_mut().push(message.to_owned());
            answers.pop_front().unwrap_or_else(|| {
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "test prompt was called too many times",
                ))
            })
        };
        (Box::new(prompt), prompts)
    }

    #[test]
    fn parses_encrypt_configuration() {
        let parsed = parse_args(argv(&["E", "plain.txt", "plain.txt.age"])).unwrap();

        assert_eq!(
            parsed,
            ParseOutcome::Run(Config {
                operation: Operation::Encrypt,
                input: PathBuf::from("plain.txt"),
                output: PathBuf::from("plain.txt.age"),
            })
        );
    }

    #[test]
    fn parses_decrypt_configuration() {
        let parsed = parse_args(argv(&["D", "plain.txt.age", "plain.txt"])).unwrap();

        assert_eq!(
            parsed,
            ParseOutcome::Run(Config {
                operation: Operation::Decrypt,
                input: PathBuf::from("plain.txt.age"),
                output: PathBuf::from("plain.txt"),
            })
        );
    }

    #[test]
    fn operation_is_strictly_uppercase_e_or_d() {
        for invalid in [
            "",
            "e",
            "d",
            "Encrypt",
            "Decrypt",
            "ED",
            " E",
            "E ",
            "D\n",
            "-E",
            "--encrypt",
            "--decrypt",
        ] {
            assert!(
                matches!(
                    expect_parse_error(&[invalid, "input", "output"]),
                    Error::InvalidOperation
                ),
                "operation {invalid:?} was unexpectedly accepted"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn every_single_byte_operation_except_ascii_e_and_d_is_rejected() {
        use std::os::unix::ffi::OsStringExt;

        for byte in u8::MIN..=u8::MAX {
            let args = vec![
                OsString::from("secure"),
                OsString::from_vec(vec![byte]),
                OsString::from("input"),
                OsString::from("output"),
            ];
            let parsed = parse_args(args);

            match byte {
                b'E' => assert!(matches!(
                    parsed,
                    Ok(ParseOutcome::Run(Config {
                        operation: Operation::Encrypt,
                        ..
                    }))
                )),
                b'D' => assert!(matches!(
                    parsed,
                    Ok(ParseOutcome::Run(Config {
                        operation: Operation::Decrypt,
                        ..
                    }))
                )),
                _ => assert!(matches!(parsed, Err(Error::InvalidOperation))),
            }
        }
    }

    #[test]
    fn help_aliases_are_recognized_only_as_the_sole_argument() {
        for help in ["-h", "--help"] {
            assert_eq!(parse_args(argv(&[help])).unwrap(), ParseOutcome::Help);
            assert!(matches!(
                expect_parse_error(&[help, "input", "output"]),
                Error::InvalidOperation
            ));
            assert!(matches!(
                expect_parse_error(&[help, "extra"]),
                Error::InvalidArguments
            ));
        }
    }

    #[test]
    fn version_aliases_are_recognized_only_as_the_sole_argument() {
        for version in ["-V", "--version"] {
            assert_eq!(parse_args(argv(&[version])).unwrap(), ParseOutcome::Version);
            assert!(matches!(
                expect_parse_error(&[version, "input", "output"]),
                Error::InvalidOperation
            ));
            assert!(matches!(
                expect_parse_error(&[version, "extra"]),
                Error::InvalidArguments
            ));
        }
    }

    #[test]
    fn help_and_version_spelling_is_case_sensitive() {
        for invalid in ["-H", "--Help", "--HELP", "-v", "--Version", "--VERSION"] {
            assert!(matches!(
                expect_parse_error(&[invalid]),
                Error::InvalidArguments
            ));
        }
    }

    #[test]
    fn rejects_every_argument_count_other_than_four_total_arguments() {
        for count in 0..=12 {
            if count == 4 {
                continue;
            }

            let mut args: Vec<OsString> = (0..count)
                .map(|index| OsString::from(format!("argument-{index}")))
                .collect();
            if count > 1 {
                args[1] = OsString::from("E");
            }

            assert!(
                matches!(parse_args(args), Err(Error::InvalidArguments)),
                "accepted a total argument count of {count}"
            );
        }
    }

    #[test]
    fn filenames_that_look_like_options_are_preserved_positionally() {
        let parsed = parse_args(argv(&["E", "--help", "--version"])).unwrap();

        assert_eq!(
            parsed,
            ParseOutcome::Run(Config {
                operation: Operation::Encrypt,
                input: PathBuf::from("--help"),
                output: PathBuf::from("--version"),
            })
        );
    }

    #[test]
    fn filenames_with_spaces_tabs_newlines_and_leading_dashes_are_preserved() {
        let input = "  -input name\twith-tab\nand-newline  ";
        let output = "-output name \n";
        let parsed = parse_args(argv(&["D", input, output])).unwrap();
        let ParseOutcome::Run(config) = parsed else {
            panic!("expected a run configuration");
        };

        assert_eq!(config.input, Path::new(input));
        assert_eq!(config.output, Path::new(output));
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_program_name_and_filenames_are_preserved() {
        use std::os::unix::ffi::{OsStrExt, OsStringExt};

        let input = vec![b'i', b'n', 0x80, b'p', b'u', b't'];
        let output = vec![0xff, b'o', b'u', b't'];
        let parsed = parse_args(vec![
            OsString::from_vec(vec![0xfe]),
            OsString::from("E"),
            OsString::from_vec(input.clone()),
            OsString::from_vec(output.clone()),
        ])
        .unwrap();
        let ParseOutcome::Run(config) = parsed else {
            panic!("expected a run configuration");
        };

        assert_eq!(config.input.as_os_str().as_bytes(), input);
        assert_eq!(config.output.as_os_str().as_bytes(), output);
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_operation_is_rejected_without_affecting_filename_parsing() {
        use std::os::unix::ffi::OsStringExt;

        let error = parse_args(vec![
            OsString::from("secure"),
            OsString::from_vec(vec![0xff]),
            OsString::from("input"),
            OsString::from("output"),
        ])
        .unwrap_err();

        assert!(matches!(error, Error::InvalidOperation));
    }

    #[test]
    fn completed_verbs_match_operations() {
        assert_eq!(Operation::Encrypt.completed_verb(), "Encryption");
        assert_eq!(Operation::Decrypt.completed_verb(), "Decryption");
    }

    #[test]
    fn encryption_prompts_for_new_password_then_confirmation() {
        let password = "correct horse battery staple";
        let (prompt, prompts) = scripted_prompt([Ok(password.to_owned()), Ok(password.to_owned())]);

        let secret = read_password(Operation::Encrypt, prompt).unwrap();

        assert_eq!(secret.expose_secret(), password);
        assert_eq!(
            prompts.borrow().as_slice(),
            ["New password: ", "Confirm password: "]
        );
    }

    #[test]
    fn decryption_prompts_exactly_once() {
        let (prompt, prompts) = scripted_prompt([Ok("legacy".to_owned())]);

        let secret = read_password(Operation::Decrypt, prompt).unwrap();

        assert_eq!(secret.expose_secret(), "legacy");
        assert_eq!(prompts.borrow().as_slice(), ["Password: "]);
    }

    #[test]
    fn decryption_accepts_empty_and_short_legacy_passwords() {
        for password in ["", "x", "elevenchars"] {
            let (prompt, prompts) = scripted_prompt([Ok(password.to_owned())]);
            let secret = read_password(Operation::Decrypt, prompt).unwrap();

            assert_eq!(secret.expose_secret(), password);
            assert_eq!(prompts.borrow().as_slice(), ["Password: "]);
        }
    }

    #[test]
    fn encryption_rejects_one_character_below_the_minimum_before_confirmation() {
        let short = "a".repeat(MIN_PASSWORD_CHARS - 1);
        let (prompt, prompts) = scripted_prompt([Ok(short)]);

        let error = expect_password_error(read_password(Operation::Encrypt, prompt));

        assert!(matches!(
            error,
            Error::PasswordTooShort {
                minimum: MIN_PASSWORD_CHARS
            }
        ));
        assert_eq!(prompts.borrow().as_slice(), ["New password: "]);
    }

    #[test]
    fn encryption_accepts_exactly_the_minimum_character_count() {
        let minimum = "a".repeat(MIN_PASSWORD_CHARS);
        let (prompt, prompts) = scripted_prompt([Ok(minimum.clone()), Ok(minimum.clone())]);

        let secret = read_password(Operation::Encrypt, prompt).unwrap();

        assert_eq!(secret.expose_secret(), &minimum);
        assert_eq!(prompts.borrow().len(), 2);
    }

    #[test]
    fn minimum_length_counts_unicode_scalar_values_not_utf8_bytes() {
        let too_short = "🔐".repeat(MIN_PASSWORD_CHARS - 1);
        assert!(too_short.len() > MIN_PASSWORD_CHARS);
        let (prompt, _) = scripted_prompt([Ok(too_short)]);
        assert!(matches!(
            expect_password_error(read_password(Operation::Encrypt, prompt)),
            Error::PasswordTooShort {
                minimum: MIN_PASSWORD_CHARS
            }
        ));

        let minimum = "🔐".repeat(MIN_PASSWORD_CHARS);
        let (prompt, _) = scripted_prompt([Ok(minimum.clone()), Ok(minimum.clone())]);
        let secret = read_password(Operation::Encrypt, prompt).unwrap();
        assert_eq!(secret.expose_secret(), &minimum);
    }

    #[test]
    fn encryption_accepts_exactly_the_maximum_byte_length() {
        let maximum = "a".repeat(MAX_PASSWORD_BYTES);
        let (prompt, prompts) = scripted_prompt([Ok(maximum.clone()), Ok(maximum.clone())]);

        let secret = read_password(Operation::Encrypt, prompt).unwrap();

        assert_eq!(secret.expose_secret().len(), MAX_PASSWORD_BYTES);
        assert_eq!(prompts.borrow().len(), 2);
    }

    #[test]
    fn encryption_rejects_one_byte_above_the_maximum_before_confirmation() {
        let too_long = "a".repeat(MAX_PASSWORD_BYTES + 1);
        let (prompt, prompts) = scripted_prompt([Ok(too_long)]);

        let error = expect_password_error(read_password(Operation::Encrypt, prompt));

        assert!(matches!(
            error,
            Error::PasswordTooLong {
                maximum: MAX_PASSWORD_BYTES
            }
        ));
        assert_eq!(prompts.borrow().as_slice(), ["New password: "]);
    }

    #[test]
    fn maximum_length_is_measured_in_utf8_bytes() {
        let maximum = "é".repeat(MAX_PASSWORD_BYTES / 2);
        assert_eq!(maximum.len(), MAX_PASSWORD_BYTES);
        let (prompt, _) = scripted_prompt([Ok(maximum.clone()), Ok(maximum.clone())]);
        assert!(read_password(Operation::Encrypt, prompt).is_ok());

        let too_long = format!("{maximum}é");
        let (prompt, _) = scripted_prompt([Ok(too_long)]);
        assert!(matches!(
            expect_password_error(read_password(Operation::Encrypt, prompt)),
            Error::PasswordTooLong {
                maximum: MAX_PASSWORD_BYTES
            }
        ));
    }

    #[test]
    fn decryption_enforces_the_maximum_but_not_the_minimum() {
        let maximum = "a".repeat(MAX_PASSWORD_BYTES);
        let (prompt, prompts) = scripted_prompt([Ok(maximum.clone())]);
        let secret = read_password(Operation::Decrypt, prompt).unwrap();
        assert_eq!(secret.expose_secret(), &maximum);
        assert_eq!(prompts.borrow().len(), 1);

        let too_long = "a".repeat(MAX_PASSWORD_BYTES + 1);
        let (prompt, prompts) = scripted_prompt([Ok(too_long)]);
        assert!(matches!(
            expect_password_error(read_password(Operation::Decrypt, prompt)),
            Error::PasswordTooLong {
                maximum: MAX_PASSWORD_BYTES
            }
        ));
        assert_eq!(prompts.borrow().len(), 1);
    }

    #[test]
    fn confirmation_must_match_exactly() {
        let first = "correct horse battery staple";
        let second = "correct horse battery staplf";
        let (prompt, prompts) = scripted_prompt([Ok(first.to_owned()), Ok(second.to_owned())]);

        let error = expect_password_error(read_password(Operation::Encrypt, prompt));

        assert!(matches!(error, Error::PasswordMismatch));
        assert_eq!(prompts.borrow().len(), 2);
        let message = error.to_string();
        assert!(!message.contains(first));
        assert!(!message.contains(second));
    }

    #[test]
    fn leading_and_trailing_whitespace_is_preserved() {
        let password = "  leading and trailing whitespace  ";
        let (prompt, _) = scripted_prompt([Ok(password.to_owned()), Ok(password.to_owned())]);

        let secret = read_password(Operation::Encrypt, prompt).unwrap();

        assert_eq!(secret.expose_secret(), password);
    }

    #[test]
    fn whitespace_is_not_trimmed_during_confirmation() {
        let first = "  correct horse battery staple  ";
        let trimmed = first.trim();
        let (prompt, _) = scripted_prompt([Ok(first.to_owned()), Ok(trimmed.to_owned())]);

        assert!(matches!(
            expect_password_error(read_password(Operation::Encrypt, prompt)),
            Error::PasswordMismatch
        ));
    }

    #[test]
    fn unicode_is_not_normalized_during_confirmation() {
        let composed = "é".repeat(MIN_PASSWORD_CHARS);
        let decomposed = "e\u{301}".repeat(MIN_PASSWORD_CHARS);
        assert_ne!(composed.as_bytes(), decomposed.as_bytes());
        let (prompt, _) = scripted_prompt([Ok(composed), Ok(decomposed)]);

        assert!(matches!(
            expect_password_error(read_password(Operation::Encrypt, prompt)),
            Error::PasswordMismatch
        ));
    }

    #[test]
    fn error_from_first_encryption_prompt_is_propagated_and_stops_prompting() {
        let (prompt, prompts) = scripted_prompt([Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "no controlling terminal",
        ))]);

        let error = expect_password_error(read_password(Operation::Encrypt, prompt));

        let Error::PasswordInput(source) = error else {
            panic!("expected a password input error");
        };
        assert_eq!(source.kind(), io::ErrorKind::NotConnected);
        assert_eq!(prompts.borrow().as_slice(), ["New password: "]);
    }

    #[test]
    fn error_from_decryption_prompt_is_propagated() {
        let (prompt, prompts) = scripted_prompt([Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "terminal reached EOF",
        ))]);

        let error = expect_password_error(read_password(Operation::Decrypt, prompt));

        let Error::PasswordInput(source) = error else {
            panic!("expected a password input error");
        };
        assert_eq!(source.kind(), io::ErrorKind::UnexpectedEof);
        assert_eq!(prompts.borrow().as_slice(), ["Password: "]);
    }

    #[test]
    fn error_from_confirmation_prompt_is_propagated_after_both_prompts() {
        let password = "correct horse battery staple";
        let (prompt, prompts) = scripted_prompt([
            Ok(password.to_owned()),
            Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "prompt interrupted",
            )),
        ]);

        let error = expect_password_error(read_password(Operation::Encrypt, prompt));

        let Error::PasswordInput(source) = error else {
            panic!("expected a password input error");
        };
        assert_eq!(source.kind(), io::ErrorKind::Interrupted);
        assert_eq!(
            prompts.borrow().as_slice(),
            ["New password: ", "Confirm password: "]
        );
    }
}
