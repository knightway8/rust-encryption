#![forbid(unsafe_code)]

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use filecrypt::{
    Algorithm, FileCryptError, decrypt_file, encrypt_file, generate_executable_key,
    load_executable_key,
};

const HELP: &str = "\
filecrypt — authenticated streaming file encryption

USAGE:
    filecrypt <1|2> <INPUT> <OUTPUT>
    filecrypt encrypt <1|2> <INPUT> <OUTPUT>
    filecrypt decrypt <INPUT> <OUTPUT>
    filecrypt keygen

ALGORITHMS:
    1    AES-256-GCM-SIV
    2    XChaCha20-Poly1305

The short three-argument form encrypts. Decryption reads the algorithm from
the authenticated file header. Every cryptographic operation uses the raw
32-byte key.key beside this executable, never a key in the working directory.
No command ever overwrites an existing file.
";

enum Command {
    Encrypt {
        algorithm: Algorithm,
        input: PathBuf,
        output: PathBuf,
    },
    Decrypt {
        input: PathBuf,
        output: PathBuf,
    },
    Keygen,
    Help,
    Version,
}

#[derive(Debug)]
enum CliError {
    Operation(FileCryptError),
    StandardOutput(io::Error),
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Operation(error) => error.fmt(formatter),
            Self::StandardOutput(error) => {
                write!(formatter, "could not write to standard output: {error}")
            }
        }
    }
}

impl std::error::Error for CliError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Operation(error) => Some(error),
            Self::StandardOutput(error) => Some(error),
        }
    }
}

impl From<FileCryptError> for CliError {
    fn from(error: FileCryptError) -> Self {
        Self::Operation(error)
    }
}

fn main() -> ExitCode {
    match parse(std::env::args_os().skip(1).collect()) {
        Ok(Command::Help) => finish_stdout(write_stdout(format_args!("{HELP}"))),
        Ok(Command::Version) => finish_stdout(write_stdout(format_args!(
            "filecrypt {}\n",
            env!("CARGO_PKG_VERSION")
        ))),
        Ok(command) => match execute(command) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                report_error(&error);
                ExitCode::FAILURE
            }
        },
        Err(message) => {
            let _result = write_stderr(format_args!("error: {message}\n\n{HELP}"));
            ExitCode::from(2)
        }
    }
}

fn finish_stdout(result: io::Result<()>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let error = sanitize_terminal_text(&error.to_string());
            let _result = write_stderr(format_args!(
                "error: could not write to standard output: {error}\n"
            ));
            ExitCode::FAILURE
        }
    }
}

fn execute(command: Command) -> std::result::Result<(), CliError> {
    match command {
        Command::Encrypt {
            algorithm,
            input,
            output,
        } => {
            let key = load_executable_key()?;
            encrypt_file(algorithm, &input, &output, &key)?;
            let input = terminal_safe_path(&input);
            let output = terminal_safe_path(&output);
            let algorithm_name = algorithm.name();
            write_stdout(format_args!(
                "encrypted with {algorithm_name}: '{input}' -> '{output}'\n"
            ))
            .map_err(CliError::StandardOutput)?;
            Ok(())
        }
        Command::Decrypt { input, output } => {
            let key = load_executable_key()?;
            let algorithm = decrypt_file(&input, &output, &key)?;
            let input = terminal_safe_path(&input);
            let output = terminal_safe_path(&output);
            let algorithm_name = algorithm.name();
            write_stdout(format_args!(
                "decrypted {algorithm_name} stream: '{input}' -> '{output}'\n"
            ))
            .map_err(CliError::StandardOutput)?;
            Ok(())
        }
        Command::Keygen => {
            let path = generate_executable_key()?;
            let path = terminal_safe_path(&path);
            write_stdout(format_args!(
                "created 32-byte key at '{path}'\nkeep this file secret and backed up; encrypted files cannot be recovered without it\n"
            ))
            .map_err(CliError::StandardOutput)?;
            Ok(())
        }
        Command::Help | Command::Version => Ok(()),
    }
}

fn report_error(error: &dyn fmt::Display) {
    let message = sanitize_terminal_text(&error.to_string());
    let _result = write_stderr(format_args!("error: {message}\n"));
}

fn terminal_safe_path(path: &Path) -> String {
    sanitize_terminal_text(&path.to_string_lossy())
}

fn sanitize_terminal_text(text: &str) -> String {
    let mut sanitized = String::with_capacity(text.len());
    for character in text.chars() {
        if is_terminal_control(character) {
            sanitized.extend(character.escape_default());
        } else {
            sanitized.push(character);
        }
    }
    sanitized
}

fn is_terminal_control(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{061c}'
                | '\u{200e}'
                | '\u{200f}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
        )
}

fn write_stdout(arguments: fmt::Arguments<'_>) -> io::Result<()> {
    let mut output = io::stdout().lock();
    output.write_fmt(arguments)?;
    output.flush()
}

fn write_stderr(arguments: fmt::Arguments<'_>) -> io::Result<()> {
    let mut output = io::stderr().lock();
    output.write_fmt(arguments)?;
    output.flush()
}

fn parse(mut arguments: Vec<OsString>) -> std::result::Result<Command, &'static str> {
    if arguments
        .first()
        .is_some_and(|value| value == "-h" || value == "--help")
    {
        return (arguments.len() == 1)
            .then_some(Command::Help)
            .ok_or("help option does not accept arguments");
    }
    if arguments
        .first()
        .is_some_and(|value| value == "-V" || value == "--version")
    {
        return (arguments.len() == 1)
            .then_some(Command::Version)
            .ok_or("version option does not accept arguments");
    }
    if arguments.first().is_some_and(|value| value == "keygen") {
        return (arguments.len() == 1)
            .then_some(Command::Keygen)
            .ok_or("keygen does not accept arguments");
    }

    if arguments.first().is_some_and(|value| value == "decrypt") {
        arguments.remove(0);
        remove_path_separator(&mut arguments);
        return match arguments.as_slice() {
            [input, output] => Ok(Command::Decrypt {
                input: PathBuf::from(input),
                output: PathBuf::from(output),
            }),
            _ => Err("decrypt requires exactly INPUT and OUTPUT paths"),
        };
    }
    let explicit_encrypt = arguments.first().is_some_and(|value| value == "encrypt");
    if explicit_encrypt {
        arguments.remove(0);
    }

    let selector = arguments.first().ok_or(if explicit_encrypt {
        "encrypt requires an algorithm, INPUT, and OUTPUT"
    } else {
        "missing command or encryption algorithm"
    })?;
    let algorithm = Algorithm::from_selector(selector.as_os_str())
        .ok_or("algorithm must be exactly 1 (AES-256-GCM-SIV) or 2 (XChaCha20-Poly1305)")?;
    arguments.remove(0);
    remove_path_separator(&mut arguments);
    match arguments.as_slice() {
        [input, output] => Ok(Command::Encrypt {
            algorithm,
            input: PathBuf::from(input),
            output: PathBuf::from(output),
        }),
        _ => Err("encryption requires exactly INPUT and OUTPUT paths"),
    }
}

fn remove_path_separator(arguments: &mut Vec<OsString>) {
    if arguments
        .first()
        .is_some_and(|value| value == OsStr::new("--"))
    {
        arguments.remove(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_short_encrypt_form() {
        let command = parse(vec!["1".into(), "in".into(), "out".into()]);
        assert!(matches!(
            command,
            Ok(Command::Encrypt {
                algorithm: Algorithm::Aes256GcmSiv,
                ..
            })
        ));
    }

    #[test]
    fn parses_decrypt_paths_starting_with_dash() {
        let command = parse(vec![
            "decrypt".into(),
            "--".into(),
            "-input".into(),
            "-output".into(),
        ]);
        assert!(matches!(command, Ok(Command::Decrypt { .. })));
    }

    #[test]
    fn rejects_unknown_algorithm() {
        let command = parse(vec!["3".into(), "in".into(), "out".into()]);
        assert!(command.is_err());
    }

    #[test]
    fn explicit_encrypt_cannot_be_reinterpreted_as_decrypt() {
        let command = parse(vec![
            "encrypt".into(),
            "decrypt".into(),
            "in".into(),
            "out".into(),
        ]);
        assert!(command.is_err());
    }

    #[test]
    fn recognized_zero_argument_commands_reject_trailing_arguments() {
        assert_eq!(
            parse(vec!["--help".into(), "extra".into()]).err(),
            Some("help option does not accept arguments")
        );
        assert_eq!(
            parse(vec!["--version".into(), "extra".into()]).err(),
            Some("version option does not accept arguments")
        );
        assert_eq!(
            parse(vec!["keygen".into(), "extra".into()]).err(),
            Some("keygen does not accept arguments")
        );
    }

    #[test]
    fn terminal_text_escapes_line_ansi_and_bidi_controls() {
        assert_eq!(
            sanitize_terminal_text("ordinary é\n\u{1b}[31m\u{202e}"),
            "ordinary é\\n\\u{1b}[31m\\u{202e}"
        );
    }
}
