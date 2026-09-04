use super::*;
use std::cell::Cell;
use std::io::Cursor;
use std::rc::Rc;

type RunResult = (Result<(), CliError>, Vec<u8>, Vec<(u64, String)>, usize);

fn recorded_run(size_input: &str, supplied_passwords: &[&str]) -> RunResult {
    let mut input = Cursor::new(size_input.as_bytes());
    let mut output = Vec::new();
    let mut passwords = supplied_passwords.iter();
    let prompt_count = Rc::new(Cell::new(0));
    let prompt_count_for_closure = Rc::clone(&prompt_count);
    let mut generated = Vec::new();
    let result = run_with(
        &mut input,
        &mut output,
        |_prompt| {
            prompt_count_for_closure.set(prompt_count_for_closure.get() + 1);
            Ok(passwords.next().unwrap_or(&"").to_string())
        },
        |size, password| {
            generated.push((size, password.as_str().to_owned()));
            Ok(())
        },
    );
    (result, output, generated, prompt_count.get())
}

#[test]
fn cli_success_uses_exact_size_and_password() {
    let (result, output, generated, prompts) =
        recorded_run("4097\n", &["correct horse", "correct horse"]);
    assert!(result.is_ok());
    assert_eq!(generated, vec![(4097, "correct horse".to_owned())]);
    assert_eq!(prompts, 2);
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("Created key.key (4097 bytes)."));
}

#[test]
fn cli_accepts_maximum_without_narrowing_the_byte_count() {
    let (result, _output, generated, prompts) =
        recorded_run("20000000000\n", &["password", "password"]);
    assert!(result.is_ok());
    assert_eq!(generated, vec![(MAX_KEY_BYTES, "password".to_owned())]);
    assert_eq!(prompts, 2);
}

#[test]
fn cli_prompts_for_password_exactly_twice() {
    let (result, _output, generated, prompts) = recorded_run("1\n", &["x", "x", "x"]);
    assert!(result.is_ok());
    assert_eq!(prompts, 2);
    assert_eq!(generated.len(), 1);
}

#[test]
fn cli_preserves_unicode_and_whitespace_password_exactly() {
    let password = " pässword 🔑 ";
    let (result, _output, generated, _) = recorded_run("16\n", &[password, password]);
    assert!(result.is_ok());
    assert_eq!(generated, vec![(16, password.to_owned())]);
}

#[test]
fn cli_rejects_empty_password_before_generation() {
    let (result, _output, generated, prompts) = recorded_run("32\n", &["", ""]);
    assert!(matches!(result, Err(CliError::EmptyPassword)));
    assert!(generated.is_empty());
    assert_eq!(prompts, 2);
}

#[test]
fn cli_rejects_password_mismatch_before_generation() {
    let (result, _output, generated, prompts) = recorded_run("32\n", &["one", "two"]);
    assert!(matches!(result, Err(CliError::PasswordMismatch)));
    assert!(generated.is_empty());
    assert_eq!(prompts, 2);
}

#[test]
fn cli_checks_size_before_asking_for_password() {
    for invalid in ["0\n", "20000000001\n", "1GB\n", "\n"] {
        let (result, _output, generated, prompts) = recorded_run(invalid, &["unused"]);
        assert!(
            matches!(result, Err(CliError::Size(_))),
            "input {invalid:?}"
        );
        assert!(generated.is_empty());
        assert_eq!(prompts, 0);
    }
}

#[test]
fn cli_bounds_size_input_before_asking_for_password() {
    let maximum_length = format!("{}1\n", " ".repeat(126));
    let (result, _output, generated, prompts) =
        recorded_run(&maximum_length, &["password", "password"]);
    assert!(result.is_ok());
    assert_eq!(generated, vec![(1, "password".to_owned())]);
    assert_eq!(prompts, 2);

    let too_long = format!("{}1\n", " ".repeat(127));
    let (result, output, generated, prompts) = recorded_run(&too_long, &["unused"]);
    assert!(matches!(result, Err(CliError::SizeInputTooLong)));
    assert!(generated.is_empty());
    assert_eq!(prompts, 0);
    let output = String::from_utf8(output).unwrap();
    assert!(!output.contains("Generating key.key"));
}

#[test]
fn cli_reports_eof_before_password_or_generation() {
    let (result, _output, generated, prompts) = recorded_run("", &["unused"]);
    assert!(matches!(result, Err(CliError::Io(_))));
    assert!(generated.is_empty());
    assert_eq!(prompts, 0);
}

#[test]
fn cli_propagates_first_password_read_error() {
    let mut input = Cursor::new(b"8\n");
    let mut output = Vec::new();
    let generated = Cell::new(false);
    let result = run_with(
        &mut input,
        &mut output,
        |_prompt| Err(io::Error::other("password input failed")),
        |_size, _password| {
            generated.set(true);
            Ok(())
        },
    );
    assert!(matches!(result, Err(CliError::Io(_))));
    assert!(!generated.get());
}

#[test]
fn cli_propagates_second_password_read_error() {
    let mut input = Cursor::new(b"8\n");
    let mut output = Vec::new();
    let calls = Cell::new(0);
    let result = run_with(
        &mut input,
        &mut output,
        |_prompt| {
            calls.set(calls.get() + 1);
            if calls.get() == 1 {
                Ok("password".to_owned())
            } else {
                Err(io::Error::other("confirmation input failed"))
            }
        },
        |_size, _password| Ok(()),
    );
    assert!(matches!(result, Err(CliError::Io(_))));
    assert_eq!(calls.get(), 2);
}

#[test]
fn cli_propagates_generation_failure_without_success_message() {
    let mut input = Cursor::new(b"8\n");
    let mut output = Vec::new();
    let mut passwords = ["password", "password"].into_iter();
    let result = run_with(
        &mut input,
        &mut output,
        |_prompt| Ok(passwords.next().unwrap().to_owned()),
        |_size, _password| Err(crate::GenerateError::Io(io::Error::other("disk full"))),
    );
    assert!(matches!(result, Err(CliError::Generate(_))));
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("Generating key.key..."));
    assert!(!output.contains("Created key.key"));
}

#[test]
fn cli_errors_and_output_do_not_reveal_password() {
    let password = "NEVER-PRINT-THIS-PASSWORD";
    let (result, output, generated, _) = recorded_run("8\n", &[password, "mismatch"]);
    let error = result.unwrap_err().to_string();
    let output = String::from_utf8(output).unwrap();
    assert!(!error.contains(password));
    assert!(!output.contains(password));
    assert!(generated.is_empty());
}

struct FailAfterCommitWriter {
    bytes: Vec<u8>,
    committed: Rc<Cell<bool>>,
}

impl Write for FailAfterCommitWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self.committed.get() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "injected post-commit console failure",
            ));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn cli_distinguishes_post_commit_status_failure() {
    let committed = Rc::new(Cell::new(false));
    let mut output = FailAfterCommitWriter {
        bytes: Vec::new(),
        committed: Rc::clone(&committed),
    };
    let mut input = Cursor::new(b"8\n");
    let mut passwords = ["password", "password"].into_iter();
    let committed_by_generator = Rc::clone(&committed);

    let result = run_with(
        &mut input,
        &mut output,
        |_prompt| Ok(passwords.next().unwrap().to_owned()),
        move |_size, _password| {
            committed_by_generator.set(true);
            Ok(())
        },
    );

    let error = result.expect_err("the final console write must fail");
    assert!(matches!(&error, CliError::CommittedButStatusWriteFailed(_)));
    assert!(committed.get());
    assert!(error.to_string().contains("key.key was created"));
    let output = String::from_utf8(output.bytes).unwrap();
    assert!(output.contains("Generating key.key..."));
    assert!(!output.contains("Created key.key"));
}
