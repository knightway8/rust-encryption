#![cfg(target_os = "linux")]

use std::{
    ffi::OsStr,
    fs,
    process::{Command, Output, Stdio},
};

use secure::USAGE;

fn run(arguments: impl IntoIterator<Item = impl AsRef<OsStr>>) -> Output {
    Command::new(env!("CARGO_BIN_EXE_secure"))
        .args(arguments)
        .stdin(Stdio::null())
        .env("LC_ALL", "C")
        .output()
        .expect("secure binary should run")
}

fn stdout(output: &Output) -> &str {
    std::str::from_utf8(&output.stdout).expect("stdout should be UTF-8")
}

fn stderr(output: &Output) -> &str {
    std::str::from_utf8(&output.stderr).expect("stderr should be UTF-8")
}

#[test]
fn long_help_exits_successfully_without_prompting() {
    let output = run(["--help"]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(stdout(&output), format!("{USAGE}\n"));
    assert_eq!(stderr(&output), "");
    assert!(!stdout(&output).contains("New password:"));
    assert!(!stdout(&output).contains("Password: "));
}

#[test]
fn short_help_exits_successfully_without_prompting() {
    let output = run(["-h"]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(stdout(&output), format!("{USAGE}\n"));
    assert_eq!(stderr(&output), "");
}

#[test]
fn long_version_exits_successfully_without_prompting() {
    let output = run(["--version"]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        stdout(&output),
        format!("secure {}\n", env!("CARGO_PKG_VERSION"))
    );
    assert_eq!(stderr(&output), "");
}

#[test]
fn short_version_exits_successfully_without_prompting() {
    let output = run(["-V"]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        stdout(&output),
        format!("secure {}\n", env!("CARGO_PKG_VERSION"))
    );
    assert_eq!(stderr(&output), "");
}

#[test]
fn no_arguments_is_a_usage_error_without_prompting() {
    let output = run(std::iter::empty::<&str>());

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(stdout(&output), "");
    assert!(stderr(&output).contains("expected exactly an uppercase operation"));
    assert!(stderr(&output).contains(USAGE));
    assert!(!stderr(&output).contains("New password:"));
    assert!(!stderr(&output).contains("Password: "));
}

#[test]
fn lowercase_operation_is_a_usage_error_without_prompting() {
    let output = run(["e", "input", "output"]);

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(stdout(&output), "");
    assert!(stderr(&output).contains("operation must be uppercase E"));
    assert!(stderr(&output).contains(USAGE));
    assert!(!stderr(&output).contains("New password:"));
    assert!(!stderr(&output).contains("Password: "));
}

#[test]
fn missing_filename_is_a_usage_error_without_prompting() {
    let output = run(["E", "input"]);

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(stdout(&output), "");
    assert!(stderr(&output).contains("expected exactly an uppercase operation"));
    assert!(stderr(&output).contains(USAGE));
    assert!(!stderr(&output).contains("New password:"));
}

#[test]
fn extra_argument_is_a_usage_error_without_prompting() {
    let output = run(["D", "input", "output", "extra"]);

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(stdout(&output), "");
    assert!(stderr(&output).contains("expected exactly an uppercase operation"));
    assert!(stderr(&output).contains(USAGE));
    assert!(!stderr(&output).contains("Password: "));
}

#[test]
fn help_with_an_extra_argument_is_not_treated_as_help() {
    let output = run(["--help", "extra"]);

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(stdout(&output), "");
    assert!(stderr(&output).contains("expected exactly an uppercase operation"));
    assert!(stderr(&output).contains(USAGE));
}

#[test]
fn help_in_the_operation_position_is_rejected() {
    let output = run(["--help", "input", "output"]);

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(stdout(&output), "");
    assert!(stderr(&output).contains("operation must be uppercase E"));
    assert!(stderr(&output).contains(USAGE));
    assert!(!stderr(&output).contains("Password: "));
}

#[test]
fn valid_operation_without_a_controlling_terminal_fails_closed() {
    let directory = tempfile::tempdir().expect("temporary directory should be created");
    let input = directory.path().join("input");
    let encrypted = directory.path().join("output.age");
    fs::write(&input, b"must remain plaintext-only").expect("input fixture should be written");

    let output = Command::new("setsid")
        .arg(env!("CARGO_BIN_EXE_secure"))
        .arg("E")
        .arg(&input)
        .arg(&encrypted)
        .stdin(Stdio::null())
        .env("LC_ALL", "C")
        .output()
        .expect("detached secure process should run");

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(stdout(&output), "");
    assert!(stderr(&output).contains("could not read the password from the terminal"));
    assert!(!encrypted.exists());
}
