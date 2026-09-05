#![forbid(unsafe_code)]
#![allow(clippy::expect_used)]

use std::process::Command;
#[cfg(unix)]
use std::process::Stdio;

fn x2() -> Command {
    Command::new(env!("CARGO_BIN_EXE_x2"))
}

#[test]
fn help_is_successful_and_documents_exact_commands() {
    let output = x2().arg("--help").output().expect("run x2 --help");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 help text");
    assert!(stdout.contains("x2 E AES"));
    assert!(stdout.contains("x2 E XCHA"));
    assert!(stdout.contains("x2 D AES"));
    assert!(stdout.contains("x2 D XCHA"));
    assert!(output.stderr.is_empty());
}

#[test]
fn version_is_successful() {
    let output = x2().arg("--version").output().expect("run x2 --version");
    assert!(output.status.success());
    assert_eq!(output.stdout, b"x2 0.1.0\n");
    assert!(output.stderr.is_empty());
}

#[test]
fn invalid_commands_return_usage_exit_code_without_panicking() {
    for arguments in [
        Vec::<&str>::new(),
        vec!["E"],
        vec!["e", "AES", "in", "out"],
        vec!["E", "CHACHA", "in", "out"],
        vec!["E", "AES", "in", "out", "extra"],
    ] {
        let output = x2().args(arguments).output().expect("run invalid command");
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("x2:"));
    }
}

#[test]
fn missing_input_fails_before_a_password_prompt() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let output_path = directory.path().join("output");
    let output = x2()
        .arg("E")
        .arg("AES")
        .arg(directory.path().join("missing"))
        .arg(output_path)
        .output()
        .expect("run x2");
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("cannot open input"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("Password:"));
}

#[test]
fn directory_input_is_reported_without_prompting_or_creating_output() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let destination = directory.path().join("output");
    let result = x2()
        .args(["E", "AES"])
        .arg(directory.path())
        .arg(&destination)
        .stdin(std::process::Stdio::null())
        .output()
        .expect("run x2 with a directory input");
    assert_eq!(result.status.code(), Some(1));
    let error = String::from_utf8_lossy(&result.stderr);
    assert!(error.contains("regular file"), "{error}");
    assert!(!error.contains("Password:"));
    assert!(!destination.exists());
}

#[cfg(unix)]
#[test]
fn failed_stdout_and_stderr_never_panic() {
    let full = || {
        std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/full")
            .expect("open /dev/full")
    };

    let help_status = x2()
        .arg("--help")
        .stdout(Stdio::from(full()))
        .status()
        .expect("run x2 --help");
    assert_eq!(help_status.code(), Some(1));

    let usage_status = x2()
        .stderr(Stdio::from(full()))
        .status()
        .expect("run invalid x2 command");
    assert_eq!(usage_status.code(), Some(2));
}
