use ezcrypt::cli::USAGE;
use std::os::windows::process::CommandExt;
use std::process::{Command, Output};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

fn run(args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ezcrypt"));
    command
        .args(args)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .creation_flags(CREATE_NO_WINDOW);
    command.output().expect("ezcrypt executable should run")
}

fn text(bytes: &[u8]) -> String {
    std::str::from_utf8(bytes)
        .expect("CLI output should be UTF-8")
        .replace("\r\n", "\n")
}

fn assert_exit(output: &Output, expected: i32) {
    assert_eq!(output.status.code(), Some(expected), "output: {output:?}");
}

fn usage_error(message: &str) -> String {
    format!("error: {message}\n\n{USAGE}\n")
}

#[test]
fn help_prints_usage_to_stdout() {
    let output = run(&["--help"]);

    assert_exit(&output, 0);
    assert_eq!(text(&output.stdout), format!("{USAGE}\n"));
    assert!(output.stderr.is_empty());
}

#[test]
fn version_prints_package_version_to_stdout() {
    let output = run(&["--version"]);

    assert_exit(&output, 0);
    assert_eq!(
        text(&output.stdout),
        format!("ezcrypt {}\n", env!("CARGO_PKG_VERSION"))
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn zero_arguments_is_a_usage_error() {
    let output = run(&[]);

    assert_exit(&output, 2);
    assert!(output.stdout.is_empty());
    assert_eq!(
        text(&output.stderr),
        usage_error("exactly one file name is required")
    );
}

#[test]
fn separator_without_a_file_is_a_usage_error() {
    let output = run(&["--"]);

    assert_exit(&output, 2);
    assert!(output.stdout.is_empty());
    assert_eq!(
        text(&output.stderr),
        usage_error("exactly one file name is required")
    );
}

#[test]
fn unknown_option_is_a_usage_error() {
    let output = run(&["--unknown"]);

    assert_exit(&output, 2);
    assert!(output.stdout.is_empty());
    assert_eq!(
        text(&output.stderr),
        usage_error("unknown option; use -- before a file name that starts with '-'")
    );
}

#[test]
fn too_many_paths_is_a_usage_error() {
    let output = run(&["one.txt", "two.txt"]);

    assert_exit(&output, 2);
    assert!(output.stdout.is_empty());
    assert_eq!(
        text(&output.stderr),
        usage_error("exactly one file name is required")
    );
}

#[test]
fn invalid_lexical_path_fails_before_password_input() {
    let output = run(&["bad?.txt"]);

    assert_exit(&output, 1);
    assert!(output.stdout.is_empty());
    assert_eq!(
        text(&output.stderr),
        "error: invalid input path: path contains a character reserved by Windows\n"
    );
}
