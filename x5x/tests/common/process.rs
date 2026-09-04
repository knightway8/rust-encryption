#![allow(dead_code)]

use std::path::Path;
use std::process::{Command, Output};

pub fn run(binary: &str, arguments: &[&str]) -> Output {
    let directory = tempfile::tempdir().expect("create process test directory");
    run_in(binary, directory.path(), arguments)
}

pub fn run_in(binary: &str, directory: &Path, arguments: &[&str]) -> Output {
    Command::new(binary)
        .current_dir(directory)
        .args(arguments)
        .output()
        .expect("run tested binary")
}

pub fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

pub fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

pub fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "process failed with {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        stdout(output),
        stderr(output)
    );
}

pub fn assert_failure_contains(output: &Output, expected: &str) {
    assert!(
        !output.status.success(),
        "process unexpectedly succeeded\nstdout:\n{}",
        stdout(output)
    );
    let actual = stderr(output);
    assert!(
        actual.contains(expected),
        "stderr did not contain {expected:?}\nactual stderr:\n{actual}"
    );
}
