#[path = "common/process.rs"]
mod process;

use process::{assert_failure_contains, run, run_in};
use std::fs;

const BINARY: &str = env!("CARGO_BIN_EXE_keymake");

#[test]
fn reports_usage_without_arguments() {
    assert_failure_contains(&run(BINARY, &[]), "usage: keymake [size in bytes]");
}

#[test]
fn reports_usage_with_extra_arguments() {
    assert_failure_contains(
        &run(BINARY, &["32", "extra"]),
        "usage: keymake [size in bytes]",
    );
}

#[test]
fn rejects_non_decimal_sizes_before_prompting() {
    for size in ["abc", "1.0", "++1", "-1", " 32", "32 ", "32bytes"] {
        assert_failure_contains(&run(BINARY, &[size]), "invalid byte count");
    }
}

#[test]
fn rejects_zero_before_prompting() {
    assert_failure_contains(
        &run(BINARY, &["0"]),
        "size must be an exact byte count from 1 through 20000000000",
    );
}

#[test]
fn rejects_too_large_sizes_before_prompting() {
    for size in ["20000000001", "18446744073709551615"] {
        assert_failure_contains(
            &run(BINARY, &[size]),
            "size must be an exact byte count from 1 through 20000000000",
        );
    }
}

#[test]
fn refuses_an_existing_output_before_prompting() {
    let directory = tempfile::tempdir().expect("create keymake test directory");
    fs::write(directory.path().join("keymake.key"), b"preserve me").expect("write existing key");
    let output = run_in(BINARY, directory.path(), &["32"]);
    assert_failure_contains(&output, "refusing to overwrite existing file");
    assert_eq!(
        fs::read(directory.path().join("keymake.key")).expect("read preserved key"),
        b"preserve me"
    );
}

#[test]
fn invalid_size_never_creates_an_output() {
    let directory = tempfile::tempdir().expect("create keymake test directory");
    let output = run_in(BINARY, directory.path(), &["not-a-size"]);
    assert_failure_contains(&output, "invalid byte count");
    assert!(!directory.path().join("keymake.key").exists());
}

#[test]
fn rejects_an_empty_size_argument_before_prompting() {
    assert_failure_contains(&run(BINARY, &[""]), "invalid byte count");
}

#[test]
fn accepts_an_explicit_plus_sign_before_existing_output_check() {
    let directory = tempfile::tempdir().expect("create keymake test directory");
    fs::write(directory.path().join("keymake.key"), b"preserve me").expect("write output");
    let output = run_in(BINARY, directory.path(), &["+1"]);
    assert_failure_contains(&output, "refusing to overwrite existing file");
    assert_eq!(
        fs::read(directory.path().join("keymake.key")).expect("read preserved output"),
        b"preserve me"
    );
}

#[test]
fn rejects_exponent_notation_before_prompting() {
    assert_failure_contains(&run(BINARY, &["1e3"]), "invalid byte count");
}

#[test]
fn rejects_hex_notation_before_prompting() {
    assert_failure_contains(&run(BINARY, &["0x20"]), "invalid byte count");
}

#[test]
fn rejects_values_larger_than_u64_before_prompting() {
    assert_failure_contains(
        &run(BINARY, &["18446744073709551616"]),
        "invalid byte count",
    );
}

#[test]
fn rejects_unicode_digits_before_prompting() {
    assert_failure_contains(&run(BINARY, &["１２"]), "invalid byte count");
}

#[test]
fn rejects_embedded_ascii_whitespace_before_prompting() {
    assert_failure_contains(&run(BINARY, &["3 2"]), "invalid byte count");
}

#[test]
fn invalid_size_preserves_unrelated_files() {
    let directory = tempfile::tempdir().expect("create keymake test directory");
    fs::write(directory.path().join("unrelated"), b"preserve me").expect("write unrelated file");
    assert_failure_contains(
        &run_in(BINARY, directory.path(), &["invalid"]),
        "invalid byte count",
    );
    assert_eq!(
        fs::read(directory.path().join("unrelated")).expect("read unrelated file"),
        b"preserve me"
    );
}

#[test]
fn invalid_size_leaves_no_temporary_artifacts() {
    let directory = tempfile::tempdir().expect("create keymake test directory");
    assert_failure_contains(
        &run_in(BINARY, directory.path(), &["invalid"]),
        "invalid byte count",
    );
    assert_eq!(
        fs::read_dir(directory.path())
            .expect("list keymake directory")
            .count(),
        0
    );
}

#[test]
fn validation_failure_emits_no_stdout() {
    let output = run(BINARY, &["invalid"]);
    assert!(!output.status.success());
    assert!(process::stdout(&output).is_empty());
}

#[test]
fn refuses_an_existing_empty_output_before_prompting() {
    let directory = tempfile::tempdir().expect("create keymake test directory");
    fs::write(directory.path().join("keymake.key"), []).expect("write empty output");
    let output = run_in(BINARY, directory.path(), &["1"]);
    assert_failure_contains(&output, "refusing to overwrite existing file");
    assert_eq!(
        fs::metadata(directory.path().join("keymake.key"))
            .expect("inspect preserved output")
            .len(),
        0
    );
}

#[test]
fn refuses_an_output_directory_before_prompting() {
    let directory = tempfile::tempdir().expect("create keymake test directory");
    fs::create_dir(directory.path().join("keymake.key")).expect("create output directory");
    let output = run_in(BINARY, directory.path(), &["1"]);
    assert_failure_contains(&output, "refusing to overwrite existing file");
    assert!(directory.path().join("keymake.key").is_dir());
}

#[test]
fn refuses_a_hard_link_output_before_prompting() {
    let directory = tempfile::tempdir().expect("create keymake hard-link test directory");
    fs::write(directory.path().join("sentinel"), b"preserve me").expect("write sentinel");
    fs::hard_link(
        directory.path().join("sentinel"),
        directory.path().join("keymake.key"),
    )
    .expect("create hard-link output");
    let output = run_in(BINARY, directory.path(), &["1"]);
    assert_failure_contains(&output, "refusing to overwrite existing file");
    assert_eq!(
        fs::read(directory.path().join("sentinel")).expect("read sentinel"),
        b"preserve me"
    );
}

#[test]
fn maximum_size_checks_existing_output_before_prompting() {
    let directory = tempfile::tempdir().expect("create keymake test directory");
    fs::write(directory.path().join("keymake.key"), b"preserve me").expect("write output");
    let output = run_in(BINARY, directory.path(), &["20000000000"]);
    assert_failure_contains(&output, "refusing to overwrite existing file");
    assert_eq!(
        fs::read(directory.path().join("keymake.key")).expect("read preserved output"),
        b"preserve me"
    );
}
