#[path = "common/process.rs"]
mod process;

use process::{assert_failure_contains, assert_success, run, run_in, stdout};
use std::fs;

const BINARY: &str = env!("CARGO_BIN_EXE_keygen");

#[test]
fn reports_usage_for_wrong_argument_counts() {
    for arguments in [Vec::<&str>::new(), vec!["1", "extra"]] {
        assert_failure_contains(&run(BINARY, &arguments), "usage: keygen [size in bytes]");
    }
}

#[test]
fn rejects_non_decimal_sizes() {
    for size in ["abc", "1.0", "++1", "-1", " 1", "1 ", "1KiB"] {
        assert_failure_contains(&run(BINARY, &[size]), "invalid byte count");
    }
}

#[test]
fn rejects_sizes_outside_the_documented_range() {
    for size in ["0", "20000000001", "18446744073709551615"] {
        assert_failure_contains(
            &run(BINARY, &[size]),
            "size must be an exact byte count from 1 through 20000000000",
        );
    }
}

#[test]
fn creates_exact_requested_sizes() {
    for size in [1_usize, 32, 4097, 1024 * 1024 + 17] {
        let directory = tempfile::tempdir().expect("create keygen test directory");
        let output = run_in(BINARY, directory.path(), &[&size.to_string()]);
        assert_success(&output);
        assert_eq!(
            fs::metadata(directory.path().join("keygen.key"))
                .expect("inspect generated key")
                .len(),
            size as u64
        );
    }
}

#[test]
fn reports_the_created_size() {
    let directory = tempfile::tempdir().expect("create keygen test directory");
    let output = run_in(BINARY, directory.path(), &["73"]);
    assert_success(&output);
    assert!(stdout(&output).contains("created keygen.key with exactly 73 random bytes"));
}

#[test]
fn generated_key_is_not_an_all_zero_buffer() {
    let directory = tempfile::tempdir().expect("create keygen test directory");
    assert_success(&run_in(BINARY, directory.path(), &["4096"]));
    let key = fs::read(directory.path().join("keygen.key")).expect("read generated key");
    assert!(key.iter().any(|byte| *byte != 0));
}

#[test]
fn separate_runs_use_fresh_randomness() {
    let first_directory = tempfile::tempdir().expect("create first keygen test directory");
    let second_directory = tempfile::tempdir().expect("create second keygen test directory");
    assert_success(&run_in(BINARY, first_directory.path(), &["64"]));
    assert_success(&run_in(BINARY, second_directory.path(), &["64"]));
    assert_ne!(
        fs::read(first_directory.path().join("keygen.key")).expect("read first key"),
        fs::read(second_directory.path().join("keygen.key")).expect("read second key")
    );
}

#[test]
fn refuses_to_overwrite_an_existing_key() {
    let directory = tempfile::tempdir().expect("create keygen test directory");
    fs::write(directory.path().join("keygen.key"), b"preserve me").expect("write existing key");
    let output = run_in(BINARY, directory.path(), &["32"]);
    assert_failure_contains(&output, "refusing to overwrite existing file");
    assert_eq!(
        fs::read(directory.path().join("keygen.key")).expect("read preserved key"),
        b"preserve me"
    );
}

#[test]
fn successful_run_leaves_only_the_requested_key_file() {
    let directory = tempfile::tempdir().expect("create keygen test directory");
    assert_success(&run_in(BINARY, directory.path(), &["257"]));
    let entries: Vec<_> = fs::read_dir(directory.path())
        .expect("list keygen directory")
        .map(|entry| entry.expect("read directory entry").file_name())
        .collect();
    assert_eq!(entries, ["keygen.key"]);
}
#[test]
fn invalid_sizes_leave_no_output_or_temporary_file() {
    let directory = tempfile::tempdir().expect("create invalid-size keygen test directory");
    for size in ["0", "not-a-size", "20000000001"] {
        let output = run_in(BINARY, directory.path(), &[size]);
        assert!(!output.status.success());
        assert!(!directory.path().join("keygen.key").exists());
        assert_eq!(
            fs::read_dir(directory.path())
                .expect("list invalid-size keygen directory")
                .count(),
            0
        );
    }
}

#[test]
fn refuses_to_replace_a_directory_at_the_output_name() {
    let directory = tempfile::tempdir().expect("create directory-output keygen test directory");
    fs::create_dir(directory.path().join("keygen.key")).expect("create output-name directory");

    let output = run_in(BINARY, directory.path(), &["32"]);
    assert_failure_contains(&output, "refusing to overwrite existing file");
    assert!(directory.path().join("keygen.key").is_dir());
    assert_eq!(
        fs::read_dir(directory.path())
            .expect("list directory-output keygen directory")
            .count(),
        1
    );
}

#[test]
fn accepts_a_leading_zero_decimal_size() {
    let directory = tempfile::tempdir().expect("create keygen test directory");
    assert_success(&run_in(BINARY, directory.path(), &["00032"]));
    assert_eq!(
        fs::metadata(directory.path().join("keygen.key"))
            .expect("inspect generated key")
            .len(),
        32
    );
}

#[test]
fn rejects_an_empty_size_argument() {
    assert_failure_contains(&run(BINARY, &[""]), "invalid byte count");
}

#[test]
fn accepts_an_explicit_plus_sign() {
    let directory = tempfile::tempdir().expect("create keygen test directory");
    assert_success(&run_in(BINARY, directory.path(), &["+1"]));
    assert_eq!(
        fs::metadata(directory.path().join("keygen.key"))
            .expect("inspect generated key")
            .len(),
        1
    );
}

#[test]
fn rejects_exponent_notation() {
    assert_failure_contains(&run(BINARY, &["1e3"]), "invalid byte count");
}

#[test]
fn rejects_values_larger_than_u64() {
    assert_failure_contains(
        &run(BINARY, &["18446744073709551616"]),
        "invalid byte count",
    );
}

#[test]
fn success_emits_no_stderr() {
    let directory = tempfile::tempdir().expect("create keygen test directory");
    let output = run_in(BINARY, directory.path(), &["16"]);
    assert_success(&output);
    assert!(process::stderr(&output).is_empty());
}

#[test]
fn validation_failure_emits_no_stdout() {
    let output = run(BINARY, &["not-a-size"]);
    assert!(!output.status.success());
    assert!(process::stdout(&output).is_empty());
}

#[test]
fn successful_generation_preserves_unrelated_files() {
    let directory = tempfile::tempdir().expect("create keygen test directory");
    fs::write(directory.path().join("unrelated"), b"preserve me").expect("write unrelated file");
    assert_success(&run_in(BINARY, directory.path(), &["32"]));
    assert_eq!(
        fs::read(directory.path().join("unrelated")).expect("read unrelated file"),
        b"preserve me"
    );
}

#[test]
fn refuses_a_hard_link_at_the_output_name() {
    let directory = tempfile::tempdir().expect("create keygen hard-link test directory");
    fs::write(directory.path().join("sentinel"), b"preserve me").expect("write sentinel");
    fs::hard_link(
        directory.path().join("sentinel"),
        directory.path().join("keygen.key"),
    )
    .expect("create hard-link output");
    let output = run_in(BINARY, directory.path(), &["32"]);
    assert_failure_contains(&output, "refusing to overwrite existing file");
    assert_eq!(
        fs::read(directory.path().join("sentinel")).expect("read sentinel"),
        b"preserve me"
    );
}

#[test]
fn one_byte_generation_has_no_temporary_artifacts() {
    let directory = tempfile::tempdir().expect("create keygen test directory");
    assert_success(&run_in(BINARY, directory.path(), &["1"]));
    assert_eq!(
        fs::read_dir(directory.path())
            .expect("list keygen directory")
            .count(),
        1
    );
}
