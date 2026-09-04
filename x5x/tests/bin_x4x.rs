use std::fs;

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::tempdir;

fn x4x() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("x4x"))
}

#[test]
fn help_describes_commands_and_password_file() {
    x4x()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("encrypt"))
        .stdout(predicate::str::contains("decrypt"))
        .stdout(predicate::str::contains("--password-file"));
}

#[test]
fn missing_subcommand_is_a_usage_error() {
    x4x()
        .assert()
        .failure()
        .stderr(predicate::str::contains("Usage:"));
}

#[test]
fn cli_round_trip_with_default_paths() {
    let directory = tempdir().unwrap();
    let input = directory.path().join("report.bin");
    let encrypted = directory.path().join("report.bin.x4x");
    let password = directory.path().join("password.txt");
    let original: Vec<u8> = (0..20_000)
        .map(|index| u8::try_from((index * 29 + 7) & 0xff).expect("masked pattern byte fits in u8"))
        .collect();
    fs::write(&input, &original).unwrap();
    fs::write(&password, b"automation passphrase\r\n").unwrap();

    x4x()
        .args(["encrypt", input.to_str().unwrap(), "--password-file"])
        .arg(&password)
        .assert()
        .success()
        .stdout(predicate::str::contains("Encrypted"));
    assert!(encrypted.exists());
    assert_eq!(fs::read(&input).unwrap(), original);

    // The no-clobber policy intentionally prevents replacing the original.
    fs::remove_file(&input).unwrap();
    x4x()
        .args(["decrypt", encrypted.to_str().unwrap(), "--password-file"])
        .arg(&password)
        .assert()
        .success()
        .stdout(predicate::str::contains("Decrypted"));
    assert_eq!(fs::read(input).unwrap(), original);
}

#[test]
fn cli_wrong_password_reports_one_safe_error_and_leaves_no_output() {
    let directory = tempdir().unwrap();
    let input = directory.path().join("input");
    let encrypted = directory.path().join("encrypted");
    let output = directory.path().join("output");
    let password = directory.path().join("password");
    let wrong = directory.path().join("wrong");
    fs::write(&input, b"secret").unwrap();
    fs::write(&password, b"right password").unwrap();
    fs::write(&wrong, b"wrong password").unwrap();

    x4x()
        .args(["encrypt", input.to_str().unwrap(), "-o"])
        .arg(&encrypted)
        .arg("--password-file")
        .arg(&password)
        .assert()
        .success();
    x4x()
        .args(["decrypt", encrypted.to_str().unwrap(), "-o"])
        .arg(&output)
        .arg("--password-file")
        .arg(&wrong)
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "password is wrong or the encrypted file was modified",
        ));
    assert!(!output.exists());
}

#[test]
fn cli_refuses_to_overwrite_before_doing_crypto() {
    let directory = tempdir().unwrap();
    let input = directory.path().join("input");
    let output = directory.path().join("output");
    let password = directory.path().join("password");
    fs::write(&input, b"new").unwrap();
    fs::write(&output, b"keep").unwrap();
    fs::write(&password, b"password").unwrap();

    x4x()
        .args(["encrypt", input.to_str().unwrap(), "-o"])
        .arg(&output)
        .arg("--password-file")
        .arg(&password)
        .assert()
        .failure()
        .stderr(predicate::str::contains("refusing to overwrite"));
    assert_eq!(fs::read(output).unwrap(), b"keep");
}

#[test]
fn cli_rejects_an_empty_password_file() {
    let directory = tempdir().unwrap();
    let input = directory.path().join("input");
    let password = directory.path().join("password");
    fs::write(&input, b"data").unwrap();
    fs::write(&password, b"\n").unwrap();

    x4x()
        .args(["encrypt", input.to_str().unwrap(), "--password-file"])
        .arg(&password)
        .assert()
        .failure()
        .stderr(predicate::str::contains("password must not be empty"));
    assert!(!directory.path().join("input.x4x").exists());
}

#[test]
fn version_flag_reports_the_package_version() {
    x4x()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("x4x 0.1.0"));
}

#[test]
fn test_is_not_misrepresented_as_an_application_subcommand() {
    x4x()
        .args(["test", "--all-targets"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unrecognized subcommand 'test'"));
}

#[test]
fn missing_password_file_is_reported_without_creating_output() {
    let directory = tempdir().unwrap();
    let input = directory.path().join("input");
    let missing_password = directory.path().join("missing-password");
    fs::write(&input, b"data").unwrap();

    x4x()
        .args(["encrypt", input.to_str().unwrap(), "--password-file"])
        .arg(&missing_password)
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot open password file"));
    assert!(!directory.path().join("input.x4x").exists());
}

#[test]
fn malformed_ciphertext_is_rejected_without_output() {
    let directory = tempdir().unwrap();
    let encrypted = directory.path().join("broken.x4x");
    let output = directory.path().join("restored");
    let password = directory.path().join("password");
    fs::write(&encrypted, b"not an x4x file").unwrap();
    fs::write(&password, b"password").unwrap();

    x4x()
        .args(["decrypt", encrypted.to_str().unwrap(), "-o"])
        .arg(&output)
        .arg("--password-file")
        .arg(&password)
        .assert()
        .failure()
        .stderr(predicate::str::contains("truncated header"));
    assert!(!output.exists());
}

#[test]
fn default_decrypt_path_never_replaces_the_original() {
    let directory = tempdir().unwrap();
    let original = directory.path().join("document");
    let encrypted = directory.path().join("document.x4x");
    let password = directory.path().join("password");
    fs::write(&original, b"valuable original").unwrap();
    fs::write(&encrypted, b"contents are irrelevant because output exists").unwrap();
    fs::write(&password, b"password").unwrap();

    x4x()
        .args(["decrypt", encrypted.to_str().unwrap(), "--password-file"])
        .arg(&password)
        .assert()
        .failure()
        .stderr(predicate::str::contains("refusing to overwrite"));
    assert_eq!(fs::read(original).unwrap(), b"valuable original");
}

#[test]
fn both_subcommands_have_complete_help() {
    for subcommand in ["encrypt", "decrypt"] {
        x4x()
            .args([subcommand, "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("--output"))
            .stdout(predicate::str::contains("--password-file"))
            .stdout(predicate::str::contains("<INPUT>"));
    }
}

#[test]
fn both_subcommands_require_an_input_path() {
    for subcommand in ["encrypt", "decrypt"] {
        x4x()
            .arg(subcommand)
            .assert()
            .failure()
            .stderr(predicate::str::contains("<INPUT>"));
    }
}

#[test]
fn plaintext_password_command_line_option_is_intentionally_unsupported() {
    x4x()
        .args(["encrypt", "input", "--password", "leaked-secret"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unexpected argument '--password'"))
        .stderr(predicate::str::contains("leaked-secret").not());
}

#[test]
fn missing_input_file_reports_context_and_creates_nothing() {
    let directory = tempdir().unwrap();
    let input = directory.path().join("missing-input");
    let password = directory.path().join("password");
    fs::write(&password, b"password").unwrap();

    x4x()
        .args(["encrypt", input.to_str().unwrap(), "--password-file"])
        .arg(&password)
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot open input"));
    assert!(!directory.path().join("missing-input.x4x").exists());
}

#[test]
fn missing_output_directory_reports_context() {
    let directory = tempdir().unwrap();
    let input = directory.path().join("input");
    let output = directory.path().join("missing-directory").join("output");
    let password = directory.path().join("password");
    fs::write(&input, b"data").unwrap();
    fs::write(&password, b"password").unwrap();

    x4x()
        .args(["encrypt", input.to_str().unwrap(), "--output"])
        .arg(&output)
        .arg("--password-file")
        .arg(&password)
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot resolve output directory"));
    assert!(!output.exists());
}

#[test]
fn repeated_default_encryption_preserves_the_first_ciphertext() {
    let directory = tempdir().unwrap();
    let input = directory.path().join("input");
    let encrypted = directory.path().join("input.x4x");
    let password = directory.path().join("password");
    fs::write(&input, b"data").unwrap();
    fs::write(&password, b"password").unwrap();

    x4x()
        .args(["encrypt", input.to_str().unwrap(), "--password-file"])
        .arg(&password)
        .assert()
        .success();
    let first_ciphertext = fs::read(&encrypted).unwrap();

    x4x()
        .args(["encrypt", input.to_str().unwrap(), "--password-file"])
        .arg(&password)
        .assert()
        .failure()
        .stderr(predicate::str::contains("refusing to overwrite"));
    assert_eq!(fs::read(encrypted).unwrap(), first_ciphertext);
}

#[test]
fn double_dash_allows_a_filename_beginning_with_a_hyphen() {
    let directory = tempdir().unwrap();
    let input = directory.path().join("-secret.txt");
    let encrypted = directory.path().join("-secret.txt.x4x");
    let password = directory.path().join("password");
    fs::write(&input, b"hyphenated name").unwrap();
    fs::write(&password, b"password").unwrap();

    x4x()
        .current_dir(directory.path())
        .args(["encrypt", "--password-file"])
        .arg(&password)
        .args(["--", "-secret.txt"])
        .assert()
        .success();
    assert!(encrypted.exists());
    assert_eq!(fs::read(input).unwrap(), b"hyphenated name");
}

#[test]
fn runtime_failures_use_exit_code_one_and_no_success_output() {
    let directory = tempdir().unwrap();
    let password = directory.path().join("password");
    fs::write(&password, b"password").unwrap();
    x4x()
        .args(["encrypt", "missing", "--password-file"])
        .arg(&password)
        .assert()
        .code(1)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("error:"));
}

#[test]
fn command_line_usage_failures_use_exit_code_two() {
    x4x()
        .args(["encrypt", "--definitely-not-an-option"])
        .assert()
        .code(2)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("unexpected argument"));
}

#[test]
fn output_option_requires_a_value() {
    x4x()
        .args(["encrypt", "input", "--output"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("a value is required"));
}
