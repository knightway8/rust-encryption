use std::fs;

use assert_cmd::Command;
use predicates::prelude::*;

use algos::{ALL_SUITES, Suite};

fn command(suite: Suite) -> Command {
    Command::cargo_bin(suite.binary_name()).expect("binary target must exist")
}

fn write_fixture(directory: &tempfile::TempDir) -> (std::path::PathBuf, std::path::PathBuf) {
    let input = directory.path().join("input with spaces.bin");
    let password = directory.path().join("password.bin");
    let data: Vec<u8> = (0_u8..=255).cycle().take(70_123).collect();
    fs::write(&input, data).unwrap();
    fs::write(&password, b"correct horse battery staple\n").unwrap();
    (input, password)
}

fn round_trip_cli(suite: Suite) {
    let directory = tempfile::tempdir().unwrap();
    let (input, password) = write_fixture(&directory);
    let encrypted = directory.path().join("encrypted.af");
    let decrypted = directory.path().join("decrypted.bin");

    command(suite)
        .args(["encrypt", "--input"])
        .arg(&input)
        .args(["--output"])
        .arg(&encrypted)
        .args(["--password-file"])
        .arg(&password)
        .assert()
        .success()
        .stdout(predicate::str::is_empty());

    command(suite)
        .args(["decrypt", "--input"])
        .arg(&encrypted)
        .args(["--output"])
        .arg(&decrypted)
        .args(["--password-file"])
        .arg(&password)
        .assert()
        .success()
        .stdout(predicate::str::is_empty());

    assert_eq!(fs::read(decrypted).unwrap(), fs::read(input).unwrap());
}

#[test]
fn every_binary_has_suite_specific_help() {
    for suite in ALL_SUITES {
        command(suite)
            .arg("--help")
            .assert()
            .success()
            .stdout(predicate::str::contains(suite.name()))
            .stdout(predicate::str::contains("encrypt"))
            .stdout(predicate::str::contains("decrypt"));
    }
}

#[test]
fn native_aead_cli_round_trip() {
    round_trip_cli(Suite::XChaCha20Poly1305);
}

#[test]
fn encrypt_then_mac_cli_round_trip() {
    round_trip_cli(Suite::Serpent192CtrHmac);
}

#[test]
fn wrong_password_is_generic_and_leaves_no_output() {
    let suite = Suite::Aes256Gcm;
    let directory = tempfile::tempdir().unwrap();
    let (input, password) = write_fixture(&directory);
    let wrong_password = directory.path().join("wrong-password.bin");
    let encrypted = directory.path().join("encrypted.af");
    let output = directory.path().join("must-not-exist.bin");
    fs::write(&wrong_password, b"definitely wrong").unwrap();

    command(suite)
        .args(["encrypt", "-i"])
        .arg(&input)
        .args(["-o"])
        .arg(&encrypted)
        .args(["--password-file"])
        .arg(&password)
        .assert()
        .success();

    command(suite)
        .args(["decrypt", "-i"])
        .arg(&encrypted)
        .args(["-o"])
        .arg(&output)
        .args(["--password-file"])
        .arg(&wrong_password)
        .assert()
        .failure()
        .stderr(predicate::str::contains("wrong password or corrupted file"))
        .stderr(predicate::str::contains("definitely wrong").not());
    assert!(!output.exists());
}

#[test]
fn corrupted_late_record_leaves_no_plaintext_output() {
    let suite = Suite::Camellia256CtrHmac;
    let directory = tempfile::tempdir().unwrap();
    let (input, password) = write_fixture(&directory);
    let encrypted = directory.path().join("encrypted.af");
    let output = directory.path().join("must-not-exist.bin");

    command(suite)
        .args(["encrypt", "-i"])
        .arg(&input)
        .args(["-o"])
        .arg(&encrypted)
        .args(["--password-file"])
        .arg(&password)
        .assert()
        .success();

    let mut bytes = fs::read(&encrypted).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    fs::write(&encrypted, bytes).unwrap();

    command(suite)
        .args(["decrypt", "-i"])
        .arg(&encrypted)
        .args(["-o"])
        .arg(&output)
        .args(["--password-file"])
        .arg(&password)
        .assert()
        .failure()
        .stderr(predicate::str::contains("wrong password or corrupted file"));
    assert!(!output.exists());
}

#[test]
fn existing_output_is_never_changed() {
    let suite = Suite::ChaCha20Poly1305;
    let directory = tempfile::tempdir().unwrap();
    let (input, password) = write_fixture(&directory);
    let output = directory.path().join("existing.bin");
    fs::write(&output, b"sentinel").unwrap();

    command(suite)
        .args(["encrypt", "-i"])
        .arg(&input)
        .args(["-o"])
        .arg(&output)
        .args(["--password-file"])
        .arg(&password)
        .assert()
        .failure()
        .stderr(predicate::str::contains("refusing to overwrite"));
    assert_eq!(fs::read(output).unwrap(), b"sentinel");
}

#[test]
#[ignore = "production Argon2id round trip for every binary; run explicitly before releases"]
fn slow_every_binary_process_round_trip() {
    for suite in ALL_SUITES {
        round_trip_cli(suite);
    }
}
