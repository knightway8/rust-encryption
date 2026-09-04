use std::fs;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

fn otp_command(test_directory: &TempDir) -> Command {
    let mut command = Command::cargo_bin("otp").expect("binary should build");
    command
        .env("OTP_STATE_DIR", test_directory.path().join("state"))
        .env("NO_COLOR", "1");
    command
}

fn create_pair(test_directory: &TempDir, plaintext: &Path, sender: &Path, receiver: &Path) {
    otp_command(test_directory)
        .arg("pad")
        .arg("create")
        .arg("--for-file")
        .arg(plaintext)
        .arg("--sender")
        .arg(sender)
        .arg("--receiver")
        .arg(receiver)
        .assert()
        .success()
        .stdout(predicate::str::contains("one-message pad pair"));
}

fn encrypt(
    test_directory: &TempDir,
    plaintext: &Path,
    sender: &Path,
    encrypted: &Path,
) -> assert_cmd::assert::Assert {
    otp_command(test_directory)
        .arg("encrypt")
        .arg("--input")
        .arg(plaintext)
        .arg("--pad")
        .arg(sender)
        .arg("--output")
        .arg(encrypted)
        .assert()
}

fn decrypt(
    test_directory: &TempDir,
    encrypted: &Path,
    receiver: &Path,
    plaintext: &Path,
) -> assert_cmd::assert::Assert {
    otp_command(test_directory)
        .arg("decrypt")
        .arg("--input")
        .arg(encrypted)
        .arg("--pad")
        .arg(receiver)
        .arg("--output")
        .arg(plaintext)
        .assert()
}

fn paths(directory: &TempDir) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    (
        directory.path().join("plain.bin"),
        directory.path().join("sender.otppad"),
        directory.path().join("receiver.otppad"),
        directory.path().join("encrypted.otp"),
    )
}

#[test]
fn top_level_and_subcommand_help_are_available() {
    let directory = TempDir::new().unwrap();
    for arguments in [
        vec!["--help"],
        vec!["pad", "--help"],
        vec!["pad", "create", "--help"],
        vec!["pad", "info", "--help"],
        vec!["pad", "destroy", "--help"],
        vec!["encrypt", "--help"],
        vec!["decrypt", "--help"],
    ] {
        otp_command(&directory)
            .args(arguments)
            .assert()
            .success()
            .stdout(predicate::str::contains("Usage:"));
    }
}

#[test]
fn version_matches_the_package() {
    let directory = TempDir::new().unwrap();
    otp_command(&directory)
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::eq(format!(
            "otp {}\n",
            env!("CARGO_PKG_VERSION")
        )));
}

#[test]
fn cli_round_trip_preserves_arbitrary_binary_data() {
    let directory = TempDir::new().unwrap();
    let (plain, sender, receiver, encrypted) = paths(&directory);
    let recovered = directory.path().join("recovered.bin");
    let mut message: Vec<u8> = (0_u8..=255).collect();
    message.extend((0..150_000).map(|index| ((index * 197 + 31) % 256) as u8));
    fs::write(&plain, &message).unwrap();

    create_pair(&directory, &plain, &sender, &receiver);
    encrypt(&directory, &plain, &sender, &encrypted)
        .success()
        .stdout(predicate::str::contains("sender pad is now consumed"));
    decrypt(&directory, &encrypted, &receiver, &recovered)
        .success()
        .stdout(predicate::str::contains("receiver pad is now consumed"));

    assert_eq!(fs::read(recovered).unwrap(), message);
    assert!(sender.exists(), "consumed sender pad should be retained");
    assert!(
        receiver.exists(),
        "consumed receiver pad should be retained"
    );
}

#[test]
fn empty_file_round_trip_works() {
    let directory = TempDir::new().unwrap();
    let (plain, sender, receiver, encrypted) = paths(&directory);
    let recovered = directory.path().join("empty.out");
    fs::write(&plain, []).unwrap();

    create_pair(&directory, &plain, &sender, &receiver);
    encrypt(&directory, &plain, &sender, &encrypted).success();
    decrypt(&directory, &encrypted, &receiver, &recovered).success();

    assert_eq!(fs::read(recovered).unwrap(), Vec::<u8>::new());
}

#[test]
fn human_readable_length_creates_exact_capacity() {
    let directory = TempDir::new().unwrap();
    let sender = directory.path().join("send.pad");
    let receiver = directory.path().join("receive.pad");

    otp_command(&directory)
        .args(["pad", "create", "--length", "2KiB", "--sender"])
        .arg(&sender)
        .arg("--receiver")
        .arg(&receiver)
        .assert()
        .success();

    otp_command(&directory)
        .args(["pad", "info", "--pad"])
        .arg(&sender)
        .assert()
        .success()
        .stdout(predicate::str::contains("Role: sender"))
        .stdout(predicate::str::contains("State: fresh"))
        .stdout(predicate::str::contains("Capacity: 2048 bytes"));
}

#[test]
fn invalid_size_and_conflicting_capacity_sources_are_usage_errors() {
    let directory = TempDir::new().unwrap();
    let plain = directory.path().join("plain");
    fs::write(&plain, b"x").unwrap();

    otp_command(&directory)
        .args([
            "pad",
            "create",
            "--length",
            "-1",
            "--sender",
            "a",
            "--receiver",
            "b",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unexpected argument"));

    otp_command(&directory)
        .args(["pad", "create", "--length", "1", "--for-file"])
        .arg(&plain)
        .args(["--sender", "a", "--receiver", "b"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn existing_output_is_never_overwritten_and_does_not_consume_pad() {
    let directory = TempDir::new().unwrap();
    let (plain, sender, receiver, encrypted) = paths(&directory);
    fs::write(&plain, b"do not overwrite").unwrap();
    fs::write(&encrypted, b"sentinel").unwrap();
    create_pair(&directory, &plain, &sender, &receiver);

    encrypt(&directory, &plain, &sender, &encrypted)
        .failure()
        .stderr(predicate::str::contains("refusing to overwrite"));
    assert_eq!(fs::read(&encrypted).unwrap(), b"sentinel");

    fs::remove_file(&encrypted).unwrap();
    encrypt(&directory, &plain, &sender, &encrypted).success();
}

#[test]
fn exact_length_is_required_and_failure_does_not_commit_output() {
    let directory = TempDir::new().unwrap();
    let plain = directory.path().join("plain");
    let sender = directory.path().join("sender");
    let receiver = directory.path().join("receiver");
    let output = directory.path().join("output");
    fs::write(&plain, b"12345678").unwrap();

    otp_command(&directory)
        .args(["pad", "create", "--length", "7", "--sender"])
        .arg(&sender)
        .arg("--receiver")
        .arg(&receiver)
        .assert()
        .success();
    encrypt(&directory, &plain, &sender, &output)
        .failure()
        .stderr(predicate::str::contains("length mismatch"));
    assert!(!output.exists());
}

#[test]
fn sender_and_receiver_roles_cannot_be_swapped() {
    let directory = TempDir::new().unwrap();
    let (plain, sender, receiver, encrypted) = paths(&directory);
    fs::write(&plain, b"role separation").unwrap();
    create_pair(&directory, &plain, &sender, &receiver);

    encrypt(&directory, &plain, &receiver, &encrypted)
        .failure()
        .stderr(predicate::str::contains("requires a sender pad"));
    assert!(!encrypted.exists());

    encrypt(&directory, &plain, &sender, &encrypted).success();
    let wrong_output = directory.path().join("wrong.out");
    decrypt(&directory, &encrypted, &sender, &wrong_output)
        .failure()
        .stderr(predicate::str::contains("requires a receiver pad"));
    assert!(!wrong_output.exists());
}

#[test]
fn copied_sender_pad_is_blocked_by_the_usage_ledger() {
    let directory = TempDir::new().unwrap();
    let (plain, sender, receiver, encrypted) = paths(&directory);
    let copied_sender = directory.path().join("copied-sender.pad");
    let second_output = directory.path().join("second.otp");
    fs::write(&plain, b"ledger prevents restored copies").unwrap();
    create_pair(&directory, &plain, &sender, &receiver);
    fs::copy(&sender, &copied_sender).unwrap();

    encrypt(&directory, &plain, &sender, &encrypted).success();
    encrypt(&directory, &plain, &copied_sender, &second_output)
        .failure()
        .stderr(predicate::str::contains("already consumed or reserved"));
    assert!(!second_output.exists());
}

#[test]
fn tampering_releases_no_plaintext_and_does_not_burn_receiver_pad() {
    let directory = TempDir::new().unwrap();
    let (plain, sender, receiver, encrypted) = paths(&directory);
    let tampered = directory.path().join("tampered.otp");
    let rejected_output = directory.path().join("rejected.out");
    let recovered = directory.path().join("recovered.out");
    fs::write(&plain, b"authenticate before producing any plaintext").unwrap();
    create_pair(&directory, &plain, &sender, &receiver);
    encrypt(&directory, &plain, &sender, &encrypted).success();

    let mut bytes = fs::read(&encrypted).unwrap();
    bytes[otp::ENVELOPE_HEADER_LEN + 3] ^= 0x80;
    fs::write(&tampered, bytes).unwrap();
    decrypt(&directory, &tampered, &receiver, &rejected_output)
        .failure()
        .stderr(predicate::str::contains("authentication failed"));
    assert!(!rejected_output.exists());

    decrypt(&directory, &encrypted, &receiver, &recovered).success();
    assert_eq!(fs::read(recovered).unwrap(), fs::read(plain).unwrap());
}

#[test]
fn truncated_and_extended_envelopes_are_rejected_without_output() {
    let directory = TempDir::new().unwrap();
    let (plain, sender, receiver, encrypted) = paths(&directory);
    fs::write(&plain, b"strict framing").unwrap();
    create_pair(&directory, &plain, &sender, &receiver);
    encrypt(&directory, &plain, &sender, &encrypted).success();
    let valid = fs::read(&encrypted).unwrap();

    for (name, malformed) in [
        ("truncated.otp", valid[..valid.len() - 1].to_vec()),
        ("extended.otp", {
            let mut extended = valid.clone();
            extended.push(0);
            extended
        }),
    ] {
        let input = directory.path().join(name);
        let output = directory.path().join(format!("{name}.out"));
        fs::write(&input, malformed).unwrap();
        decrypt(&directory, &input, &receiver, &output)
            .failure()
            .stderr(predicate::str::contains("file size"));
        assert!(!output.exists());
    }
}

#[test]
fn wrong_receiver_pad_fails_without_plaintext() {
    let directory = TempDir::new().unwrap();
    let (plain, sender, receiver, encrypted) = paths(&directory);
    let other_sender = directory.path().join("other-sender");
    let other_receiver = directory.path().join("other-receiver");
    let output = directory.path().join("wrong-key.out");
    fs::write(&plain, b"wrong pad").unwrap();
    create_pair(&directory, &plain, &sender, &receiver);
    otp_command(&directory)
        .args(["pad", "create", "--for-file"])
        .arg(&plain)
        .arg("--sender")
        .arg(&other_sender)
        .arg("--receiver")
        .arg(&other_receiver)
        .assert()
        .success();
    encrypt(&directory, &plain, &sender, &encrypted).success();

    decrypt(&directory, &encrypted, &other_receiver, &output)
        .failure()
        .stderr(predicate::str::contains("different pad"));
    assert!(!output.exists());
}

#[test]
fn consumed_state_is_visible_in_pad_info() {
    let directory = TempDir::new().unwrap();
    let (plain, sender, receiver, encrypted) = paths(&directory);
    fs::write(&plain, b"state").unwrap();
    create_pair(&directory, &plain, &sender, &receiver);
    encrypt(&directory, &plain, &sender, &encrypted).success();

    otp_command(&directory)
        .args(["pad", "info", "--pad"])
        .arg(&sender)
        .assert()
        .success()
        .stdout(predicate::str::contains("State: consumed"));
}

#[test]
fn explicit_destroy_requires_confirmation_then_truncates_only_the_pad() {
    let directory = TempDir::new().unwrap();
    let plain = directory.path().join("keep.txt");
    let sender = directory.path().join("sender.pad");
    let receiver = directory.path().join("receiver.pad");
    fs::write(&plain, b"keep me").unwrap();
    create_pair(&directory, &plain, &sender, &receiver);

    otp_command(&directory)
        .args(["pad", "destroy", "--pad"])
        .arg(&sender)
        .assert()
        .failure()
        .stderr(predicate::str::contains("--yes"));
    assert!(sender.exists());

    otp_command(&directory)
        .args(["pad", "destroy", "--pad"])
        .arg(&sender)
        .arg("--yes")
        .assert()
        .success()
        .stdout(predicate::str::contains("Destroyed and truncated pad"));
    assert!(sender.exists());
    assert_eq!(fs::metadata(&sender).unwrap().len(), 0);
    assert!(receiver.exists());
    assert_eq!(fs::read(plain).unwrap(), b"keep me");
}

#[test]
fn unicode_and_space_filenames_work() {
    let directory = TempDir::new().unwrap();
    let plain = directory.path().join("message \u{2603}.bin");
    let sender = directory.path().join("sender copy \u{00e9}.pad");
    let receiver = directory.path().join("receiver copy \u{65e5}.pad");
    let encrypted = directory.path().join("cipher text.otp");
    let recovered = directory.path().join("recovered file.bin");
    fs::write(&plain, b"path handling").unwrap();

    create_pair(&directory, &plain, &sender, &receiver);
    encrypt(&directory, &plain, &sender, &encrypted).success();
    decrypt(&directory, &encrypted, &receiver, &recovered).success();
    assert_eq!(fs::read(recovered).unwrap(), b"path handling");
}

#[test]
fn bare_relative_paths_use_the_current_directory() {
    let directory = TempDir::new().unwrap();
    fs::write(directory.path().join("plain.bin"), b"relative paths").unwrap();

    otp_command(&directory)
        .current_dir(directory.path())
        .args([
            "pad",
            "create",
            "--for-file",
            "plain.bin",
            "--sender",
            "sender.pad",
            "--receiver",
            "receiver.pad",
        ])
        .assert()
        .success();
    otp_command(&directory)
        .current_dir(directory.path())
        .args([
            "encrypt",
            "--input",
            "plain.bin",
            "--pad",
            "sender.pad",
            "--output",
            "encrypted.otp",
        ])
        .assert()
        .success();
    otp_command(&directory)
        .current_dir(directory.path())
        .args([
            "decrypt",
            "--input",
            "encrypted.otp",
            "--pad",
            "receiver.pad",
            "--output",
            "recovered.bin",
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read(directory.path().join("recovered.bin")).unwrap(),
        b"relative paths"
    );
}

#[test]
fn unknown_commands_and_missing_arguments_fail_cleanly() {
    let directory = TempDir::new().unwrap();
    otp_command(&directory)
        .arg("unknown")
        .assert()
        .failure()
        .stderr(predicate::str::contains("unrecognized subcommand"));
    otp_command(&directory)
        .arg("encrypt")
        .assert()
        .failure()
        .stderr(predicate::str::contains("required arguments"));
}
