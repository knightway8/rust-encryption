use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

fn staged_binary() -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let source = PathBuf::from(env!("CARGO_BIN_EXE_be"));
    let name = if cfg!(windows) { "be.exe" } else { "be" };
    let destination = directory.path().join(name);
    fs::copy(source, &destination).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o755)).unwrap();
    }
    (directory, destination)
}

fn run(binary: &PathBuf, arguments: &[&str]) -> Output {
    Command::new(binary).args(arguments).output().unwrap()
}

#[test]
fn help_is_available() {
    let (_directory, binary) = staged_binary();
    let output = run(&binary, &["--help"]);
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("keygen"));
    assert!(stdout.contains("verify"));
}

#[test]
fn cli_keygen_creates_both_keys() {
    let (directory, binary) = staged_binary();
    let output = run(&binary, &["keygen"]);
    assert!(output.status.success());
    assert!(directory.path().join("key.key").is_file());
    assert!(directory.path().join("key.pub").is_file());
}

#[test]
fn cli_keygen_refuses_a_second_run() {
    let (_directory, binary) = staged_binary();
    assert!(run(&binary, &["keygen"]).status.success());
    let second = run(&binary, &["keygen"]);
    assert!(!second.status.success());
    assert!(
        String::from_utf8(second.stderr)
            .unwrap()
            .contains("refusing to overwrite")
    );
}

#[test]
fn cli_encrypt_verify_decrypt_round_trip() {
    let (directory, binary) = staged_binary();
    assert!(run(&binary, &["keygen"]).status.success());
    let plaintext = b"command-line round trip\0with binary data\xff";
    fs::write(directory.path().join("plain.bin"), plaintext).unwrap();
    assert!(
        run(&binary, &["E", "plain.bin", "cipher.age"])
            .status
            .success()
    );
    let verified = run(&binary, &["verify", "cipher.age"]);
    assert!(verified.status.success());
    assert!(
        String::from_utf8(verified.stdout)
            .unwrap()
            .contains("verified")
    );
    assert!(
        run(&binary, &["D", "cipher.age", "recovered.bin"])
            .status
            .success()
    );
    assert_eq!(
        fs::read(directory.path().join("recovered.bin")).unwrap(),
        plaintext
    );
}

#[test]
fn cli_lowercase_aliases_work() {
    let (directory, binary) = staged_binary();
    assert!(run(&binary, &["keygen"]).status.success());
    fs::write(directory.path().join("plain.bin"), b"aliases").unwrap();
    assert!(
        run(&binary, &["encrypt", "plain.bin", "cipher.age"])
            .status
            .success()
    );
    assert!(
        run(&binary, &["decrypt", "cipher.age", "recovered.bin"])
            .status
            .success()
    );
    assert_eq!(
        fs::read(directory.path().join("recovered.bin")).unwrap(),
        b"aliases"
    );
}

#[test]
fn cli_pubkey_matches_key_pub() {
    let (directory, binary) = staged_binary();
    assert!(run(&binary, &["keygen"]).status.success());
    let output = run(&binary, &["pubkey"]);
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        fs::read_to_string(directory.path().join("key.pub"))
            .unwrap()
            .trim()
    );
}

#[test]
fn cli_rejects_missing_arguments() {
    let (_directory, binary) = staged_binary();
    let output = run(&binary, &["E"]);
    assert!(!output.status.success());
}

#[test]
fn cli_rejects_path_traversal() {
    let (directory, binary) = staged_binary();
    assert!(run(&binary, &["keygen"]).status.success());
    fs::write(directory.path().join("plain.bin"), b"data").unwrap();
    let output = run(&binary, &["E", "../plain.bin", "cipher.age"]);
    assert!(!output.status.success());
    assert!(!directory.path().join("cipher.age").exists());
}

#[test]
fn cli_never_overwrites_an_output() {
    let (directory, binary) = staged_binary();
    assert!(run(&binary, &["keygen"]).status.success());
    fs::write(directory.path().join("plain.bin"), b"new").unwrap();
    fs::write(directory.path().join("cipher.age"), b"old").unwrap();
    let output = run(&binary, &["E", "plain.bin", "cipher.age"]);
    assert!(!output.status.success());
    assert_eq!(
        fs::read(directory.path().join("cipher.age")).unwrap(),
        b"old"
    );
}
