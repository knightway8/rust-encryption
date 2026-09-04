use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use multicrypt::Algorithm;

fn run(binary: &Path, arguments: &[&OsStr]) -> Output {
    Command::new(binary)
        .args(arguments)
        .output()
        .expect("failed to launch multicrypt")
}

fn copied_binary(directory: &Path) -> PathBuf {
    let source = PathBuf::from(env!("CARGO_BIN_EXE_multicrypt"));
    let destination = directory.join(source.file_name().unwrap());
    fs::copy(&source, &destination).unwrap();
    destination
}

#[test]
fn every_help_spelling_is_successful_and_side_effect_free() {
    for help in ["-h", "--help", "help"] {
        let directory = tempfile::tempdir().unwrap();
        let binary = copied_binary(directory.path());
        let result = run(&binary, &[OsStr::new(help)]);

        assert!(result.status.success(), "help={help}");
        assert!(result.stderr.is_empty(), "help={help}");
        assert!(
            String::from_utf8_lossy(&result.stdout).contains("Usage:"),
            "help={help}"
        );
        for algorithm in Algorithm::ALL {
            assert!(
                !directory.path().join(algorithm.key_filename()).exists(),
                "help={help}, algorithm={algorithm}"
            );
        }
    }
}

#[test]
fn command_line_keygen_and_every_algorithm_round_trip() {
    let directory = tempfile::tempdir().unwrap();
    let binary = copied_binary(directory.path());

    let generated = run(&binary, &[OsStr::new("keygen")]);
    assert!(
        generated.status.success(),
        "{}",
        String::from_utf8_lossy(&generated.stderr)
    );
    for algorithm in Algorithm::ALL {
        assert!(
            directory.path().join(algorithm.key_filename()).is_file(),
            "missing key for {algorithm}"
        );
    }

    let second_keygen = run(&binary, &[OsStr::new("keygen")]);
    assert!(second_keygen.status.success());
    assert!(String::from_utf8_lossy(&second_keygen.stdout).contains("nothing changed"));

    let input = directory.path().join("input with spaces - snowman.bin");
    let plaintext: Vec<u8> = (0..8193)
        .map(|index| (index as u8).wrapping_mul(73).wrapping_add(19))
        .collect();
    fs::write(&input, &plaintext).unwrap();

    for algorithm in Algorithm::ALL {
        let encrypted = directory.path().join(format!("{}.mcrypt", algorithm.id()));
        let decrypted = directory
            .path()
            .join(format!("{}.decrypted", algorithm.id()));

        let encrypted_result = run(
            &binary,
            &[
                OsStr::new(algorithm.name()),
                OsStr::new("E"),
                input.as_os_str(),
                encrypted.as_os_str(),
            ],
        );
        assert!(
            encrypted_result.status.success(),
            "{algorithm}: {}",
            String::from_utf8_lossy(&encrypted_result.stderr)
        );
        assert_ne!(fs::read(&encrypted).unwrap(), plaintext);

        let decrypted_result = run(
            &binary,
            &[
                OsStr::new(algorithm.name()),
                OsStr::new("D"),
                encrypted.as_os_str(),
                decrypted.as_os_str(),
            ],
        );
        assert!(
            decrypted_result.status.success(),
            "{algorithm}: {}",
            String::from_utf8_lossy(&decrypted_result.stderr)
        );
        assert_eq!(fs::read(decrypted).unwrap(), plaintext);
    }
}

#[test]
fn command_line_rejects_bad_operations_arguments_and_existing_outputs() {
    let directory = tempfile::tempdir().unwrap();
    let binary = copied_binary(directory.path());
    assert!(run(&binary, &[OsStr::new("keygen")]).status.success());

    let input = directory.path().join("input.bin");
    let output = directory.path().join("output.bin");
    fs::write(&input, b"data").unwrap();
    fs::write(&output, b"preserve").unwrap();

    let lowercase = run(
        &binary,
        &[
            OsStr::new("AES-256-GCM-SIV"),
            OsStr::new("e"),
            input.as_os_str(),
            directory.path().join("unused.bin").as_os_str(),
        ],
    );
    assert!(!lowercase.status.success());
    assert!(String::from_utf8_lossy(&lowercase.stderr).contains("uppercase E or D"));

    let existing = run(
        &binary,
        &[
            OsStr::new("AES-256-GCM-SIV"),
            OsStr::new("E"),
            input.as_os_str(),
            output.as_os_str(),
        ],
    );
    assert!(!existing.status.success());
    assert_eq!(fs::read(output).unwrap(), b"preserve");

    let missing = run(&binary, &[]);
    assert_eq!(missing.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&missing.stderr).contains("Usage:"));
}

#[test]
fn command_line_auth_failure_leaves_no_plaintext_file() {
    let directory = tempfile::tempdir().unwrap();
    let binary = copied_binary(directory.path());
    assert!(run(&binary, &[OsStr::new("keygen")]).status.success());

    let input = directory.path().join("input.bin");
    let encrypted = directory.path().join("encrypted.bin");
    let decrypted = directory.path().join("must-not-exist.bin");
    fs::write(&input, b"highly sensitive plaintext").unwrap();
    assert!(
        run(
            &binary,
            &[
                OsStr::new("RABBIT-HMAC-SHA-512"),
                OsStr::new("E"),
                input.as_os_str(),
                encrypted.as_os_str(),
            ],
        )
        .status
        .success()
    );

    let mut bytes = fs::read(&encrypted).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    fs::write(&encrypted, bytes).unwrap();
    let result = run(
        &binary,
        &[
            OsStr::new("RABBIT-HMAC-SHA-512"),
            OsStr::new("D"),
            encrypted.as_os_str(),
            decrypted.as_os_str(),
        ],
    );
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("authentication failed"));
    assert!(!decrypted.exists());
}
