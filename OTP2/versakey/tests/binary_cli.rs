use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

const SENTINEL_KEY: &[u8] = b"preexisting key material must survive CLI validation errors";
const EXPECTED_PROMPT_AFTER_SUITE: &str =
    "VersaKey deterministic key maker (1 to 20000000000 bytes)\nKey size in bytes: ";
const OVERSIZED_SIZE_INPUT: [u8; 129] = [b' '; 129];

struct FailureCase {
    name: &'static str,
    stdin: &'static [u8],
    expected_stderr: &'static str,
}

const FAILURE_CASES: &[FailureCase] = &[
    FailureCase {
        name: "zero size",
        stdin: b"0\n",
        expected_stderr: "Error: key size must be between 1 and 20000000000 bytes\n",
    },
    FailureCase {
        name: "non-decimal size",
        stdin: b"1KB\n",
        expected_stderr: "Error: key size must contain decimal digits only (bytes, with no unit suffix)\n",
    },
    FailureCase {
        name: "end of input",
        stdin: b"",
        expected_stderr: "Error: console input/output failed: no key size was provided\n",
    },
    FailureCase {
        name: "oversized input",
        stdin: &OVERSIZED_SIZE_INPUT,
        expected_stderr: "Error: key size input is too long\n",
    },
];

fn run_with_stdin(binary: &Path, current_dir: &Path, stdin: &[u8]) -> Output {
    let mut child = Command::new(binary)
        .current_dir(current_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("failed to launch {}: {error}", binary.display()));

    child
        .stdin
        .take()
        .expect("piped child stdin")
        .write_all(stdin)
        .expect("write child stdin");

    child.wait_with_output().expect("wait for child process")
}

fn assert_cli_validation_failures(binary_name: &str, suite_name: &str, binary: &Path) {
    for case in FAILURE_CASES {
        let directory = tempfile::tempdir().expect("temporary working directory");
        let key_path = directory.path().join("key.key");
        std::fs::write(&key_path, SENTINEL_KEY).expect("write sentinel key file");

        let output = run_with_stdin(binary, directory.path(), case.stdin);
        let stdout = String::from_utf8(output.stdout).expect("CLI stdout is UTF-8");
        let stderr = String::from_utf8(output.stderr).expect("CLI stderr is UTF-8");

        assert!(
            !output.status.success(),
            "{binary_name} unexpectedly succeeded for {}",
            case.name
        );
        let expected_stdout =
            format!("VersaKey suite: {suite_name}\n{EXPECTED_PROMPT_AFTER_SUITE}");
        assert_eq!(
            stdout, expected_stdout,
            "unexpected {binary_name} stdout for {}",
            case.name
        );
        assert_eq!(
            stderr, case.expected_stderr,
            "unexpected {binary_name} stderr for {}",
            case.name
        );

        for forbidden in [
            "Password:",
            "Confirm password:",
            "Generating key.key",
            "Created key.key",
        ] {
            assert!(
                !stdout.contains(forbidden) && !stderr.contains(forbidden),
                "{binary_name} printed {forbidden:?} for {}",
                case.name
            );
        }

        assert_eq!(
            std::fs::read(&key_path).expect("read sentinel key file"),
            SENTINEL_KEY,
            "{binary_name} modified key.key for {}",
            case.name
        );
    }
}

#[test]
fn versakey_rejects_bad_size_input_without_touching_existing_key() {
    assert_cli_validation_failures(
        "versakey",
        "Argon2id + AES-256-CTR",
        Path::new(env!("CARGO_BIN_EXE_versakey")),
    );
}

#[test]
fn scrypt_rejects_bad_size_input_without_touching_existing_key() {
    assert_cli_validation_failures(
        "versakey-scrypt",
        "scrypt + AES-256-CTR",
        Path::new(env!("CARGO_BIN_EXE_versakey-scrypt")),
    );
}

#[test]
fn pbkdf2_rejects_bad_size_input_without_touching_existing_key() {
    assert_cli_validation_failures(
        "versakey-pbkdf2",
        "PBKDF2-HMAC-SHA-256 + AES-256-CTR",
        Path::new(env!("CARGO_BIN_EXE_versakey-pbkdf2")),
    );
}

#[test]
fn chacha20_rejects_bad_size_input_without_touching_existing_key() {
    assert_cli_validation_failures(
        "versakey-chacha20",
        "Argon2id + ChaCha20",
        Path::new(env!("CARGO_BIN_EXE_versakey-chacha20")),
    );
}

#[test]
fn blake3_rejects_bad_size_input_without_touching_existing_key() {
    assert_cli_validation_failures(
        "versakey-blake3",
        "Argon2id + keyed BLAKE3 XOF",
        Path::new(env!("CARGO_BIN_EXE_versakey-blake3")),
    );
}
