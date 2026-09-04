use std::{
    fs,
    io::{Read, Write},
    path::Path,
    process::{Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};
use tempfile::TempDir;

const BINARY: &str = env!("CARGO_BIN_EXE_x30");
const APP_ID: u8 = 30;
const PASSWORD: &str = "integration-test passphrase";

fn run_cli(mode: &str, input: &Path, output: &Path) -> Output {
    let mut child = Command::new(BINARY)
        .arg(mode)
        .arg(input)
        .arg(output)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{PASSWORD}\n").as_bytes())
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("CLI process exceeded the 30-second timeout");
        }
        thread::sleep(Duration::from_millis(25));
    }

    let status = child.wait().unwrap();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut stdout)
        .unwrap();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_end(&mut stderr)
        .unwrap();
    Output {
        status,
        stdout,
        stderr,
    }
}

#[test]
fn real_cli_uses_production_encryption_and_preserves_exact_data() {
    let directory = TempDir::new().unwrap();
    let input = directory.path().join("input file.bin");
    let encrypted = directory.path().join("encrypted file.x30");
    let restored = directory.path().join("restored file.bin");
    let data: Vec<u8> = (0..(128 * 1024 + 17))
        .map(|index| ((index * 31) & 0xff) as u8)
        .collect();
    fs::write(&input, &data).unwrap();

    let encrypted_result = run_cli("E", &input, &encrypted);
    assert!(
        encrypted_result.status.success(),
        "encryption failed: {}",
        String::from_utf8_lossy(&encrypted_result.stderr)
    );
    let encrypted_bytes = fs::read(&encrypted).unwrap();
    assert_eq!(&encrypted_bytes[..7], &[69, 84, 79, 79, 76, 0, 0]);
    assert_eq!(encrypted_bytes[7], APP_ID);
    let decrypted_result = run_cli("D", &encrypted, &restored);
    assert!(
        decrypted_result.status.success(),
        "decryption failed: {}",
        String::from_utf8_lossy(&decrypted_result.stderr)
    );

    assert_eq!(fs::read(&restored).unwrap(), data);
    assert_eq!(fs::read(&input).unwrap(), data);
    for captured in [
        encrypted_result.stdout,
        encrypted_result.stderr,
        decrypted_result.stdout,
        decrypted_result.stderr,
    ] {
        assert!(
            !captured
                .windows(PASSWORD.len())
                .any(|part| part == PASSWORD.as_bytes())
        );
        assert!(!captured.windows(16).any(|part| part == &data[..16]));
    }
}
