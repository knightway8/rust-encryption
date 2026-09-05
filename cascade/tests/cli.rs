use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

#[cfg(unix)]
use std::process::{Child, Stdio};

use tempfile::TempDir;

#[cfg(unix)]
const KEY_FILES: [(&str, usize); 4] = [
    ("aes.key", 32),
    ("ser.key", 32),
    ("cha.key", 32),
    ("thr.key", 128),
];

struct InstalledBinary {
    _directory: TempDir,
    path: PathBuf,
}

impl InstalledBinary {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(if cfg!(windows) {
            "cascade.exe"
        } else {
            "cascade"
        });
        let source = Path::new(env!("CARGO_BIN_EXE_cascade"));
        fs::copy(source, &path).unwrap();
        // Windows requires write access for FlushFileBuffers (File::sync_all).
        fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .sync_all()
            .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self {
            _directory: directory,
            path,
        }
    }

    #[cfg(unix)]
    fn directory(&self) -> &Path {
        self.path.parent().unwrap()
    }

    fn run(&self, current_dir: &Path, arguments: &[&str]) -> Output {
        #[cfg(unix)]
        {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            loop {
                match Command::new(&self.path)
                    .args(arguments)
                    .current_dir(current_dir)
                    .output()
                {
                    Ok(output) => return output,
                    Err(error)
                        if error.raw_os_error() == Some(libc::ETXTBSY)
                            && std::time::Instant::now() < deadline =>
                    {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                    }
                    Err(error) => panic!("failed to run copied binary: {error}"),
                }
            }
        }
        #[cfg(not(unix))]
        {
            Command::new(&self.path)
                .args(arguments)
                .current_dir(current_dir)
                .output()
                .unwrap()
        }
    }

    #[cfg(unix)]
    fn keygen(&self, current_dir: &Path) {
        assert_success(self.run(current_dir, &["keygen"]));
    }

    #[cfg(unix)]
    fn spawn_quiet(&self, current_dir: &Path, arguments: &[&str]) -> Child {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            match Command::new(&self.path)
                .args(arguments)
                .current_dir(current_dir)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
            {
                Ok(child) => return child,
                Err(error)
                    if error.raw_os_error() == Some(libc::ETXTBSY)
                        && std::time::Instant::now() < deadline =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(error) => panic!("failed to spawn copied binary: {error}"),
            }
        }
    }
}

fn assert_success(output: Output) {
    assert!(
        output.status.success(),
        "status: {:?}\nstdout: {}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
fn patterned_bytes(length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| (index as u8).wrapping_mul(73).wrapping_add(19))
        .collect()
}

#[test]
#[cfg(unix)]
fn keygen_uses_executable_directory_and_never_overwrites() {
    let binary = InstalledBinary::new();
    let working = tempfile::tempdir().unwrap();
    binary.keygen(working.path());

    for (filename, length) in KEY_FILES {
        let path = binary.directory().join(filename);
        let bytes = fs::read(&path).unwrap();
        assert_eq!(bytes.len(), length, "{filename}");
        assert!(bytes.iter().any(|byte| *byte != 0), "{filename}");
        assert!(!working.path().join(filename).exists(), "{filename}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(fs::metadata(path).unwrap().mode() & 0o077, 0);
        }
    }

    let originals: Vec<_> = KEY_FILES
        .iter()
        .map(|(name, _)| fs::read(binary.directory().join(name)).unwrap())
        .collect();
    let second = binary.run(working.path(), &["keygen"]);
    assert_eq!(second.status.code(), Some(1));
    for ((name, _), original) in KEY_FILES.iter().zip(originals) {
        assert_eq!(fs::read(binary.directory().join(name)).unwrap(), original);
    }
}

#[test]
#[cfg(unix)]
fn preexisting_single_key_makes_keygen_all_or_nothing() {
    let binary = InstalledBinary::new();
    let working = tempfile::tempdir().unwrap();
    let existing = binary.directory().join("ser.key");
    fs::write(&existing, [0x55_u8; 32]).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&existing, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let output = binary.run(working.path(), &["keygen"]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(fs::read(existing).unwrap(), [0x55_u8; 32]);
    for filename in ["aes.key", "cha.key", "thr.key"] {
        assert!(!binary.directory().join(filename).exists());
    }
}

#[test]
#[cfg(unix)]
fn each_algorithm_round_trips_empty_binary_and_boundary_files() {
    let binary = InstalledBinary::new();
    let working = tempfile::tempdir().unwrap();
    binary.keygen(working.path());

    for (selector, length) in [("A", 0), ("A", 4097), ("S", 17), ("X", 4097), ("T", 129)] {
        let input_name = format!("{selector}-{length}.input");
        let encrypted_name = format!("{selector}-{length}.encrypted");
        let output_name = format!("{selector}-{length}.output");
        let input = patterned_bytes(length);
        fs::write(working.path().join(&input_name), &input).unwrap();

        assert_success(binary.run(
            working.path(),
            &[selector, "E", &input_name, &encrypted_name],
        ));
        assert_success(binary.run(
            working.path(),
            &[selector, "D", &encrypted_name, &output_name],
        ));
        assert_eq!(fs::read(working.path().join(output_name)).unwrap(), input);
    }
}

#[test]
#[cfg(unix)]
fn four_layer_manual_cascade_round_trips_in_reverse_order() {
    let binary = InstalledBinary::new();
    let working = tempfile::tempdir().unwrap();
    binary.keygen(working.path());
    let original = patterned_bytes(8193);
    fs::write(working.path().join("plain"), &original).unwrap();

    for arguments in [
        ["A", "E", "plain", "layer-a"],
        ["X", "E", "layer-a", "layer-ax"],
        ["T", "E", "layer-ax", "layer-axt"],
        ["S", "E", "layer-axt", "layer-axts"],
        ["S", "D", "layer-axts", "unwrap-axt"],
        ["T", "D", "unwrap-axt", "unwrap-ax"],
        ["X", "D", "unwrap-ax", "unwrap-a"],
        ["A", "D", "unwrap-a", "recovered"],
    ] {
        assert_success(binary.run(working.path(), &arguments));
    }

    assert_eq!(
        fs::read(working.path().join("recovered")).unwrap(),
        original
    );
}

#[test]
#[cfg(unix)]
fn randomized_encryption_and_authentication_failures_are_safe() {
    let binary = InstalledBinary::new();
    let working = tempfile::tempdir().unwrap();
    binary.keygen(working.path());
    fs::write(working.path().join("plain"), b"same secret input").unwrap();

    assert_success(binary.run(working.path(), &["A", "E", "plain", "one"]));
    assert_success(binary.run(working.path(), &["A", "E", "plain", "two"]));
    let one = fs::read(working.path().join("one")).unwrap();
    let two = fs::read(working.path().join("two")).unwrap();
    assert_ne!(one, two);

    let mut tampered = one;
    let final_index = tampered.len() - 1;
    tampered[final_index] ^= 1;
    fs::write(working.path().join("tampered"), tampered).unwrap();
    let output = binary.run(working.path(), &["A", "D", "tampered", "must-not-exist"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(!working.path().join("must-not-exist").exists());
    assert!(String::from_utf8_lossy(&output.stderr).contains("wrong key or corrupted ciphertext"));
}

#[test]
#[cfg(unix)]
fn existing_output_and_bad_key_are_never_modified_or_bypassed() {
    let binary = InstalledBinary::new();
    let working = tempfile::tempdir().unwrap();
    binary.keygen(working.path());
    fs::write(working.path().join("plain"), b"plaintext").unwrap();
    fs::write(working.path().join("output"), b"keep me").unwrap();

    let refused = binary.run(working.path(), &["X", "E", "plain", "output"]);
    assert_eq!(refused.status.code(), Some(1));
    assert_eq!(fs::read(working.path().join("output")).unwrap(), b"keep me");

    fs::write(binary.directory().join("cha.key"), [1_u8; 31]).unwrap();
    let bad_key = binary.run(working.path(), &["X", "E", "plain", "new-output"]);
    assert_eq!(bad_key.status.code(), Some(1));
    assert!(!working.path().join("new-output").exists());
}

#[test]
fn grammar_is_strict_and_uses_exit_code_two() {
    let binary = InstalledBinary::new();
    let working = tempfile::tempdir().unwrap();
    for arguments in [
        vec![],
        vec!["a", "E", "in", "out"],
        vec!["A", "e", "in", "out"],
        vec!["AES", "E", "in", "out"],
        vec!["KEYGEN"],
        vec!["keygen", "extra"],
    ] {
        let output = binary.run(working.path(), &arguments);
        assert_eq!(output.status.code(), Some(2), "{arguments:?}");
        assert!(String::from_utf8_lossy(&output.stderr).contains("Usage:"));
    }

    assert_success(binary.run(working.path(), &["--help"]));
    assert_success(binary.run(working.path(), &["--version"]));
}

#[cfg(unix)]
#[test]
fn input_symlink_is_rejected_and_outputs_are_private() {
    use std::os::unix::fs::{MetadataExt, symlink};

    let binary = InstalledBinary::new();
    let working = tempfile::tempdir().unwrap();
    binary.keygen(working.path());
    fs::write(working.path().join("plain"), b"plaintext").unwrap();
    symlink("plain", working.path().join("link")).unwrap();

    let rejected = binary.run(working.path(), &["S", "E", "link", "bad"]);
    assert_eq!(rejected.status.code(), Some(1));
    assert!(!working.path().join("bad").exists());

    assert_success(binary.run(working.path(), &["S", "E", "plain", "encrypted"]));
    assert_eq!(
        fs::metadata(working.path().join("encrypted"))
            .unwrap()
            .mode()
            & 0o077,
        0
    );
}

#[test]
#[cfg(unix)]
fn concurrent_keygen_has_one_winner_and_one_complete_key_set() {
    let binary = InstalledBinary::new();
    let working = tempfile::tempdir().unwrap();
    let mut first = binary.spawn_quiet(working.path(), &["keygen"]);
    let mut second = binary.spawn_quiet(working.path(), &["keygen"]);
    let statuses = [first.wait().unwrap(), second.wait().unwrap()];
    assert_eq!(statuses.iter().filter(|status| status.success()).count(), 1);
    for (filename, length) in KEY_FILES {
        assert_eq!(
            fs::metadata(binary.directory().join(filename))
                .unwrap()
                .len(),
            length as u64
        );
    }
}

#[cfg(not(unix))]
#[test]
fn file_operations_fail_closed_on_unsupported_platforms() {
    let binary = InstalledBinary::new();
    let working = tempfile::tempdir().unwrap();
    fs::write(working.path().join("input"), b"data").unwrap();

    for arguments in [
        &["keygen"][..],
        &["A", "E", "input", "encrypted"][..],
        &["A", "D", "input", "decrypted"][..],
    ] {
        let output = binary.run(working.path(), arguments);
        assert_eq!(output.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&output.stderr).contains("supported only on Unix"));
    }
    assert!(!working.path().join("encrypted").exists());
    assert!(!working.path().join("decrypted").exists());
}
