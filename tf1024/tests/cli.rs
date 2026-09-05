use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
};

struct App {
    directory: tempfile::TempDir,
    binary: PathBuf,
}

impl App {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let binary = directory
            .path()
            .join(format!("tf1024{}", std::env::consts::EXE_SUFFIX));
        fs::copy(env!("CARGO_BIN_EXE_tf1024"), &binary).unwrap();
        Self { directory, binary }
    }

    fn run(&self, args: &[&str]) -> Output {
        // Deliberately run outside the executable directory.
        let cwd = tempfile::tempdir().unwrap();
        Command::new(&self.binary)
            .args(args)
            .current_dir(cwd.path())
            .output()
            .unwrap()
    }

    fn prepare(&self) {
        assert!(self.run(&["keygen"]).status.success());
        fs::write(
            self.directory.path().join("plain.bin"),
            b"binary\0payload\xff\r\n",
        )
        .unwrap();
        assert!(self.run(&["E", "plain.bin", "cipher.bin"]).status.success());
    }
}

#[test]
fn cli_uses_executable_directory_and_preserves_key_and_inputs() {
    let app = App::new();
    app.prepare();
    let key = fs::read(app.directory.path().join("key.key")).unwrap();
    assert_eq!(key.len(), 128);
    assert!(!app.run(&["keygen"]).status.success());
    assert_eq!(fs::read(app.directory.path().join("key.key")).unwrap(), key);
    assert!(
        app.run(&["D", "cipher.bin", "restored.bin"])
            .status
            .success()
    );
    let original = fs::read(app.directory.path().join("plain.bin")).unwrap();
    assert_eq!(
        fs::read(app.directory.path().join("restored.bin")).unwrap(),
        original
    );
    assert!(
        !app.run(&["E", "plain.bin", "restored.bin"])
            .status
            .success()
    );
    assert_eq!(
        fs::read(app.directory.path().join("restored.bin")).unwrap(),
        original
    );
}

#[test]
fn cli_rejects_corruption_truncation_and_length_overflow_without_output() {
    let app = App::new();
    app.prepare();
    let original = fs::read(app.directory.path().join("cipher.bin")).unwrap();
    let mut variants = Vec::new();
    for index in [0, 8, 16, 48, 64, original.len() - 1] {
        let mut bytes = original.clone();
        bytes[index] ^= 1;
        variants.push(bytes);
    }
    for length in [0, 7, 63, original.len() - 1] {
        variants.push(original[..length].to_vec());
    }
    let mut overflow = original.clone();
    overflow[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
    variants.push(overflow);
    let mut appended = original.clone();
    appended.push(0);
    variants.push(appended);
    for bytes in variants {
        fs::write(app.directory.path().join("damaged.bin"), bytes).unwrap();
        let result = app.run(&["D", "damaged.bin", "restored.bin"]);
        assert!(!result.status.success());
        assert!(!String::from_utf8_lossy(&result.stderr).contains("panicked"));
        assert!(!app.directory.path().join("restored.bin").exists());
        assert_eq!(fs::read_dir(app.directory.path()).unwrap().count(), 5);
    }
}

#[test]
fn cli_rejects_invalid_key_lengths_without_output() {
    let app = App::new();
    fs::write(app.directory.path().join("plain.bin"), b"keep").unwrap();
    for length in [0, 1, 127, 129, 256] {
        fs::write(app.directory.path().join("key.key"), vec![0x55; length]).unwrap();
        assert!(!app.run(&["E", "plain.bin", "cipher.bin"]).status.success());
        assert!(!app.directory.path().join("cipher.bin").exists());
        assert_eq!(
            fs::read(app.directory.path().join("plain.bin")).unwrap(),
            b"keep"
        );
    }
}

#[cfg(windows)]
#[test]
fn cli_rejects_key_file_alias_before_reading_key_material() {
    let app = App::new();
    assert!(app.run(&["keygen"]).status.success());
    for alias in ["key.key.", "key.key ", "key.key:secret"] {
        assert!(!app.run(&["E", alias, "leaked.bin"]).status.success());
        assert!(!app.directory.path().join("leaked.bin").exists());
    }
}
