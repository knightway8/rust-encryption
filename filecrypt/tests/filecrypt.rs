#![allow(clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use filecrypt::{
    Algorithm, CHUNK_SIZE, FileCryptError, HEADER_SIZE, KEY_FILE_NAME, KEY_SIZE,
    MAX_PLAINTEXT_SIZE, MasterKey, RECORD_HEADER_SIZE, decrypt_file, encrypt_file,
    generate_key_file, load_key_file,
};
use secrecy::{ExposeSecret, ExposeSecretMut};

fn key_with_byte(value: u8) -> MasterKey {
    let mut key = MasterKey::default();
    key.expose_secret_mut().fill(value);
    key
}

fn test_bytes(length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| (index.wrapping_mul(131) ^ (index >> 7)).to_le_bytes()[0])
        .collect()
}

struct CopiedCli {
    _directory: tempfile::TempDir,
    executable_dir: PathBuf,
    working_dir: PathBuf,
    executable: PathBuf,
}

impl CopiedCli {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("test directory");
        let executable_dir = directory.path().join("app");
        let working_dir = directory.path().join("working directory");
        fs::create_dir(&executable_dir).expect("create executable directory");
        fs::create_dir(&working_dir).expect("create working directory");

        let executable_name = if cfg!(windows) {
            "filecrypt.exe"
        } else {
            "filecrypt"
        };
        let executable = executable_dir.join(executable_name);
        fs::copy(Path::new(env!("CARGO_BIN_EXE_filecrypt")), &executable).expect("copy executable");

        Self {
            _directory: directory,
            executable_dir,
            working_dir,
            executable,
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(&self.executable);
        command.current_dir(&self.working_dir);
        command
    }

    fn run(&self, arguments: &[&str]) -> Output {
        let mut command = self.command();
        command.args(arguments);
        copied_cli_output(&mut command)
    }

    fn key_path(&self) -> PathBuf {
        self.executable_dir.join(KEY_FILE_NAME)
    }
}

fn copied_cli_output(command: &mut Command) -> Output {
    #[cfg(unix)]
    {
        for _attempt in 0..32 {
            match command.output() {
                Ok(output) => return output,
                Err(error) if error.kind() == std::io::ErrorKind::ExecutableFileBusy => {
                    // Some overlay filesystems briefly retain the writer used by fs::copy.
                    std::thread::yield_now();
                }
                result => return result.expect("run copied CLI"),
            }
        }
        command.output().expect("run copied CLI after retries")
    }

    #[cfg(not(unix))]
    {
        command.output().expect("run copied CLI")
    }
}

#[test]
fn algorithm_public_api_uses_only_exact_documented_selectors_and_names() {
    use std::ffi::OsStr;

    assert_eq!(
        Algorithm::from_selector(OsStr::new("1")),
        Some(Algorithm::Aes256GcmSiv)
    );
    assert_eq!(
        Algorithm::from_selector(OsStr::new("2")),
        Some(Algorithm::XChaCha20Poly1305)
    );
    assert_eq!(Algorithm::Aes256GcmSiv.name(), "AES-256-GCM-SIV");
    assert_eq!(Algorithm::XChaCha20Poly1305.name(), "XChaCha20-Poly1305");

    for invalid in ["", "0", "01", " 1", "1 ", "aes", "3", "٢"] {
        assert_eq!(
            Algorithm::from_selector(OsStr::new(invalid)),
            None,
            "accepted non-canonical selector {invalid:?}"
        );
    }
}

#[test]
fn malformed_public_headers_are_rejected_without_creating_plaintext() {
    let directory = tempfile::tempdir().expect("test directory");
    let key = key_with_byte(0x4c);
    let input = directory.path().join("source");
    let encrypted = directory.path().join("valid.enc");
    fs::write(&input, b"authenticated input").expect("write input");
    encrypt_file(Algorithm::Aes256GcmSiv, &input, &encrypted, &key).expect("encrypt baseline");
    let baseline = fs::read(&encrypted).expect("read baseline");

    let mut variants = Vec::new();

    let mut bad_magic = baseline.clone();
    bad_magic[0] ^= 0x80;
    variants.push(("bad-magic", bad_magic, "bad magic"));

    let mut bad_version = baseline.clone();
    bad_version[8..10].copy_from_slice(&2_u16.to_le_bytes());
    variants.push(("bad-version", bad_version, "unsupported version"));

    let mut bad_algorithm = baseline.clone();
    bad_algorithm[10] = 3;
    variants.push(("bad-algorithm", bad_algorithm, "unsupported algorithm"));

    let mut reserved_byte = baseline.clone();
    reserved_byte[11] = 1;
    variants.push((
        "reserved-byte",
        reserved_byte,
        "nonzero reserved header field",
    ));

    let mut reserved_tail = baseline.clone();
    reserved_tail[95] = 1;
    variants.push((
        "reserved-tail",
        reserved_tail,
        "nonzero reserved header field",
    ));

    let mut bad_chunk_size = baseline.clone();
    bad_chunk_size[12..16].copy_from_slice(&4096_u32.to_le_bytes());
    variants.push(("bad-chunk-size", bad_chunk_size, "unsupported chunk size"));

    let mut oversized_plaintext = baseline.clone();
    oversized_plaintext[16..24].copy_from_slice(&(MAX_PLAINTEXT_SIZE + 1).to_le_bytes());
    variants.push((
        "oversized-plaintext",
        oversized_plaintext,
        "declared plaintext is too large",
    ));

    let mut aes_nonce_padding = baseline;
    aes_nonce_padding[64] = 1;
    variants.push((
        "aes-nonce-padding",
        aes_nonce_padding,
        "nonzero AES nonce padding",
    ));

    for (name, bytes, expected_reason) in variants {
        let malformed = directory.path().join(format!("{name}.enc"));
        let output = directory.path().join(format!("{name}.out"));
        fs::write(&malformed, bytes).expect("write malformed input");
        let error = decrypt_file(&malformed, &output, &key).expect_err(name);
        assert!(
            matches!(error, FileCryptError::InvalidFormat(reason) if reason == expected_reason),
            "unexpected error for {name}: {error:?}"
        );
        assert!(!output.exists(), "{name} published plaintext");
        assert_no_temporary_files(directory.path());
    }
}

#[test]
fn public_api_rejects_bad_paths_without_leaving_outputs_or_staging_files() {
    let directory = tempfile::tempdir().expect("test directory");
    let key = key_with_byte(0x6d);
    let input = directory.path().join("input");
    fs::write(&input, b"source contents").expect("write input");

    let invalid_output = Path::new("");
    let error = encrypt_file(Algorithm::Aes256GcmSiv, &input, invalid_output, &key)
        .expect_err("empty output path");
    assert!(matches!(error, FileCryptError::InvalidOutputPath(_)));

    let missing_parent_output = directory.path().join("missing-parent/output");
    let error = encrypt_file(
        Algorithm::Aes256GcmSiv,
        &input,
        &missing_parent_output,
        &key,
    )
    .expect_err("missing output parent");
    assert!(
        matches!(error, FileCryptError::Io { action, .. } if action == "inspect output directory")
    );
    assert!(!missing_parent_output.exists());

    let non_directory_parent = directory.path().join("parent-file");
    fs::write(&non_directory_parent, b"sentinel").expect("write parent sentinel");
    let nested_output = non_directory_parent.join("output");
    let error = encrypt_file(Algorithm::XChaCha20Poly1305, &input, &nested_output, &key)
        .expect_err("non-directory output parent");
    assert!(matches!(error, FileCryptError::InvalidOutputPath(_)));
    assert_eq!(
        fs::read(&non_directory_parent).expect("read parent sentinel"),
        b"sentinel"
    );

    let missing_input = directory.path().join("missing-input");
    let missing_input_output = directory.path().join("missing-input.enc");
    let error = encrypt_file(
        Algorithm::Aes256GcmSiv,
        &missing_input,
        &missing_input_output,
        &key,
    )
    .expect_err("missing input");
    assert!(matches!(error, FileCryptError::Io { action, .. } if action == "open input"));
    assert!(!missing_input_output.exists());
    assert_no_temporary_files(directory.path());
}

#[cfg(unix)]
#[test]
fn public_api_rejects_directory_inputs_without_publishing_outputs() {
    let directory = tempfile::tempdir().expect("test directory");
    let key = key_with_byte(0x71);

    for (name, decrypting) in [("encrypt", false), ("decrypt", true)] {
        let output = directory.path().join(format!("{name}.out"));
        let result = if decrypting {
            decrypt_file(directory.path(), &output, &key).map(|_| ())
        } else {
            encrypt_file(Algorithm::Aes256GcmSiv, directory.path(), &output, &key)
        };
        assert!(
            matches!(result, Err(FileCryptError::InputNotRegular(_))),
            "unexpected {name} result: {result:?}"
        );
        assert!(!output.exists());
        assert_no_temporary_files(directory.path());
    }
}

#[cfg(unix)]
#[test]
fn public_api_rejects_fifo_inputs_without_waiting_for_a_writer() {
    use std::sync::mpsc;
    use std::time::Duration;

    let directory = tempfile::tempdir().expect("test directory");
    let fifo = directory.path().join("input-fifo");
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        &fifo,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .expect("create FIFO");

    for (name, decrypting) in [("encrypt", false), ("decrypt", true)] {
        let fifo = fifo.clone();
        let output = directory.path().join(format!("{name}-fifo.out"));
        let operation_output = output.clone();
        let (sender, receiver) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let key = key_with_byte(0x51);
            let result = if decrypting {
                decrypt_file(&fifo, &operation_output, &key).map(|_| ())
            } else {
                encrypt_file(Algorithm::Aes256GcmSiv, &fifo, &operation_output, &key)
            };
            sender.send(result).expect("return FIFO result");
        });
        let result = receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("opening a FIFO for reading must not block");
        worker.join().expect("join FIFO worker");
        assert!(
            matches!(result, Err(FileCryptError::InputNotRegular(_))),
            "unexpected {name} result: {result:?}"
        );
        assert!(!output.exists());
        assert_no_temporary_files(directory.path());
    }
}

#[test]
fn decrypt_never_changes_existing_or_in_place_destinations() {
    let directory = tempfile::tempdir().expect("test directory");
    let key = key_with_byte(0x39);
    let wrong_key = key_with_byte(0x93);
    let input = directory.path().join("input");
    let encrypted = directory.path().join("encrypted");
    let existing_output = directory.path().join("existing-output");
    fs::write(&input, b"plaintext").expect("write input");
    encrypt_file(Algorithm::XChaCha20Poly1305, &input, &encrypted, &key).expect("encrypt");
    let encrypted_before = fs::read(&encrypted).expect("read encrypted input");
    fs::write(&existing_output, b"output sentinel").expect("write output sentinel");

    let existing_error = decrypt_file(&encrypted, &existing_output, &wrong_key)
        .expect_err("existing output must be rejected before authentication");
    assert!(matches!(existing_error, FileCryptError::OutputExists(_)));
    assert_eq!(
        fs::read(&existing_output).expect("read output sentinel"),
        b"output sentinel"
    );

    let in_place_error =
        decrypt_file(&encrypted, &encrypted, &key).expect_err("in-place decryption");
    assert!(matches!(in_place_error, FileCryptError::OutputExists(_)));
    assert_eq!(
        fs::read(&encrypted).expect("reread encrypted input"),
        encrypted_before
    );
    assert_no_temporary_files(directory.path());
}

#[test]
fn independently_generated_keys_have_the_public_size_and_distinct_contents() {
    let directory = tempfile::tempdir().expect("test directory");
    let first_path = directory.path().join("first.key");
    let second_path = directory.path().join("second.key");
    generate_key_file(&first_path).expect("generate first key");
    generate_key_file(&second_path).expect("generate second key");

    let first = fs::read(&first_path).expect("read first key");
    let second = fs::read(&second_path).expect("read second key");
    assert_eq!(first.len(), KEY_SIZE);
    assert_eq!(second.len(), KEY_SIZE);
    assert_ne!(first, second, "independent key generation reused a key");
    assert_no_temporary_files(directory.path());
}

#[test]
fn both_algorithms_round_trip_chunk_boundaries_and_randomize_ciphertexts() {
    let directory = tempfile::tempdir().expect("test directory");
    let key = key_with_byte(0xa5);
    let sizes = [
        0,
        1,
        15,
        16,
        CHUNK_SIZE - 1,
        CHUNK_SIZE,
        CHUNK_SIZE + 1,
        2 * CHUNK_SIZE - 1,
        2 * CHUNK_SIZE,
        2 * CHUNK_SIZE + 1,
    ];

    for algorithm in [Algorithm::Aes256GcmSiv, Algorithm::XChaCha20Poly1305] {
        for size in sizes {
            let stem = format!("{}-{size}", algorithm as u8);
            let input = directory.path().join(format!("{stem}.plain"));
            let encrypted_a = directory.path().join(format!("{stem}.a.enc"));
            let encrypted_b = directory.path().join(format!("{stem}.b.enc"));
            let decrypted = directory.path().join(format!("{stem}.roundtrip"));
            let plaintext = test_bytes(size);
            fs::write(&input, &plaintext).expect("write plaintext");

            encrypt_file(algorithm, &input, &encrypted_a, &key).expect("encrypt first copy");
            encrypt_file(algorithm, &input, &encrypted_b, &key).expect("encrypt second copy");
            let detected = decrypt_file(&encrypted_a, &decrypted, &key).expect("decrypt");

            assert_eq!(detected, algorithm);
            assert_eq!(fs::read(&decrypted).expect("read plaintext"), plaintext);
            assert_eq!(fs::read(&input).expect("reread source"), plaintext);
            assert_ne!(
                fs::read(&encrypted_a).expect("read first ciphertext"),
                fs::read(&encrypted_b).expect("read second ciphertext"),
                "fresh salt and nonce must randomize each encryption"
            );

            let data_records = size.div_ceil(CHUNK_SIZE);
            let expected_ciphertext_size = HEADER_SIZE
                + size
                + data_records * (RECORD_HEADER_SIZE + 16)
                + RECORD_HEADER_SIZE
                + 24
                + 16;
            assert_eq!(
                fs::metadata(&encrypted_a)
                    .expect("ciphertext metadata")
                    .len(),
                expected_ciphertext_size as u64
            );
        }
    }
}

#[test]
fn corruption_wrong_key_truncation_and_trailing_bytes_never_publish_plaintext() {
    let directory = tempfile::tempdir().expect("test directory");
    let key = key_with_byte(0x11);
    let wrong_key = key_with_byte(0x22);
    let input = directory.path().join("source.bin");
    fs::write(&input, test_bytes(CHUNK_SIZE + 123)).expect("write plaintext");

    for algorithm in [Algorithm::Aes256GcmSiv, Algorithm::XChaCha20Poly1305] {
        let algorithm_id = algorithm as u8;
        let encrypted = directory.path().join(format!("source-{algorithm_id}.enc"));
        encrypt_file(algorithm, &input, &encrypted, &key).expect("encrypt");
        let original = fs::read(&encrypted).expect("read encrypted file");

        let wrong_key_output = directory
            .path()
            .join(format!("wrong-key-{algorithm_id}.out"));
        let error = decrypt_file(&encrypted, &wrong_key_output, &wrong_key).expect_err("wrong key");
        assert!(matches!(error, FileCryptError::AuthenticationFailed));
        assert!(!wrong_key_output.exists());
        assert_no_temporary_files(directory.path());

        let first_record_size = RECORD_HEADER_SIZE + CHUNK_SIZE + 16;
        let second_record_offset = HEADER_SIZE + first_record_size;
        let second_record_size = RECORD_HEADER_SIZE + 123 + 16;
        let end_record_offset = second_record_offset + second_record_size;
        let mut variants = Vec::new();

        let mut header_salt_flip = original.clone();
        header_salt_flip[24] ^= 1;
        variants.push(("header-salt", header_salt_flip));

        let mut record_sequence_flip = original.clone();
        record_sequence_flip[HEADER_SIZE + 8] ^= 1;
        variants.push(("record-sequence", record_sequence_flip));

        let mut record_reserved_flip = original.clone();
        record_reserved_flip[HEADER_SIZE + 1] = 1;
        variants.push(("record-reserved", record_reserved_flip));

        let mut oversized_record = original.clone();
        oversized_record[HEADER_SIZE + 4..HEADER_SIZE + 8].copy_from_slice(&u32::MAX.to_le_bytes());
        variants.push(("oversized-record", oversized_record));

        let mut first_ciphertext_flip = original.clone();
        first_ciphertext_flip[HEADER_SIZE + RECORD_HEADER_SIZE + 7] ^= 0x80;
        variants.push(("first-ciphertext", first_ciphertext_flip));

        let mut second_ciphertext_flip = original.clone();
        second_ciphertext_flip[second_record_offset + RECORD_HEADER_SIZE + 7] ^= 0x10;
        variants.push(("second-ciphertext", second_ciphertext_flip));

        let mut first_tag_flip = original.clone();
        let first_tag = HEADER_SIZE + RECORD_HEADER_SIZE + CHUNK_SIZE;
        first_tag_flip[first_tag] ^= 0x40;
        variants.push(("first-tag", first_tag_flip));

        let mut end_record_type_flip = original.clone();
        end_record_type_flip[end_record_offset] = 1;
        variants.push(("end-record-type", end_record_type_flip));

        let mut footer_tag_flip = original.clone();
        let final_index = footer_tag_flip.len() - 1;
        footer_tag_flip[final_index] ^= 0x20;
        variants.push(("footer-tag", footer_tag_flip));

        variants.push(("short-header", original[..HEADER_SIZE - 1].to_vec()));
        variants.push((
            "missing-footer-byte",
            original[..original.len() - 1].to_vec(),
        ));
        variants.push((
            "complete-first-record-only",
            original[..HEADER_SIZE + first_record_size].to_vec(),
        ));

        let mut trailing = original.clone();
        trailing.push(0);
        variants.push(("trailing-byte", trailing));

        let mut deleted_first_record = original[..HEADER_SIZE].to_vec();
        deleted_first_record.extend_from_slice(&original[HEADER_SIZE + first_record_size..]);
        variants.push(("deleted-record", deleted_first_record));

        for (name, bytes) in variants {
            let damaged = directory.path().join(format!("{algorithm_id}-{name}.enc"));
            let output = directory.path().join(format!("{algorithm_id}-{name}.out"));
            fs::write(&damaged, bytes).expect("write damaged ciphertext");
            let error = decrypt_file(&damaged, &output, &key).expect_err(name);
            assert!(
                matches!(&error, FileCryptError::AuthenticationFailed),
                "{name} returned an unexpected error: {error:?}"
            );
            assert!(!output.exists(), "{name} published partial plaintext");
            assert_no_temporary_files(directory.path());
        }
    }
}

#[cfg(unix)]
#[test]
fn encrypted_and_decrypted_outputs_are_private() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().expect("test directory");
    let key = key_with_byte(0x5a);
    let input = directory.path().join("source.bin");
    let encrypted = directory.path().join("source.enc");
    let decrypted = directory.path().join("source.out");
    fs::write(&input, b"private output permissions").expect("write plaintext");
    fs::set_permissions(&input, fs::Permissions::from_mode(0o644))
        .expect("make source non-private");

    encrypt_file(Algorithm::Aes256GcmSiv, &input, &encrypted, &key).expect("encrypt");
    decrypt_file(&encrypted, &decrypted, &key).expect("decrypt");

    for output in [&encrypted, &decrypted] {
        let mode = fs::metadata(output)
            .expect("output metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "'{}' was not private", output.display());
        assert_no_temporary_files(directory.path());
    }
}

#[test]
fn existing_destinations_are_never_changed() {
    let directory = tempfile::tempdir().expect("test directory");
    let key = key_with_byte(7);
    let input = directory.path().join("input");
    let output = directory.path().join("output");
    fs::write(&input, b"plaintext").expect("write input");
    fs::write(&output, b"must survive").expect("write output sentinel");
    let before = fs::metadata(&output)
        .expect("metadata before")
        .modified()
        .expect("mtime before");

    let error = encrypt_file(Algorithm::Aes256GcmSiv, &input, &output, &key)
        .expect_err("existing destination must fail");
    assert!(matches!(error, FileCryptError::OutputExists(_)));
    assert_eq!(fs::read(&output).expect("read sentinel"), b"must survive");
    assert_eq!(
        fs::metadata(&output)
            .expect("metadata after")
            .modified()
            .expect("mtime after"),
        before
    );

    let in_place = encrypt_file(Algorithm::Aes256GcmSiv, &input, &input, &key)
        .expect_err("in-place operation must fail");
    assert!(matches!(in_place, FileCryptError::OutputExists(_)));
    assert_eq!(fs::read(&input).expect("read input"), b"plaintext");
}

#[cfg(unix)]
#[test]
fn existing_symlink_destination_is_preserved() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().expect("test directory");
    let key = key_with_byte(9);
    let input = directory.path().join("input");
    let target = directory.path().join("target");
    let output = directory.path().join("output-link");
    fs::write(&input, b"plaintext").expect("write input");
    fs::write(&target, b"target sentinel").expect("write target");
    symlink(&target, &output).expect("create symlink");

    let error = encrypt_file(Algorithm::XChaCha20Poly1305, &input, &output, &key)
        .expect_err("symlink destination must fail");
    assert!(matches!(error, FileCryptError::OutputExists(_)));
    assert_eq!(fs::read(&target).expect("read target"), b"target sentinel");
    assert!(
        fs::symlink_metadata(&output)
            .expect("symlink metadata")
            .file_type()
            .is_symlink()
    );
}

#[test]
fn key_generation_loading_and_no_overwrite_are_strict() {
    let directory = tempfile::tempdir().expect("test directory");
    let path = directory.path().join("key.key");

    generate_key_file(&path).expect("generate key");
    let first = fs::read(&path).expect("read key");
    assert_eq!(first.len(), 32);
    let loaded = load_key_file(&path).expect("load generated key");
    assert_eq!(loaded.expose_secret(), first.as_slice());

    let error = generate_key_file(&path).expect_err("keygen must not overwrite");
    assert!(matches!(error, FileCryptError::OutputExists(_)));
    assert_eq!(fs::read(&path).expect("reread key"), first);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&path)
                .expect("key metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[test]
fn key_loader_rejects_missing_and_wrong_lengths() {
    let directory = tempfile::tempdir().expect("test directory");
    let missing = directory.path().join("missing.key");
    assert!(matches!(
        load_key_file(&missing),
        Err(FileCryptError::KeyNotFound(_))
    ));

    for length in [0, 31, 33, 64] {
        let path = directory.path().join(format!("key-{length}"));
        write_private(&path, &vec![b'a'; length]);
        assert!(matches!(
            load_key_file(&path),
            Err(FileCryptError::InvalidKeyLength { .. })
        ));
    }

    let binary = directory.path().join("binary-key");
    let mut bytes = [0_u8; 32];
    bytes[3] = b'\n';
    bytes[17] = 0xff;
    write_private(&binary, &bytes);
    assert_eq!(
        load_key_file(&binary)
            .expect("load binary key")
            .expose_secret(),
        &bytes
    );
}

#[cfg(unix)]
#[test]
fn key_loader_rejects_group_or_world_access() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().expect("test directory");
    let path = directory.path().join("key.key");
    fs::write(&path, [0x42; 32]).expect("write key");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).expect("set permissions");
    assert!(matches!(
        load_key_file(&path),
        Err(FileCryptError::InsecureKeyPermissions(_))
    ));
}

#[test]
fn cli_help_version_and_every_command_arity_have_stable_streams_and_exit_codes() {
    let executable = Path::new(env!("CARGO_BIN_EXE_filecrypt"));

    for argument in ["-h", "--help"] {
        let output = Command::new(executable)
            .arg(argument)
            .output()
            .expect("run help");
        assert_eq!(output.status.code(), Some(0));
        assert!(output.stderr.is_empty());
        let stdout = String::from_utf8(output.stdout).expect("UTF-8 help");
        assert!(stdout.starts_with("filecrypt — authenticated streaming file encryption\n"));
        assert!(stdout.contains("filecrypt decrypt <INPUT> <OUTPUT>"));
        assert!(stdout.ends_with("No command ever overwrites an existing file.\n"));
    }

    for argument in ["-V", "--version"] {
        let output = Command::new(executable)
            .arg(argument)
            .output()
            .expect("run version");
        assert_eq!(output.status.code(), Some(0));
        assert_eq!(
            output.stdout,
            format!("filecrypt {}\n", env!("CARGO_PKG_VERSION")).as_bytes()
        );
        assert!(output.stderr.is_empty());
    }

    let invalid_invocations: &[(&[&str], &str)] = &[
        (&[], "missing command or encryption algorithm"),
        (
            &["--help", "extra"],
            "help option does not accept arguments",
        ),
        (
            &["--version", "extra"],
            "version option does not accept arguments",
        ),
        (&["keygen", "extra"], "keygen does not accept arguments"),
        (
            &["decrypt"],
            "decrypt requires exactly INPUT and OUTPUT paths",
        ),
        (
            &["decrypt", "input"],
            "decrypt requires exactly INPUT and OUTPUT paths",
        ),
        (
            &["decrypt", "input", "output", "extra"],
            "decrypt requires exactly INPUT and OUTPUT paths",
        ),
        (
            &["encrypt"],
            "encrypt requires an algorithm, INPUT, and OUTPUT",
        ),
        (
            &["encrypt", "1"],
            "encryption requires exactly INPUT and OUTPUT paths",
        ),
        (
            &["encrypt", "1", "input"],
            "encryption requires exactly INPUT and OUTPUT paths",
        ),
        (
            &["encrypt", "1", "input", "output", "extra"],
            "encryption requires exactly INPUT and OUTPUT paths",
        ),
        (&["1"], "encryption requires exactly INPUT and OUTPUT paths"),
        (
            &["1", "input"],
            "encryption requires exactly INPUT and OUTPUT paths",
        ),
        (
            &["1", "input", "output", "extra"],
            "encryption requires exactly INPUT and OUTPUT paths",
        ),
        (
            &["3", "input", "output"],
            "algorithm must be exactly 1 (AES-256-GCM-SIV) or 2 (XChaCha20-Poly1305)",
        ),
        (
            &["encrypt", "decrypt", "input", "output"],
            "algorithm must be exactly 1 (AES-256-GCM-SIV) or 2 (XChaCha20-Poly1305)",
        ),
    ];

    for (arguments, expected_error) in invalid_invocations {
        let output = Command::new(executable)
            .args(*arguments)
            .output()
            .expect("run invalid invocation");
        assert_eq!(
            output.status.code(),
            Some(2),
            "wrong exit status for {arguments:?}"
        );
        assert!(output.stdout.is_empty(), "stdout for {arguments:?}");
        let expected_prefix = format!("error: {expected_error}\n\nfilecrypt —");
        assert!(
            String::from_utf8_lossy(&output.stderr).starts_with(&expected_prefix),
            "unexpected stderr for {arguments:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn keyless_cli_operations_fail_exactly_and_never_fall_back_or_publish() {
    let cli = CopiedCli::new();
    fs::write(cli.working_dir.join("input"), b"plaintext").expect("write input");
    write_private(&cli.working_dir.join(KEY_FILE_NAME), &[0x99; KEY_SIZE]);
    let expected_stderr = format!(
        "error: key file not found at '{}'; create it with `filecrypt keygen`\n",
        cli.key_path().display()
    );

    for (arguments, output_name) in [
        (["1", "input", "short.enc"], "short.enc"),
        (["encrypt", "2", "input"], "explicit.enc"),
    ] {
        let output = if arguments[0] == "encrypt" {
            cli.run(&[arguments[0], arguments[1], arguments[2], output_name])
        } else {
            cli.run(&arguments)
        };
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert_eq!(String::from_utf8_lossy(&output.stderr), expected_stderr);
        assert!(!cli.working_dir.join(output_name).exists());
    }

    let decrypt = cli.run(&["decrypt", "missing.enc", "decrypted"]);
    assert_eq!(decrypt.status.code(), Some(1));
    assert!(decrypt.stdout.is_empty());
    assert_eq!(String::from_utf8_lossy(&decrypt.stderr), expected_stderr);
    assert!(!cli.working_dir.join("decrypted").exists());
    assert_no_temporary_files(&cli.working_dir);
    assert_no_temporary_files(&cli.executable_dir);
}

#[test]
fn cli_short_explicit_and_separator_forms_round_trip_both_algorithms() {
    let cli = CopiedCli::new();
    let keygen = cli.run(&["keygen"]);
    assert_eq!(keygen.status.code(), Some(0));

    let cases = [
        (
            "1",
            "AES-256-GCM-SIV",
            "-aes-input",
            "-aes-encrypted",
            "-aes-output",
            false,
        ),
        (
            "2",
            "XChaCha20-Poly1305",
            "-xchacha-input",
            "-xchacha-encrypted",
            "-xchacha-output",
            true,
        ),
    ];

    for (selector, algorithm_name, input, encrypted, output, explicit) in cases {
        let plaintext = format!("contents for algorithm {selector}").into_bytes();
        fs::write(cli.working_dir.join(input), &plaintext).expect("write CLI input");
        let encryption = if explicit {
            cli.run(&["encrypt", selector, "--", input, encrypted])
        } else {
            cli.run(&[selector, "--", input, encrypted])
        };
        assert_eq!(
            encryption.status.code(),
            Some(0),
            "encryption stderr: {}",
            String::from_utf8_lossy(&encryption.stderr)
        );
        assert!(encryption.stderr.is_empty());
        assert_eq!(
            String::from_utf8_lossy(&encryption.stdout),
            format!("encrypted with {algorithm_name}: '{input}' -> '{encrypted}'\n")
        );

        let decryption = cli.run(&["decrypt", "--", encrypted, output]);
        assert_eq!(
            decryption.status.code(),
            Some(0),
            "decryption stderr: {}",
            String::from_utf8_lossy(&decryption.stderr)
        );
        assert!(decryption.stderr.is_empty());
        assert_eq!(
            String::from_utf8_lossy(&decryption.stdout),
            format!("decrypted {algorithm_name} stream: '{encrypted}' -> '{output}'\n")
        );
        assert_eq!(
            fs::read(cli.working_dir.join(output)).expect("read output"),
            plaintext
        );
        assert_no_temporary_files(&cli.working_dir);
    }
}

#[test]
fn cli_keygen_is_private_reports_exactly_and_never_overwrites() {
    let cli = CopiedCli::new();
    let first = cli.run(&["keygen"]);
    assert_eq!(first.status.code(), Some(0));
    assert!(first.stderr.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&first.stdout),
        format!(
            "created 32-byte key at '{}'\nkeep this file secret and backed up; encrypted files cannot be recovered without it\n",
            cli.key_path().display()
        )
    );
    let key_before = fs::read(cli.key_path()).expect("read generated key");
    assert_eq!(key_before.len(), KEY_SIZE);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(cli.key_path())
                .expect("key metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    let second = cli.run(&["keygen"]);
    assert_eq!(second.status.code(), Some(1));
    assert!(second.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&second.stderr),
        format!(
            "error: refusing to overwrite existing destination '{}'; choose a new output path\n",
            cli.key_path().display()
        )
    );
    assert_eq!(fs::read(cli.key_path()).expect("reread key"), key_before);
    assert_no_temporary_files(&cli.executable_dir);
}

#[test]
fn cli_authentication_and_overwrite_failures_leave_no_partial_or_temp_output() {
    let cli = CopiedCli::new();
    let key = key_with_byte(0x28);
    write_private(&cli.key_path(), key.expose_secret());
    let plaintext = test_bytes(CHUNK_SIZE + 31);
    let input = cli.working_dir.join("input");
    let encrypted = cli.working_dir.join("encrypted");
    fs::write(&input, &plaintext).expect("write input");
    encrypt_file(Algorithm::Aes256GcmSiv, &input, &encrypted, &key).expect("encrypt fixture");

    let mut corrupted = fs::read(&encrypted).expect("read encrypted fixture");
    corrupted[HEADER_SIZE + RECORD_HEADER_SIZE + 3] ^= 0x40;
    fs::write(cli.working_dir.join("corrupted"), corrupted).expect("write corruption");
    let corrupt_result = cli.run(&["decrypt", "corrupted", "corrupt-output"]);
    assert_eq!(corrupt_result.status.code(), Some(1));
    assert!(corrupt_result.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&corrupt_result.stderr),
        "error: authentication failed: wrong key or corrupted encrypted input\n"
    );
    assert!(!cli.working_dir.join("corrupt-output").exists());
    assert_no_temporary_files(&cli.working_dir);

    write_private(&cli.key_path(), &[0x82; KEY_SIZE]);
    let wrong_key_result = cli.run(&["decrypt", "encrypted", "wrong-key-output"]);
    assert_eq!(wrong_key_result.status.code(), Some(1));
    assert!(wrong_key_result.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&wrong_key_result.stderr),
        "error: authentication failed: wrong key or corrupted encrypted input\n"
    );
    assert!(!cli.working_dir.join("wrong-key-output").exists());
    assert_no_temporary_files(&cli.working_dir);

    write_private(&cli.key_path(), key.expose_secret());
    fs::write(cli.working_dir.join("existing"), b"sentinel").expect("write sentinel");
    let overwrite_result = cli.run(&["1", "input", "existing"]);
    assert_eq!(overwrite_result.status.code(), Some(1));
    assert!(overwrite_result.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&overwrite_result.stderr),
        "error: refusing to overwrite existing destination 'existing'; choose a new output path\n"
    );
    assert_eq!(
        fs::read(cli.working_dir.join("existing")).expect("read sentinel"),
        b"sentinel"
    );
    assert_no_temporary_files(&cli.working_dir);
}

#[test]
fn cli_rejects_bad_key_lengths_and_bad_path_kinds_without_artifacts() {
    let cli = CopiedCli::new();
    fs::write(cli.working_dir.join("input"), b"plaintext").expect("write input");
    write_private(&cli.key_path(), &[0x55; KEY_SIZE - 1]);
    let bad_key = cli.run(&["1", "input", "bad-key-output"]);
    assert_eq!(bad_key.status.code(), Some(1));
    assert!(bad_key.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&bad_key.stderr)
            .contains("must contain exactly 32 raw bytes (found 31)")
    );
    assert!(!cli.working_dir.join("bad-key-output").exists());

    write_private(&cli.key_path(), &[0x55; KEY_SIZE]);
    let missing_parent = cli.run(&["1", "input", "missing/output"]);
    assert_eq!(missing_parent.status.code(), Some(1));
    assert!(missing_parent.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&missing_parent.stderr)
            .contains("could not inspect output directory 'missing'")
    );
    assert!(!cli.working_dir.join("missing/output").exists());

    let missing_input = cli.run(&["encrypt", "2", "absent", "missing-input-output"]);
    assert_eq!(missing_input.status.code(), Some(1));
    assert!(missing_input.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&missing_input.stderr).contains("could not open input 'absent'")
    );
    assert!(!cli.working_dir.join("missing-input-output").exists());
    assert_no_temporary_files(&cli.working_dir);
}

#[cfg(unix)]
#[test]
fn cli_rejects_insecure_key_permissions_without_creating_output() {
    use std::os::unix::fs::PermissionsExt;

    let cli = CopiedCli::new();
    fs::write(cli.working_dir.join("input"), b"plaintext").expect("write input");
    fs::write(cli.key_path(), [0x44; KEY_SIZE]).expect("write key");
    fs::set_permissions(cli.key_path(), fs::Permissions::from_mode(0o644))
        .expect("make key insecure");

    let output = cli.run(&["1", "input", "encrypted"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        format!(
            "error: insecure key permissions on '{}': the key must be accessible only to the current user\n",
            cli.key_path().display()
        )
    );
    assert!(!cli.working_dir.join("encrypted").exists());
    assert_no_temporary_files(&cli.working_dir);
}

#[cfg(unix)]
#[test]
fn cli_round_trips_non_utf8_paths() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let cli = CopiedCli::new();
    assert_eq!(cli.run(&["keygen"]).status.code(), Some(0));
    let input_name = OsString::from_vec(b"-plain-\xff".to_vec());
    let encrypted_name = OsString::from_vec(b"-encrypted-\xfe".to_vec());
    let output_name = OsString::from_vec(b"-output-\xfd".to_vec());
    let plaintext = b"non-UTF-8 CLI path contents";
    fs::write(cli.working_dir.join(&input_name), plaintext).expect("write non-UTF-8 input");

    let mut encryption_command = cli.command();
    encryption_command.args([
        OsString::from("encrypt"),
        OsString::from("2"),
        OsString::from("--"),
        input_name.clone(),
        encrypted_name.clone(),
    ]);
    let encryption = copied_cli_output(&mut encryption_command);
    assert_eq!(encryption.status.code(), Some(0));
    assert!(encryption.stderr.is_empty());

    let mut decryption_command = cli.command();
    decryption_command.args([
        OsString::from("decrypt"),
        OsString::from("--"),
        encrypted_name.clone(),
        output_name.clone(),
    ]);
    let decryption = copied_cli_output(&mut decryption_command);
    assert_eq!(decryption.status.code(), Some(0));
    assert!(decryption.stderr.is_empty());
    assert_eq!(
        fs::read(cli.working_dir.join(output_name)).expect("read non-UTF-8 output"),
        plaintext
    );
    assert_no_temporary_files(&cli.working_dir);
}

#[cfg(unix)]
#[test]
fn cli_escapes_terminal_controls_in_success_and_error_paths() {
    let cli = CopiedCli::new();
    assert_eq!(cli.run(&["keygen"]).status.code(), Some(0));
    let malicious_input = "input-\n-\u{1b}[31m-\u{202e}-name";
    let malicious_output = "encrypted-\r-\u{1b}[2J-name";
    fs::write(cli.working_dir.join(malicious_input), b"plaintext").expect("write input");

    let encryption = cli.run(&["1", malicious_input, malicious_output]);
    assert_eq!(encryption.status.code(), Some(0));
    assert!(encryption.stderr.is_empty());
    let stdout = String::from_utf8(encryption.stdout).expect("UTF-8 stdout");
    assert_eq!(
        stdout
            .chars()
            .filter(|character| *character == '\n')
            .count(),
        1
    );
    assert!(!stdout.contains('\r'));
    assert!(!stdout.contains('\u{1b}'));
    assert!(!stdout.contains('\u{202e}'));
    assert!(stdout.contains("input-\\n-\\u{1b}[31m-\\u{202e}-name"));
    assert!(stdout.contains("encrypted-\\r-\\u{1b}[2J-name"));

    let malicious_missing = "missing-\n-\u{1b}[5m-\u{2066}-name";
    let failure = cli.run(&["2", malicious_missing, "never-created"]);
    assert_eq!(failure.status.code(), Some(1));
    assert!(failure.stdout.is_empty());
    let stderr = String::from_utf8(failure.stderr).expect("UTF-8 stderr");
    assert_eq!(
        stderr
            .chars()
            .filter(|character| *character == '\n')
            .count(),
        1
    );
    assert!(!stderr.contains('\u{1b}'));
    assert!(!stderr.contains('\u{2066}'));
    assert!(stderr.contains("missing-\\n-\\u{1b}[5m-\\u{2066}-name"));
    assert!(!cli.working_dir.join("never-created").exists());
    assert_no_temporary_files(&cli.working_dir);
}

#[cfg(unix)]
#[test]
fn cli_returns_failure_when_standard_output_is_closed() {
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use std::process::Stdio;

    let (reader, writer) = UnixStream::pair().expect("create socket pair");
    drop(reader);
    let writer = OwnedFd::from(writer);
    let output = Command::new(env!("CARGO_BIN_EXE_filecrypt"))
        .arg("--version")
        .stdout(Stdio::from(writer))
        .stderr(Stdio::piped())
        .output()
        .expect("run with closed stdout");
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .starts_with("error: could not write to standard output:")
    );
}

#[test]
fn copied_cli_uses_only_key_beside_executable_and_supports_short_form() {
    let directory = tempfile::tempdir().expect("test directory");
    let executable_dir = directory.path().join("app");
    let working_dir = directory.path().join("working directory");
    fs::create_dir(&executable_dir).expect("create executable directory");
    fs::create_dir(&working_dir).expect("create working directory");

    let source_executable = Path::new(env!("CARGO_BIN_EXE_filecrypt"));
    let executable_name = if cfg!(windows) {
        "filecrypt.exe"
    } else {
        "filecrypt"
    };
    let executable = executable_dir.join(executable_name);
    fs::copy(source_executable, &executable).expect("copy executable");

    let help = copied_cli_output(
        Command::new(&executable)
            .arg("--help")
            .current_dir(&working_dir),
    );
    assert!(help.status.success());

    let keygen = copied_cli_output(
        Command::new(&executable)
            .arg("keygen")
            .current_dir(&working_dir),
    );
    assert!(
        keygen.status.success(),
        "keygen stderr: {}",
        String::from_utf8_lossy(&keygen.stderr)
    );
    assert_eq!(
        fs::metadata(executable_dir.join("key.key"))
            .expect("executable key")
            .len(),
        32
    );

    // A conflicting working-directory key must be ignored.
    write_private(&working_dir.join("key.key"), &[0x77; 32]);
    let input = working_dir.join("input with spaces.bin");
    let decrypted = working_dir.join("decrypted with spaces.bin");
    let independently_decrypted = working_dir.join("independent verification.bin");
    let plaintext = test_bytes(CHUNK_SIZE + 19);
    fs::write(&input, &plaintext).expect("write CLI input");

    let encryption = copied_cli_output(
        Command::new(&executable)
            .args(["2", "input with spaces.bin", "encrypted with spaces.bin"])
            .current_dir(&working_dir),
    );
    assert!(
        encryption.status.success(),
        "encryption stderr: {}",
        String::from_utf8_lossy(&encryption.stderr)
    );

    let executable_key = load_key_file(&executable_dir.join("key.key")).expect("load app key");
    decrypt_file(
        &working_dir.join("encrypted with spaces.bin"),
        &independently_decrypted,
        &executable_key,
    )
    .expect("verify encryption used executable key");
    assert_eq!(
        fs::read(&independently_decrypted).expect("read independent output"),
        plaintext
    );

    // Changing the working-directory key must not affect CLI decryption.
    write_private(&working_dir.join("key.key"), &[0x88; 32]);

    let decryption = copied_cli_output(
        Command::new(&executable)
            .args([
                "decrypt",
                "encrypted with spaces.bin",
                "decrypted with spaces.bin",
            ])
            .current_dir(&working_dir),
    );
    assert!(
        decryption.status.success(),
        "decryption stderr: {}",
        String::from_utf8_lossy(&decryption.stderr)
    );
    assert_eq!(fs::read(&decrypted).expect("read CLI output"), plaintext);

    let overwrite = copied_cli_output(
        Command::new(&executable)
            .args(["2", "input with spaces.bin", "encrypted with spaces.bin"])
            .current_dir(&working_dir),
    );
    assert!(!overwrite.status.success());
    assert!(String::from_utf8_lossy(&overwrite.stderr).contains("refusing to overwrite"));

    // A second executable without an adjacent key must not fall back to CWD.
    let keyless_dir = directory.path().join("keyless-app");
    fs::create_dir(&keyless_dir).expect("create keyless app directory");
    let keyless_executable = keyless_dir.join(executable_name);
    fs::copy(source_executable, &keyless_executable).expect("copy keyless executable");
    let forbidden_output = working_dir.join("must-not-exist.enc");
    let keyless_attempt = copied_cli_output(
        Command::new(&keyless_executable)
            .args(["1", "input with spaces.bin", "must-not-exist.enc"])
            .current_dir(&working_dir),
    );
    assert!(!keyless_attempt.status.success());
    assert!(String::from_utf8_lossy(&keyless_attempt.stderr).contains("key file not found"));
    assert!(!forbidden_output.exists());
}

#[cfg(unix)]
#[test]
fn non_utf8_paths_round_trip() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let directory = tempfile::tempdir().expect("test directory");
    let key = key_with_byte(0x33);
    let input = directory
        .path()
        .join(OsString::from_vec(b"plain-\xff".to_vec()));
    let encrypted = directory
        .path()
        .join(OsString::from_vec(b"encrypted-\xfe".to_vec()));
    let output = directory
        .path()
        .join(OsString::from_vec(b"output-\xfd".to_vec()));
    fs::write(&input, b"non-UTF-8 path contents").expect("write input");
    encrypt_file(Algorithm::Aes256GcmSiv, &input, &encrypted, &key).expect("encrypt");
    decrypt_file(&encrypted, &output, &key).expect("decrypt");
    assert_eq!(
        fs::read(&output).expect("read output"),
        b"non-UTF-8 path contents"
    );
}

fn assert_no_temporary_files(directory: &Path) {
    let leaked = fs::read_dir(directory)
        .expect("list directory")
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.file_name())
        .any(|name| name.to_string_lossy().starts_with(".filecrypt-"));
    assert!(!leaked, "operation leaked a temporary file");
}

fn write_private(path: &Path, contents: &[u8]) {
    fs::write(path, contents).expect("write private test file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("set private mode");
    }
}
