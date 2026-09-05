use std::ffi::OsStr;
use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use std::sync::{Arc, Barrier};
use std::thread;

use tempfile::{TempDir, tempdir};
use threefish1024::{HEADER_LEN, KEY_LEN, TAG_LEN};

fn command(cwd: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_threefish1024"));
    command.current_dir(cwd);
    command
}

fn run<I, S>(cwd: &Path, args: I) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    command(cwd)
        .args(args)
        .output()
        .expect("the CLI process should start")
}

fn diagnostics(output: &Output) -> String {
    format!(
        "status: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn assert_success(output: &Output) {
    assert!(output.status.success(), "{}", diagnostics(output));
}

fn assert_failure(output: &Output) {
    assert!(!output.status.success(), "{}", diagnostics(output));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.is_empty(), "a failure should explain itself");
    assert!(
        !stderr.to_ascii_lowercase().contains("panicked"),
        "{}",
        diagnostics(output)
    );
}

fn write_private(path: &Path, contents: &[u8]) {
    fs::write(path, contents).expect("test file should be writable");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .expect("test file permissions should be settable");
    }
}

fn write_key(dir: &Path, byte: u8) {
    write_private(&dir.join("key.key"), &[byte; KEY_LEN]);
}

fn directory_with_key() -> TempDir {
    let dir = tempdir().expect("temporary directory should be created");
    let output = run(dir.path(), ["keygen"]);
    assert_success(&output);
    dir
}

fn payload(length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| {
            let mixed = index.wrapping_mul(197) ^ index.rotate_left(5) ^ 0xa5;
            mixed.to_le_bytes()[0]
        })
        .collect()
}

fn assert_no_temporary_files(dir: &Path) {
    for entry in fs::read_dir(dir).expect("temporary directory should be readable") {
        let entry = entry.expect("directory entry should be readable");
        let name = entry.file_name();
        let name = name.to_string_lossy();
        assert!(
            !name.starts_with(".threefish-output-") && !name.starts_with(".threefish-key-"),
            "temporary artifact was not cleaned up: {name}"
        );
    }
}

#[test]
fn help_version_and_cli_errors_are_well_behaved() {
    let dir = tempdir().unwrap();

    let help = run(dir.path(), ["--help"]);
    assert_success(&help);
    let help_text = String::from_utf8_lossy(&help.stdout);
    for word in ["encrypt", "decrypt", "keygen", "key.key"] {
        assert!(
            help_text.contains(word),
            "missing {word:?} in help:\n{help_text}"
        );
    }

    let version = run(dir.path(), ["--version"]);
    assert_success(&version);
    assert!(String::from_utf8_lossy(&version.stdout).contains(env!("CARGO_PKG_VERSION")));

    let invalid_invocations: &[&[&str]] = &[
        &[],
        &["not-a-command"],
        &["encrypt"],
        &["encrypt", "only-input"],
        &["encrypt", "in", "out", "extra"],
        &["decrypt"],
        &["decrypt", "only-input"],
        &["decrypt", "in", "out", "extra"],
        &["keygen", "extra"],
        &["encrypt", "--not-an-option", "in", "out"],
    ];
    for args in invalid_invocations {
        let output = run(dir.path(), args.iter().copied());
        assert_failure(&output);
    }

    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[test]
fn keygen_and_requested_kegen_alias_create_binary_keys_without_clobbering() {
    let first = tempdir().unwrap();
    let generated = run(first.path(), ["keygen"]);
    assert_success(&generated);
    assert!(
        generated.stdout.is_empty(),
        "key material must not be printed"
    );
    let first_key = fs::read(first.path().join("key.key")).unwrap();
    assert_eq!(first_key.len(), KEY_LEN);

    let duplicate = run(first.path(), ["keygen"]);
    assert_failure(&duplicate);
    assert!(
        String::from_utf8_lossy(&duplicate.stderr).contains("already exists"),
        "{}",
        diagnostics(&duplicate)
    );
    assert_eq!(fs::read(first.path().join("key.key")).unwrap(), first_key);

    let second = tempdir().unwrap();
    let alias = run(second.path(), ["kegen"]);
    assert_success(&alias);
    let second_key = fs::read(second.path().join("key.key")).unwrap();
    assert_eq!(second_key.len(), KEY_LEN);
    assert_ne!(
        first_key, second_key,
        "independent key generations repeated a key"
    );
    assert_no_temporary_files(first.path());
    assert_no_temporary_files(second.path());
}

#[test]
fn custom_key_option_is_honored() {
    let dir = tempdir().unwrap();
    assert_success(&run(dir.path(), ["--key", "vault.bin", "keygen"]));
    assert!(!dir.path().join("key.key").exists());
    assert_eq!(
        fs::metadata(dir.path().join("vault.bin")).unwrap().len(),
        KEY_LEN as u64
    );

    let original = payload(777);
    fs::write(dir.path().join("plain.bin"), &original).unwrap();
    assert_success(&run(
        dir.path(),
        [
            "--key",
            "vault.bin",
            "encrypt",
            "plain.bin",
            "encrypted.bin",
        ],
    ));
    assert_success(&run(
        dir.path(),
        [
            "decrypt",
            "--key",
            "vault.bin",
            "encrypted.bin",
            "restored.bin",
        ],
    ));
    assert_eq!(fs::read(dir.path().join("restored.bin")).unwrap(), original);
}

#[test]
fn default_key_is_resolved_from_the_process_working_directory() {
    let root = tempdir().unwrap();
    fs::create_dir(root.path().join("work")).unwrap();
    fs::create_dir(root.path().join("data")).unwrap();
    write_key(&root.path().join("data"), 0x31);
    fs::write(root.path().join("data/plain.bin"), payload(193)).unwrap();

    let missing_in_cwd = run(
        &root.path().join("work"),
        ["encrypt", "../data/plain.bin", "../data/encrypted.bin"],
    );
    assert_failure(&missing_in_cwd);
    assert!(!root.path().join("data/encrypted.bin").exists());

    write_key(&root.path().join("work"), 0x31);
    assert_success(&run(
        &root.path().join("work"),
        ["encrypt", "../data/plain.bin", "../data/encrypted.bin"],
    ));
}

#[test]
fn missing_and_invalid_length_keys_never_create_output() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("plain.bin"), b"secret").unwrap();

    let missing = run(dir.path(), ["encrypt", "plain.bin", "encrypted.bin"]);
    assert_failure(&missing);
    assert!(!dir.path().join("encrypted.bin").exists());

    for length in [0_usize, 1, 127, 129, 256] {
        write_private(&dir.path().join("key.key"), &vec![0x6b; length]);
        let output_name = format!("invalid-{length}.bin");
        let result = run(
            dir.path(),
            vec![
                "encrypt".to_owned(),
                "plain.bin".to_owned(),
                output_name.clone(),
            ],
        );
        assert_failure(&result);
        assert!(
            String::from_utf8_lossy(&result.stderr).contains("exactly 128 binary bytes"),
            "{}",
            diagnostics(&result)
        );
        assert!(!dir.path().join(output_name).exists());
    }
}

#[test]
fn round_trips_binary_data_at_cipher_and_io_boundaries() {
    let dir = directory_with_key();
    let lengths = [
        0_usize, 1, 2, 126, 127, 128, 129, 255, 256, 257, 4095, 4096, 4097, 65_535, 65_536, 65_537,
        1_048_707,
    ];

    for length in lengths {
        let original = payload(length);
        let plain = format!("plain-{length}.bin");
        let encrypted = format!("encrypted-{length}.bin");
        let restored = format!("restored-{length}.bin");
        fs::write(dir.path().join(&plain), &original).unwrap();

        let encryption = run(
            dir.path(),
            vec!["encrypt".to_owned(), plain, encrypted.clone()],
        );
        assert_success(&encryption);
        let container = fs::read(dir.path().join(&encrypted)).unwrap();
        assert_eq!(container.len(), HEADER_LEN + length + TAG_LEN);
        assert_ne!(container, original, "container must not equal plaintext");

        let decryption = run(
            dir.path(),
            vec!["decrypt".to_owned(), encrypted, restored.clone()],
        );
        assert_success(&decryption);
        assert_eq!(
            fs::read(dir.path().join(restored)).unwrap(),
            original,
            "round trip failed at length {length}"
        );
    }
}

#[test]
fn encryption_is_randomized_and_does_not_expose_repeated_plaintext_blocks() {
    let dir = directory_with_key();
    let original = vec![0x5a; 128 * 6];
    fs::write(dir.path().join("plain.bin"), &original).unwrap();

    assert_success(&run(dir.path(), ["encrypt", "plain.bin", "first.tfc"]));
    assert_success(&run(dir.path(), ["encrypt", "plain.bin", "second.tfc"]));
    let first = fs::read(dir.path().join("first.tfc")).unwrap();
    let second = fs::read(dir.path().join("second.tfc")).unwrap();
    assert_ne!(first, second, "fresh encryptions must use fresh randomness");

    let ciphertext = &first[HEADER_LEN..HEADER_LEN + original.len()];
    let blocks = ciphertext.as_chunks::<128>().0;
    for pair in blocks.windows(2) {
        assert_ne!(
            pair[0], pair[1],
            "repeated plaintext blocks leaked through encryption"
        );
    }
}

#[test]
fn every_security_relevant_container_region_is_authenticated() {
    let dir = directory_with_key();
    let original = payload(1024);
    fs::write(dir.path().join("plain.bin"), &original).unwrap();
    assert_success(&run(dir.path(), ["encrypt", "plain.bin", "valid.tfc"]));
    let valid = fs::read(dir.path().join("valid.tfc")).unwrap();
    let tag_start = valid.len() - TAG_LEN;
    let mutations = [
        ("magic", 0_usize),
        ("version", 8),
        ("algorithm", 10),
        ("header-length", 12),
        ("reserved", 16),
        ("plaintext-length", 24),
        ("salt", 32),
        ("tweak", 64),
        ("ciphertext-first", HEADER_LEN),
        ("ciphertext-middle", HEADER_LEN + original.len() / 2),
        ("ciphertext-last", HEADER_LEN + original.len() - 1),
        ("tag-first", tag_start),
        ("tag-last", valid.len() - 1),
    ];
    let sentinel = b"pre-existing plaintext must survive";

    for (label, offset) in mutations {
        let mut damaged = valid.clone();
        damaged[offset] ^= 0x80;
        let damaged_name = format!("damaged-{label}.tfc");
        fs::write(dir.path().join(&damaged_name), damaged).unwrap();
        fs::write(dir.path().join("recovered.bin"), sentinel).unwrap();
        let result = run(
            dir.path(),
            vec![
                "decrypt".to_owned(),
                "--force".to_owned(),
                damaged_name,
                "recovered.bin".to_owned(),
            ],
        );
        assert_failure(&result);
        assert_eq!(
            fs::read(dir.path().join("recovered.bin")).unwrap(),
            sentinel,
            "mutation in {label} published unauthenticated plaintext"
        );
    }
    assert_no_temporary_files(dir.path());
}

#[test]
fn a_wrong_key_releases_no_plaintext_and_preserves_forced_destination() {
    let dir = tempdir().unwrap();
    write_key(dir.path(), 0x11);
    fs::write(dir.path().join("plain.bin"), payload(1001)).unwrap();
    assert_success(&run(dir.path(), ["encrypt", "plain.bin", "encrypted.tfc"]));
    write_key(dir.path(), 0x22);

    let absent_destination = run(dir.path(), ["decrypt", "encrypted.tfc", "not-created.bin"]);
    assert_failure(&absent_destination);
    assert!(
        String::from_utf8_lossy(&absent_destination.stderr).contains("authentication failed"),
        "{}",
        diagnostics(&absent_destination)
    );
    assert!(!dir.path().join("not-created.bin").exists());

    let sentinel = b"keep this existing file";
    fs::write(dir.path().join("existing.bin"), sentinel).unwrap();
    let forced = run(
        dir.path(),
        ["decrypt", "--force", "encrypted.tfc", "existing.bin"],
    );
    assert_failure(&forced);
    assert_eq!(fs::read(dir.path().join("existing.bin")).unwrap(), sentinel);
    assert_no_temporary_files(dir.path());
}

#[test]
fn malformed_truncated_and_appended_containers_are_rejected() {
    let dir = directory_with_key();
    fs::write(dir.path().join("plain.bin"), payload(257)).unwrap();
    assert_success(&run(dir.path(), ["encrypt", "plain.bin", "valid.tfc"]));
    let valid = fs::read(dir.path().join("valid.tfc")).unwrap();

    let malformed_lengths = [
        0_usize,
        1,
        7,
        HEADER_LEN - 1,
        HEADER_LEN,
        HEADER_LEN + TAG_LEN - 1,
    ];
    for (case, length) in malformed_lengths.into_iter().enumerate() {
        let input = format!("malformed-{case}.tfc");
        let output = format!("malformed-{case}.out");
        fs::write(dir.path().join(&input), vec![0_u8; length]).unwrap();
        let result = run(
            dir.path(),
            vec!["decrypt".to_owned(), input, output.clone()],
        );
        assert_failure(&result);
        assert!(!dir.path().join(output).exists());
    }

    let mut truncation_points = vec![
        0,
        1,
        7,
        8,
        HEADER_LEN - 1,
        HEADER_LEN,
        valid.len() - TAG_LEN - 1,
        valid.len() - TAG_LEN,
        valid.len() - 1,
    ];
    truncation_points.sort_unstable();
    truncation_points.dedup();
    for (case, length) in truncation_points.into_iter().enumerate() {
        let input = format!("truncated-{case}.tfc");
        let output = format!("truncated-{case}.out");
        fs::write(dir.path().join(&input), &valid[..length]).unwrap();
        let result = run(
            dir.path(),
            vec!["decrypt".to_owned(), input, output.clone()],
        );
        assert_failure(&result);
        assert!(!dir.path().join(output).exists());
    }

    for (case, suffix) in [vec![0x00], vec![0x5a; 128]].into_iter().enumerate() {
        let mut appended = valid.clone();
        appended.extend_from_slice(&suffix);
        let input = format!("appended-{case}.tfc");
        let output = format!("appended-{case}.out");
        fs::write(dir.path().join(&input), appended).unwrap();
        let result = run(
            dir.path(),
            vec!["decrypt".to_owned(), input, output.clone()],
        );
        assert_failure(&result);
        assert!(!dir.path().join(output).exists());
    }

    let mut overflowing_length = valid.clone();
    overflowing_length[24..32].copy_from_slice(&u64::MAX.to_le_bytes());
    fs::write(
        dir.path().join("overflowing-length.tfc"),
        overflowing_length,
    )
    .unwrap();
    let overflow = run(
        dir.path(),
        ["decrypt", "overflowing-length.tfc", "overflow.out"],
    );
    assert_failure(&overflow);
    assert!(!dir.path().join("overflow.out").exists());
    assert_no_temporary_files(dir.path());
}

#[test]
fn no_clobber_is_default_and_force_atomically_replaces_outputs() {
    let dir = directory_with_key();
    let original = payload(513);
    let sentinel = b"existing destination";
    fs::write(dir.path().join("plain.bin"), &original).unwrap();
    fs::write(dir.path().join("encrypted.tfc"), sentinel).unwrap();

    let refused_encryption = run(dir.path(), ["encrypt", "plain.bin", "encrypted.tfc"]);
    assert_failure(&refused_encryption);
    assert_eq!(
        fs::read(dir.path().join("encrypted.tfc")).unwrap(),
        sentinel
    );

    assert_success(&run(
        dir.path(),
        ["encrypt", "--force", "plain.bin", "encrypted.tfc"],
    ));
    assert_ne!(
        fs::read(dir.path().join("encrypted.tfc")).unwrap(),
        sentinel
    );

    fs::write(dir.path().join("restored.bin"), sentinel).unwrap();
    let refused_decryption = run(dir.path(), ["decrypt", "encrypted.tfc", "restored.bin"]);
    assert_failure(&refused_decryption);
    assert_eq!(fs::read(dir.path().join("restored.bin")).unwrap(), sentinel);

    assert_success(&run(
        dir.path(),
        ["decrypt", "--force", "encrypted.tfc", "restored.bin"],
    ));
    assert_eq!(fs::read(dir.path().join("restored.bin")).unwrap(), original);
}

#[test]
fn lexical_aliases_and_the_master_key_are_protected_even_with_force() {
    let dir = tempdir().unwrap();
    write_key(dir.path(), 0x47);
    let key_before = fs::read(dir.path().join("key.key")).unwrap();
    let plain_before = payload(321);
    fs::write(dir.path().join("plain.bin"), &plain_before).unwrap();

    let same_path = run(dir.path(), ["encrypt", "--force", "plain.bin", "plain.bin"]);
    assert_failure(&same_path);
    assert_eq!(
        fs::read(dir.path().join("plain.bin")).unwrap(),
        plain_before
    );

    let key_as_input = run(
        dir.path(),
        ["encrypt", "--force", "key.key", "key-copy.tfc"],
    );
    assert_failure(&key_as_input);
    assert!(!dir.path().join("key-copy.tfc").exists());

    let key_as_output = run(dir.path(), ["encrypt", "--force", "plain.bin", "key.key"]);
    assert_failure(&key_as_output);
    assert_eq!(fs::read(dir.path().join("key.key")).unwrap(), key_before);
}

#[test]
fn unusual_but_valid_paths_and_option_terminator_work() {
    let dir = directory_with_key();
    let original = payload(999);
    fs::write(dir.path().join("plain text-雪.bin"), &original).unwrap();

    assert_success(&run(
        dir.path(),
        ["encrypt", "plain text-雪.bin", "encrypted data-☃.tfc"],
    ));
    assert_success(&run(
        dir.path(),
        ["decrypt", "encrypted data-☃.tfc", "restored text-雪.bin"],
    ));
    assert_eq!(
        fs::read(dir.path().join("restored text-雪.bin")).unwrap(),
        original
    );

    fs::write(dir.path().join("-plain.bin"), &original).unwrap();
    assert_success(&run(
        dir.path(),
        ["encrypt", "--", "-plain.bin", "-encrypted.tfc"],
    ));
    assert_success(&run(
        dir.path(),
        ["decrypt", "--", "-encrypted.tfc", "-restored.bin"],
    ));
    assert_eq!(
        fs::read(dir.path().join("-restored.bin")).unwrap(),
        original
    );
}

#[test]
fn missing_special_and_unusable_filesystem_paths_fail_cleanly() {
    let dir = directory_with_key();

    let missing_input = run(dir.path(), ["encrypt", "missing.bin", "output.tfc"]);
    assert_failure(&missing_input);
    assert!(!dir.path().join("output.tfc").exists());

    fs::create_dir(dir.path().join("input-directory")).unwrap();
    let directory_input = run(
        dir.path(),
        ["encrypt", "input-directory", "directory-output.tfc"],
    );
    assert_failure(&directory_input);
    assert!(!dir.path().join("directory-output.tfc").exists());

    fs::write(dir.path().join("plain.bin"), b"data").unwrap();
    let missing_parent = run(
        dir.path(),
        ["encrypt", "plain.bin", "missing-parent/output.tfc"],
    );
    assert_failure(&missing_parent);
    assert!(!dir.path().join("missing-parent").exists());

    fs::create_dir(dir.path().join("output-directory")).unwrap();
    let directory_output = run(
        dir.path(),
        ["encrypt", "--force", "plain.bin", "output-directory"],
    );
    assert_failure(&directory_output);
    assert!(dir.path().join("output-directory").is_dir());
    assert_no_temporary_files(dir.path());
}

#[test]
fn concurrent_no_clobber_publication_has_exactly_one_winner() {
    let dir = tempdir().unwrap();
    let cwd = dir.path().to_path_buf();
    let barrier = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let cwd = cwd.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            run(&cwd, ["keygen"])
        }));
    }
    let keygen_results: Vec<Output> = handles
        .into_iter()
        .map(|handle| handle.join().expect("keygen thread should not panic"))
        .collect();
    assert_eq!(
        keygen_results
            .iter()
            .filter(|output| output.status.success())
            .count(),
        1,
        "concurrent keygen results: {keygen_results:?}"
    );
    assert_eq!(
        fs::metadata(dir.path().join("key.key")).unwrap().len(),
        KEY_LEN as u64
    );

    fs::write(dir.path().join("plain.bin"), payload(8193)).unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let cwd = cwd.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            run(&cwd, ["encrypt", "plain.bin", "shared.tfc"])
        }));
    }
    let encryption_results: Vec<Output> = handles
        .into_iter()
        .map(|handle| handle.join().expect("encryption thread should not panic"))
        .collect();
    assert_eq!(
        encryption_results
            .iter()
            .filter(|output| output.status.success())
            .count(),
        1,
        "concurrent encryption results: {encryption_results:?}"
    );
    assert_success(&run(dir.path(), ["decrypt", "shared.tfc", "restored.bin"]));
    assert_eq!(
        fs::read(dir.path().join("restored.bin")).unwrap(),
        payload(8193)
    );
    assert_no_temporary_files(dir.path());
}

#[cfg(unix)]
#[test]
fn generated_keys_and_outputs_have_private_permissions_and_insecure_keys_fail() {
    use std::os::unix::fs::PermissionsExt;

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    let dir = directory_with_key();
    assert_eq!(mode(&dir.path().join("key.key")), 0o600);
    fs::write(dir.path().join("plain.bin"), payload(100)).unwrap();
    assert_success(&run(dir.path(), ["encrypt", "plain.bin", "encrypted.tfc"]));
    assert_success(&run(
        dir.path(),
        ["decrypt", "encrypted.tfc", "restored.bin"],
    ));
    assert_eq!(mode(&dir.path().join("encrypted.tfc")), 0o600);
    assert_eq!(mode(&dir.path().join("restored.bin")), 0o600);

    fs::set_permissions(
        dir.path().join("key.key"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let insecure = run(dir.path(), ["encrypt", "plain.bin", "rejected.tfc"]);
    assert_failure(&insecure);
    assert!(
        String::from_utf8_lossy(&insecure.stderr).contains("insecure permissions"),
        "{}",
        diagnostics(&insecure)
    );
    assert!(!dir.path().join("rejected.tfc").exists());
}

#[cfg(unix)]
#[test]
fn symlink_and_hardlink_aliases_cannot_bypass_path_protection() {
    use std::os::unix::fs::symlink;

    let dir = tempdir().unwrap();
    write_key(dir.path(), 0x93);
    let key_before = fs::read(dir.path().join("key.key")).unwrap();
    let plain_before = payload(400);
    fs::write(dir.path().join("plain.bin"), &plain_before).unwrap();

    fs::hard_link(
        dir.path().join("plain.bin"),
        dir.path().join("plain-hardlink"),
    )
    .unwrap();
    let hardlink_output = run(
        dir.path(),
        ["encrypt", "--force", "plain.bin", "plain-hardlink"],
    );
    assert_failure(&hardlink_output);
    assert_eq!(
        fs::read(dir.path().join("plain.bin")).unwrap(),
        plain_before
    );

    fs::hard_link(dir.path().join("key.key"), dir.path().join("key-hardlink")).unwrap();
    let hardlink_key = run(
        dir.path(),
        ["encrypt", "key-hardlink", "hardlink-key-output.tfc"],
    );
    assert_failure(&hardlink_key);
    assert!(!dir.path().join("hardlink-key-output.tfc").exists());

    symlink("key.key", dir.path().join("key-link")).unwrap();
    let symlink_key = run(
        dir.path(),
        [
            "--key",
            "key-link",
            "encrypt",
            "plain.bin",
            "symlink-key-output.tfc",
        ],
    );
    assert_failure(&symlink_key);
    assert!(!dir.path().join("symlink-key-output.tfc").exists());

    symlink("key.key", dir.path().join("key-output-link")).unwrap();
    let linked_key_output = run(
        dir.path(),
        ["encrypt", "--force", "plain.bin", "key-output-link"],
    );
    assert_failure(&linked_key_output);
    assert_eq!(fs::read(dir.path().join("key.key")).unwrap(), key_before);

    symlink("plain.bin", dir.path().join("plain-output-link")).unwrap();
    let linked_input_output = run(
        dir.path(),
        ["encrypt", "--force", "plain.bin", "plain-output-link"],
    );
    assert_failure(&linked_input_output);
    assert_eq!(
        fs::read(dir.path().join("plain.bin")).unwrap(),
        plain_before
    );

    fs::write(dir.path().join("unrelated-victim"), b"victim must survive").unwrap();
    symlink("unrelated-victim", dir.path().join("safe-output-link")).unwrap();
    assert_success(&run(
        dir.path(),
        ["encrypt", "--force", "plain.bin", "safe-output-link"],
    ));
    assert_eq!(
        fs::read(dir.path().join("unrelated-victim")).unwrap(),
        b"victim must survive"
    );
    assert!(
        !fs::symlink_metadata(dir.path().join("safe-output-link"))
            .unwrap()
            .file_type()
            .is_symlink(),
        "--force should replace the destination link, not its target"
    );

    symlink("unrelated-victim", dir.path().join("new-key-link")).unwrap();
    let keygen_link = run(dir.path(), ["--key", "new-key-link", "keygen"]);
    assert_failure(&keygen_link);
    assert_eq!(
        fs::read(dir.path().join("unrelated-victim")).unwrap(),
        b"victim must survive"
    );
}

#[cfg(unix)]
#[test]
fn non_utf8_paths_round_trip() {
    use std::os::unix::ffi::OsStringExt;

    let dir = directory_with_key();
    let input_name = std::ffi::OsString::from_vec(b"plain-\xff.bin".to_vec());
    let encrypted_name = std::ffi::OsString::from_vec(b"encrypted-\xfe.tfc".to_vec());
    let restored_name = std::ffi::OsString::from_vec(b"restored-\xfd.bin".to_vec());
    let original = payload(333);
    fs::write(dir.path().join(&input_name), &original).unwrap();

    let encryption = command(dir.path())
        .arg("encrypt")
        .arg(&input_name)
        .arg(&encrypted_name)
        .output()
        .unwrap();
    assert_success(&encryption);
    let decryption = command(dir.path())
        .arg("decrypt")
        .arg(&encrypted_name)
        .arg(&restored_name)
        .output()
        .unwrap();
    assert_success(&decryption);
    assert_eq!(fs::read(dir.path().join(restored_name)).unwrap(), original);
}
