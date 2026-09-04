use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT_TEMP_ID: AtomicUsize = AtomicUsize::new(0);

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(label: &str) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();

        for _ in 0..100 {
            let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "otp1-cli-{label}-{}-{timestamp}-{id}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Self { path },
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("failed to create test directory {path:?}: {error}"),
            }
        }

        panic!("could not allocate a unique temporary test directory");
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct Fixture {
    _temp: TempDir,
    root: PathBuf,
    bin_dir: PathBuf,
    work_dir: PathBuf,
    executable: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let temp = TempDir::new(label);
        let root = temp.path.clone();
        // Every test exercises executable-relative lookup through a path which is
        // distinct from the working directory and contains both spaces and Unicode.
        let bin_dir = root.join("bin with spaces λ");
        let work_dir = root.join("working directory");
        fs::create_dir(&bin_dir).expect("create isolated executable directory");
        fs::create_dir(&work_dir).expect("create isolated working directory");

        let source = PathBuf::from(env!("CARGO_BIN_EXE_otp1"));
        let executable = bin_dir.join(
            source
                .file_name()
                .expect("Cargo-provided binary path has a filename"),
        );
        fs::copy(&source, &executable).unwrap_or_else(|error| {
            panic!("failed to copy test executable from {source:?} to {executable:?}: {error}")
        });

        Self {
            _temp: temp,
            root,
            bin_dir,
            work_dir,
            executable,
        }
    }

    fn key_path(&self) -> PathBuf {
        self.bin_dir.join("key.key")
    }

    fn write_key(&self, bytes: &[u8]) {
        fs::write(self.key_path(), bytes).expect("write adjacent key file");
    }

    fn input_path(&self, relative: impl AsRef<Path>) -> PathBuf {
        self.work_dir.join(relative)
    }

    fn write_input(&self, relative: impl AsRef<Path>, bytes: &[u8]) -> PathBuf {
        let path = self.input_path(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create input parent directory");
        }
        fs::write(&path, bytes)
            .unwrap_or_else(|error| panic!("failed to write test input {path:?}: {error}"));
        path
    }

    fn command(&self) -> Command {
        let mut command = Command::new(&self.executable);
        command.current_dir(&self.work_dir);
        command
    }

    fn run<I, S>(&self, args: I) -> Output
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let args: Vec<OsString> = args
            .into_iter()
            .map(|argument| argument.as_ref().to_os_string())
            .collect();
        for attempt in 0..100 {
            match self.command().args(&args).output() {
                Ok(output) => return output,
                Err(error)
                    if error.kind() == io::ErrorKind::ExecutableFileBusy && attempt != 99 =>
                {
                    // Some overlay filesystems briefly report ETXTBSY when
                    // several freshly copied test executables start in parallel.
                    std::thread::yield_now();
                }
                Err(error) => panic!("launch isolated otp1 executable: {error}"),
            }
        }
        unreachable!("the final launch attempt always returns or panics")
    }
}

#[track_caller]
fn assert_exit_code(output: &Output, expected: i32) {
    assert_eq!(
        output.status.code(),
        Some(expected),
        "unexpected exit status\nstdout: {:?}\nstderr: {:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[track_caller]
fn assert_success_quiet(output: &Output) {
    assert_exit_code(output, 0);
    assert!(
        output.stdout.is_empty(),
        "successful invocation wrote stdout: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        output.stderr.is_empty(),
        "successful invocation wrote stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[track_caller]
fn assert_runtime_error(output: &Output) {
    assert_exit_code(output, 1);
    assert!(
        output.stdout.is_empty(),
        "runtime failure wrote stdout: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        !output.stderr.is_empty(),
        "runtime failure should explain itself on stderr"
    );
}

#[track_caller]
fn assert_usage_error(output: &Output) {
    assert_exit_code(output, 2);
    assert!(
        !output.stderr.is_empty(),
        "usage failure should explain itself on stderr"
    );
}

fn xor_reference(input: &[u8], key: &[u8]) -> Vec<u8> {
    assert!(key.len() >= input.len());
    input
        .iter()
        .zip(key)
        .map(|(&plain, &pad)| plain ^ pad)
        .collect()
}

fn pseudo_random_bytes(length: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    let mut bytes = Vec::with_capacity(length);
    for _ in 0..length {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        bytes.push((state >> 24) as u8);
    }
    bytes
}

fn directory_entries(path: &Path) -> Vec<OsString> {
    let mut entries: Vec<_> = fs::read_dir(path)
        .unwrap_or_else(|error| panic!("read directory {path:?}: {error}"))
        .map(|entry| entry.expect("read directory entry").file_name())
        .collect();
    entries.sort();
    entries
}

#[test]
fn encrypts_known_answer_with_an_exact_length_key_and_is_quiet() {
    let fixture = Fixture::new("known-answer");
    let input_bytes = [0x00, 0xff, 0x55, 0xaa, 0x10];
    let key = [0xff, 0x0f, 0xaa, 0x55, 0x10];
    let input = fixture.write_input("payload.bin", &input_bytes);
    fixture.write_key(&key);

    let output = fixture.run([input.as_os_str()]);

    assert_success_quiet(&output);
    assert_eq!(fs::read(input).unwrap(), [0xff, 0xf0, 0xff, 0xff, 0x00]);
    assert_eq!(fs::read(fixture.key_path()).unwrap(), key);
}

#[test]
fn accepts_a_longer_key_and_ignores_its_unused_suffix() {
    let fixture = Fixture::new("long-key");
    let input_bytes = b"only this many bytes";
    let prefix = pseudo_random_bytes(input_bytes.len(), 0x1234_5678);
    let input = fixture.write_input("payload.bin", input_bytes);

    let mut first_key = prefix.clone();
    first_key.extend_from_slice(b"first unused suffix");
    fixture.write_key(&first_key);
    let first = fixture.run([input.as_os_str()]);
    assert_success_quiet(&first);
    let first_ciphertext = fs::read(&input).unwrap();

    fs::write(&input, input_bytes).unwrap();
    let mut second_key = prefix.clone();
    second_key.extend_from_slice(b"a completely different and longer suffix");
    fixture.write_key(&second_key);
    let second = fixture.run([input.as_os_str()]);
    assert_success_quiet(&second);

    assert_eq!(fs::read(&input).unwrap(), first_ciphertext);
    assert_eq!(first_ciphertext, xor_reference(input_bytes, &prefix));
    assert_eq!(fs::read(fixture.key_path()).unwrap(), second_key);
}

#[test]
fn read_only_key_is_accepted_without_mutating_contents_or_metadata() {
    let fixture = Fixture::new("read-only-key-preservation");
    let original = pseudo_random_bytes(131_075, 0x5eed_cafe_1020_3040);
    let key = pseudo_random_bytes(original.len() + 257, 0x0bad_f00d_5566_7788);
    let expected = xor_reference(&original, &key);
    let input = fixture.write_input("payload.bin", &original);
    let key_path = fixture.key_path();
    fixture.write_key(&key);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o400)).unwrap();
    }
    #[cfg(windows)]
    {
        let mut permissions = fs::metadata(&key_path).unwrap().permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&key_path, permissions).unwrap();
    }

    let key_before = fs::metadata(&key_path).unwrap();
    let output = fixture.run([input.as_os_str()]);

    assert_success_quiet(&output);
    assert_eq!(fs::read(&input).unwrap(), expected);
    assert_eq!(fs::read(&key_path).unwrap(), key);

    let key_after = fs::metadata(&key_path).unwrap();
    assert_eq!(key_after.len(), key_before.len());
    assert_eq!(
        key_after.permissions().readonly(),
        key_before.permissions().readonly()
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        assert_eq!(key_after.dev(), key_before.dev());
        assert_eq!(key_after.ino(), key_before.ino());
        assert_eq!(key_after.mode(), key_before.mode());
        assert_eq!(key_after.mtime(), key_before.mtime());
        assert_eq!(key_after.mtime_nsec(), key_before.mtime_nsec());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;

        assert_eq!(key_after.file_attributes(), key_before.file_attributes());
        assert_eq!(key_after.last_write_time(), key_before.last_write_time());

        // Let the fixture remove its directory on Windows, where a read-only
        // attribute can otherwise prevent cleanup.
        let mut permissions = key_after.permissions();
        permissions.set_readonly(false);
        fs::set_permissions(&key_path, permissions).unwrap();
    }
}

#[test]
fn empty_input_accepts_an_empty_key() {
    let fixture = Fixture::new("empty-empty");
    let input = fixture.write_input("empty.bin", b"");
    fixture.write_key(b"");

    let output = fixture.run([input.as_os_str()]);

    assert_success_quiet(&output);
    assert_eq!(fs::read(input).unwrap(), b"");
    assert_eq!(fs::read(fixture.key_path()).unwrap(), b"");
}

#[test]
fn empty_input_accepts_a_nonempty_key_without_consuming_it() {
    let fixture = Fixture::new("empty-long-key");
    let input = fixture.write_input("empty.bin", b"");
    let key = b"the entire key is an unused suffix";
    fixture.write_key(key);

    let output = fixture.run([input.as_os_str()]);

    assert_success_quiet(&output);
    assert_eq!(fs::read(input).unwrap(), b"");
    assert_eq!(fs::read(fixture.key_path()).unwrap(), key);
}

#[test]
fn handles_single_byte_files() {
    let fixture = Fixture::new("single-byte");
    let input = fixture.write_input("single.bin", &[0xa5]);
    fixture.write_key(&[0x3c]);

    let output = fixture.run([input.as_os_str()]);

    assert_success_quiet(&output);
    assert_eq!(fs::read(input).unwrap(), [0x99]);
}

#[test]
fn handles_every_possible_byte_value() {
    let fixture = Fixture::new("every-byte");
    let input_bytes: Vec<u8> = (0..=u8::MAX).collect();
    let key: Vec<u8> = (0..=u8::MAX).rev().collect();
    let expected = xor_reference(&input_bytes, &key);
    let input = fixture.write_input("all-bytes.bin", &input_bytes);
    fixture.write_key(&key);

    let output = fixture.run([input.as_os_str()]);

    assert_success_quiet(&output);
    assert_eq!(fs::read(input).unwrap(), expected);
}

#[test]
fn handles_every_plaintext_and_key_byte_pair() {
    let fixture = Fixture::new("all-byte-pairs");
    let mut input_bytes = Vec::with_capacity(256 * 256);
    let mut key = Vec::with_capacity(256 * 256);
    for plain in 0..=u8::MAX {
        for pad in 0..=u8::MAX {
            input_bytes.push(plain);
            key.push(pad);
        }
    }
    let expected = xor_reference(&input_bytes, &key);
    let input = fixture.write_input("all-pairs.bin", &input_bytes);
    fixture.write_key(&key);

    let output = fixture.run([input.as_os_str()]);

    assert_success_quiet(&output);
    assert_eq!(fs::read(input).unwrap(), expected);
}

#[test]
fn a_zero_key_leaves_every_input_byte_unchanged() {
    let fixture = Fixture::new("zero-key");
    let input_bytes = pseudo_random_bytes(32_769, 0xaabb_ccdd_eeff_0011);
    let input = fixture.write_input("payload.bin", &input_bytes);
    fixture.write_key(&vec![0; input_bytes.len()]);

    let output = fixture.run([input.as_os_str()]);

    assert_success_quiet(&output);
    assert_eq!(fs::read(input).unwrap(), input_bytes);
}

#[test]
fn zero_plaintext_becomes_the_key_prefix() {
    let fixture = Fixture::new("zero-plaintext");
    let input_bytes = vec![0; 16_385];
    let mut key = pseudo_random_bytes(input_bytes.len(), 0x0ddc_0ffe_e123_4567);
    key.extend_from_slice(b"unused");
    let input = fixture.write_input("payload.bin", &input_bytes);
    fixture.write_key(&key);

    let output = fixture.run([input.as_os_str()]);

    assert_success_quiet(&output);
    assert_eq!(fs::read(input).unwrap(), key[..input_bytes.len()]);
}

#[test]
fn applying_the_same_key_twice_restores_the_original() {
    let fixture = Fixture::new("round-trip");
    let original = pseudo_random_bytes(131_073, 0xdead_beef_cafe_babe);
    let key = pseudo_random_bytes(original.len() + 31, 0x1234_0000_abcd_9999);
    let input = fixture.write_input("round-trip.bin", &original);
    fixture.write_key(&key);

    let encrypt = fixture.run([input.as_os_str()]);
    assert_success_quiet(&encrypt);
    let ciphertext = fs::read(&input).unwrap();
    assert_eq!(ciphertext, xor_reference(&original, &key));
    assert_ne!(ciphertext, original);

    let decrypt = fixture.run([input.as_os_str()]);
    assert_success_quiet(&decrypt);
    assert_eq!(fs::read(&input).unwrap(), original);
    assert_eq!(fs::read(fixture.key_path()).unwrap(), key);
}

#[test]
fn works_across_common_io_buffer_boundaries() {
    let fixture = Fixture::new("buffer-boundaries");
    let sizes = [
        0, 1, 2, 3, 255, 256, 257, 4095, 4096, 4097, 8191, 8192, 8193, 16_383, 16_384, 16_385,
        65_535, 65_536, 65_537,
    ];

    for (case, size) in sizes.into_iter().enumerate() {
        let input_bytes = pseudo_random_bytes(size, 0x1000 + case as u64);
        let key = pseudo_random_bytes(size + 17, 0x9000 + case as u64);
        let input = fixture.write_input(format!("boundary-{size}.bin"), &input_bytes);
        fixture.write_key(&key);

        let output = fixture.run([input.as_os_str()]);
        assert_success_quiet(&output);
        assert_eq!(
            fs::read(&input).unwrap(),
            xor_reference(&input_bytes, &key),
            "incorrect result at size {size}"
        );
    }
}

#[test]
fn agrees_with_reference_for_many_deterministic_random_cases() {
    let fixture = Fixture::new("random-cases");

    for case in 0..48_u64 {
        let size = ((case * 7919 + case * case * 17) % 50_000) as usize;
        let extra_key_bytes = (case % 97) as usize;
        let input_bytes = pseudo_random_bytes(size, 0x0102_0304_0506_0708 ^ case);
        let key = pseudo_random_bytes(
            size + extra_key_bytes,
            0xf0e0_d0c0_b0a0_9080 ^ case.rotate_left(11),
        );
        let input = fixture.write_input(format!("random-{case}.bin"), &input_bytes);
        fixture.write_key(&key);

        let output = fixture.run([input.as_os_str()]);
        assert_success_quiet(&output);
        assert_eq!(
            fs::read(&input).unwrap(),
            xor_reference(&input_bytes, &key),
            "reference mismatch for deterministic random case {case}"
        );
    }
}

#[test]
fn handles_a_multi_megabyte_binary_file() {
    let fixture = Fixture::new("large-file");
    let input_bytes = pseudo_random_bytes(4 * 1024 * 1024 + 3, 0x5555_aaaa_1234_9876);
    let key = pseudo_random_bytes(input_bytes.len() + 1024, 0x1111_2222_3333_4444);
    let expected = xor_reference(&input_bytes, &key);
    let input = fixture.write_input("large.bin", &input_bytes);
    fixture.write_key(&key);

    let output = fixture.run([input.as_os_str()]);

    assert_success_quiet(&output);
    assert_eq!(fs::read(input).unwrap(), expected);
}

#[test]
fn short_key_by_one_byte_fails_without_any_input_replacement() {
    let fixture = Fixture::new("short-key-by-one");
    let original = pseudo_random_bytes(4097, 0x44);
    let key = pseudo_random_bytes(original.len() - 1, 0x55);
    let input = fixture.write_input("payload.bin", &original);
    fixture.write_key(&key);
    let input_metadata_before = fs::metadata(&input).unwrap();
    let modified_before = input_metadata_before.modified().ok();
    let work_entries_before = directory_entries(&fixture.work_dir);
    let bin_entries_before = directory_entries(&fixture.bin_dir);

    let output = fixture.run([input.as_os_str()]);

    assert_runtime_error(&output);
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("key is too short"),
        "short-key diagnostic missing from stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read(&input).unwrap(), original);
    assert_eq!(fs::read(fixture.key_path()).unwrap(), key);
    let input_metadata_after = fs::metadata(&input).unwrap();
    assert_eq!(input_metadata_after.len(), input_metadata_before.len());
    assert_eq!(input_metadata_after.modified().ok(), modified_before);
    assert_eq!(directory_entries(&fixture.work_dir), work_entries_before);
    assert_eq!(directory_entries(&fixture.bin_dir), bin_entries_before);

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(input_metadata_after.dev(), input_metadata_before.dev());
        assert_eq!(input_metadata_after.ino(), input_metadata_before.ino());
        assert_eq!(input_metadata_after.mode(), input_metadata_before.mode());
    }
}

#[test]
fn short_key_diagnostic_reports_exact_sizes_without_disclosing_key_material() {
    const SECRET_CANARY: &[u8] = b"OTP1_SECRET_KEY_CANARY_7b4f_DO_NOT_PRINT";

    let fixture = Fixture::new("short-key-redaction");
    let original = vec![0xa6; SECRET_CANARY.len() + 37];
    let input = fixture.write_input("payload.bin", &original);
    fixture.write_key(SECRET_CANARY);
    let work_entries_before = directory_entries(&fixture.work_dir);
    let bin_entries_before = directory_entries(&fixture.bin_dir);

    let output = fixture.run([input.as_os_str()]);

    assert_runtime_error(&output);
    let diagnostic = String::from_utf8_lossy(&output.stderr);
    let expected_sizes = format!(
        "has {} bytes but the input needs {}",
        SECRET_CANARY.len(),
        original.len()
    );
    assert!(
        diagnostic.contains(&expected_sizes),
        "short-key diagnostic did not report exact sizes: {diagnostic:?}"
    );
    for secret_fragment in [
        SECRET_CANARY,
        b"OTP1_SECRET_KEY_CANARY".as_slice(),
        b"7b4f_DO_NOT_PRINT".as_slice(),
    ] {
        assert!(
            !output
                .stderr
                .windows(secret_fragment.len())
                .any(|window| window == secret_fragment),
            "short-key diagnostic disclosed key material: {diagnostic:?}"
        );
    }
    assert_eq!(fs::read(&input).unwrap(), original);
    assert_eq!(fs::read(fixture.key_path()).unwrap(), SECRET_CANARY);
    assert_eq!(directory_entries(&fixture.work_dir), work_entries_before);
    assert_eq!(directory_entries(&fixture.bin_dir), bin_entries_before);
}

#[test]
fn empty_key_rejects_nonempty_input_without_modification() {
    let fixture = Fixture::new("empty-short-key");
    let original = b"not empty";
    let input = fixture.write_input("payload.bin", original);
    fixture.write_key(b"");

    let output = fixture.run([input.as_os_str()]);

    assert_runtime_error(&output);
    assert!(String::from_utf8_lossy(&output.stderr).contains("key is too short"));
    assert_eq!(fs::read(input).unwrap(), original);
}

#[test]
fn short_keys_fail_at_multiple_boundaries_and_leave_inputs_untouched() {
    let fixture = Fixture::new("short-key-boundaries");
    for (case, size) in [1, 2, 256, 4096, 4097, 8192, 65_536]
        .into_iter()
        .enumerate()
    {
        let original = pseudo_random_bytes(size, 0x7000 + case as u64);
        let key = pseudo_random_bytes(size - 1, 0x8000 + case as u64);
        let input = fixture.write_input(format!("short-{size}.bin"), &original);
        fixture.write_key(&key);

        let output = fixture.run([input.as_os_str()]);

        assert_runtime_error(&output);
        assert!(String::from_utf8_lossy(&output.stderr).contains("key is too short"));
        assert_eq!(
            fs::read(input).unwrap(),
            original,
            "input changed at size {size}"
        );
        assert_eq!(fs::read(fixture.key_path()).unwrap(), key);
    }
}

#[test]
fn missing_adjacent_key_does_not_fall_back_to_cwd_key() {
    let fixture = Fixture::new("ignore-cwd-key");
    let original = b"must remain plaintext";
    let input = fixture.write_input("payload.bin", original);
    let cwd_key = vec![0x77; original.len() + 20];
    fs::write(fixture.work_dir.join("key.key"), &cwd_key).unwrap();

    let output = fixture.run([input.as_os_str()]);

    assert_runtime_error(&output);
    assert_eq!(fs::read(input).unwrap(), original);
    assert_eq!(fs::read(fixture.work_dir.join("key.key")).unwrap(), cwd_key);
    assert!(!fixture.key_path().exists());
}

#[test]
fn adjacent_key_wins_over_a_different_cwd_key() {
    let fixture = Fixture::new("adjacent-wins");
    let original = b"choose the correct key";
    let adjacent_key = vec![0xa5; original.len()];
    let cwd_key = vec![0x5a; original.len()];
    let input = fixture.write_input("payload.bin", original);
    fixture.write_key(&adjacent_key);
    fs::write(fixture.work_dir.join("key.key"), &cwd_key).unwrap();

    let output = fixture.run([input.as_os_str()]);

    assert_success_quiet(&output);
    assert_eq!(
        fs::read(input).unwrap(),
        xor_reference(original, &adjacent_key)
    );
    assert_eq!(fs::read(fixture.work_dir.join("key.key")).unwrap(), cwd_key);
    assert_eq!(fs::read(fixture.key_path()).unwrap(), adjacent_key);
}

#[test]
fn a_directory_at_the_key_path_is_a_runtime_error() {
    let fixture = Fixture::new("key-directory");
    fs::create_dir(fixture.key_path()).unwrap();
    let original = b"unchanged";
    let input = fixture.write_input("payload.bin", original);

    let output = fixture.run([input.as_os_str()]);

    assert_runtime_error(&output);
    assert_eq!(fs::read(input).unwrap(), original);
    assert!(fixture.key_path().is_dir());
}

#[test]
fn missing_input_is_a_runtime_error() {
    let fixture = Fixture::new("missing-input");
    fixture.write_key(b"a sufficiently long key");
    let missing = fixture.input_path("does-not-exist.bin");

    let output = fixture.run([missing.as_os_str()]);

    assert_runtime_error(&output);
    assert!(!missing.exists());
}

#[test]
fn an_input_directory_is_rejected_without_changing_it() {
    let fixture = Fixture::new("input-directory");
    fixture.write_key(&[0x88; 128]);
    let input = fixture.input_path("input-dir");
    fs::create_dir(&input).unwrap();
    fs::write(input.join("sentinel"), b"do not touch").unwrap();

    let output = fixture.run([input.as_os_str()]);

    assert_runtime_error(&output);
    assert_eq!(fs::read(input.join("sentinel")).unwrap(), b"do not touch");
}

#[test]
fn input_that_is_the_key_file_itself_is_rejected() {
    let fixture = Fixture::new("input-is-key");
    let key = pseudo_random_bytes(1024, 0xabcdef);
    fixture.write_key(&key);
    let entries_before = directory_entries(&fixture.bin_dir);

    let output = fixture.run([fixture.key_path().as_os_str()]);

    assert_runtime_error(&output);
    assert_eq!(fs::read(fixture.key_path()).unwrap(), key);
    assert_eq!(directory_entries(&fixture.bin_dir), entries_before);
}

#[test]
fn hardlink_alias_of_the_key_is_rejected() {
    let fixture = Fixture::new("hardlink-key-alias");
    let key = pseudo_random_bytes(2048, 0x1111_aaaa);
    fixture.write_key(&key);
    let alias = fixture.input_path("key-alias.bin");
    fs::hard_link(fixture.key_path(), &alias).expect("create hardlink alias of key");

    let output = fixture.run([alias.as_os_str()]);

    assert_runtime_error(&output);
    assert_eq!(fs::read(&alias).unwrap(), key);
    assert_eq!(fs::read(fixture.key_path()).unwrap(), key);
}

#[test]
fn hardlinked_input_is_rejected_and_every_link_remains_plaintext() {
    let fixture = Fixture::new("hardlinked-input");
    let original = pseudo_random_bytes(4096, 0x2222_bbbb);
    let input = fixture.write_input("payload.bin", &original);
    let alias = fixture.input_path("payload-alias.bin");
    fs::hard_link(&input, &alias).expect("create second input hardlink");
    fixture.write_key(&pseudo_random_bytes(original.len(), 0x3333_cccc));

    let output = fixture.run([input.as_os_str()]);

    assert_runtime_error(&output);
    assert_eq!(fs::read(input).unwrap(), original);
    assert_eq!(fs::read(alias).unwrap(), original);
}

#[test]
fn no_arguments_is_a_usage_error() {
    let fixture = Fixture::new("no-args");
    let output = fixture.run(std::iter::empty::<&OsStr>());
    assert_usage_error(&output);
}

#[test]
fn extra_arguments_are_a_usage_error() {
    let fixture = Fixture::new("extra-args");
    fixture.write_key(b"long enough for either");
    fixture.write_input("one.bin", b"one");
    fixture.write_input("two.bin", b"two");

    let output = fixture.run(["one.bin", "two.bin"]);

    assert_usage_error(&output);
}

#[test]
fn delimiter_without_an_input_is_a_usage_error() {
    let fixture = Fixture::new("delimiter-no-input");
    let output = fixture.run(["--"]);
    assert_usage_error(&output);
}

#[test]
fn delimiter_with_two_inputs_is_a_usage_error() {
    let fixture = Fixture::new("delimiter-extra-input");
    fixture.write_key(b"long enough for either");
    fixture.write_input("one.bin", b"one");
    fixture.write_input("two.bin", b"two");

    let output = fixture.run(["--", "one.bin", "two.bin"]);

    assert_usage_error(&output);
}

#[test]
fn unknown_option_is_a_usage_error() {
    let fixture = Fixture::new("unknown-option");
    let output = fixture.run(["--definitely-not-an-otp1-option"]);
    assert_usage_error(&output);
}

#[test]
fn short_and_long_help_succeed_without_a_key() {
    let fixture = Fixture::new("help");

    let short = fixture.run(["-h"]);
    let long = fixture.run(["--help"]);

    assert_exit_code(&short, 0);
    assert_exit_code(&long, 0);
}

#[test]
fn double_dash_allows_a_filename_beginning_with_a_dash() {
    let fixture = Fixture::new("dash-filename");
    let original = b"option-looking filename";
    let key = vec![0x4d; original.len()];
    let input = fixture.write_input("--help", original);
    fixture.write_key(&key);

    let output = fixture.run([OsStr::new("--"), OsStr::new("--help")]);

    assert_success_quiet(&output);
    assert_eq!(fs::read(input).unwrap(), xor_reference(original, &key));
}

#[test]
fn relative_input_path_is_resolved_from_the_working_directory() {
    let fixture = Fixture::new("relative-input");
    let original = b"relative path";
    let key = vec![0x19; original.len()];
    let input = fixture.write_input("nested/payload.bin", original);
    fixture.write_key(&key);

    let output = fixture.run(["nested/payload.bin"]);

    assert_success_quiet(&output);
    assert_eq!(fs::read(input).unwrap(), xor_reference(original, &key));
}

#[test]
fn absolute_input_path_is_supported() {
    let fixture = Fixture::new("absolute-input");
    let original = b"absolute path";
    let key = vec![0xe1; original.len()];
    let input = fixture.write_input("payload.bin", original);
    fixture.write_key(&key);

    let output = fixture.run([input.as_os_str()]);

    assert_success_quiet(&output);
    assert_eq!(fs::read(input).unwrap(), xor_reference(original, &key));
}

#[test]
fn input_path_with_spaces_and_unicode_is_supported() {
    let fixture = Fixture::new("unicode-input");
    let original = b"path encoding is separate from file contents";
    let key = pseudo_random_bytes(original.len(), 0x7777);
    let input = fixture.write_input("nested folder/πayload 🔐.bin", original);
    fixture.write_key(&key);

    let output = fixture.run([input.as_os_str()]);

    assert_success_quiet(&output);
    assert_eq!(fs::read(input).unwrap(), xor_reference(original, &key));
}

#[test]
fn success_does_not_touch_neighboring_or_temp_like_files() {
    let fixture = Fixture::new("neighbors");
    let original = b"target file only";
    let key = vec![0x91; original.len()];
    let input = fixture.write_input("payload.bin", original);
    fixture.write_key(&key);

    let neighbors = [
        ("neighbor.bin", b"neighbor".as_slice()),
        (".otp1.tmp", b"not a temp file".as_slice()),
        ("payload.bin.tmp", b"also not a temp file".as_slice()),
        (
            ".payload.bin.otp1.tmp",
            b"still belongs to the user".as_slice(),
        ),
    ];
    for (name, contents) in neighbors {
        fs::write(fixture.input_path(name), contents).unwrap();
    }
    let work_entries_before = directory_entries(&fixture.work_dir);
    let bin_entries_before = directory_entries(&fixture.bin_dir);

    let output = fixture.run([input.as_os_str()]);

    assert_success_quiet(&output);
    assert_eq!(directory_entries(&fixture.work_dir), work_entries_before);
    assert_eq!(directory_entries(&fixture.bin_dir), bin_entries_before);
    assert_eq!(
        fs::read(fixture.input_path("neighbor.bin")).unwrap(),
        b"neighbor"
    );
    assert_eq!(
        fs::read(fixture.input_path(".otp1.tmp")).unwrap(),
        b"not a temp file"
    );
    assert_eq!(
        fs::read(fixture.input_path("payload.bin.tmp")).unwrap(),
        b"also not a temp file"
    );
    assert_eq!(
        fs::read(fixture.input_path(".payload.bin.otp1.tmp")).unwrap(),
        b"still belongs to the user"
    );
}

#[cfg(unix)]
#[test]
fn non_utf8_input_filename_is_supported() {
    use std::os::unix::ffi::OsStringExt;

    let fixture = Fixture::new("non-utf8-name");
    let name = OsString::from_vec(b"payload-\xff.bin".to_vec());
    let original = b"opaque operating system string";
    let key = vec![0x6a; original.len()];
    let input = fixture.write_input(PathBuf::from(&name), original);
    fixture.write_key(&key);

    let output = fixture.run([name.as_os_str()]);

    assert_success_quiet(&output);
    assert_eq!(fs::read(input).unwrap(), xor_reference(original, &key));
}

#[cfg(unix)]
#[test]
fn input_symlink_is_rejected_without_replacing_link_or_target() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new("input-symlink");
    let original = b"symlink target plaintext";
    let target = fixture.write_input("target.bin", original);
    let link = fixture.input_path("input-link.bin");
    symlink(&target, &link).unwrap();
    fixture.write_key(&vec![0x27; original.len()]);
    let link_target_before = fs::read_link(&link).unwrap();

    let output = fixture.run([link.as_os_str()]);

    assert_runtime_error(&output);
    assert!(
        fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read_link(&link).unwrap(), link_target_before);
    assert_eq!(fs::read(target).unwrap(), original);
}

#[cfg(unix)]
#[test]
fn symlink_alias_of_the_key_is_rejected_without_changing_the_key() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new("symlink-key-alias");
    let key = pseudo_random_bytes(512, 0x9191);
    fixture.write_key(&key);
    let alias = fixture.input_path("key-link.bin");
    symlink(fixture.key_path(), &alias).unwrap();

    let output = fixture.run([alias.as_os_str()]);

    assert_runtime_error(&output);
    assert!(
        fs::symlink_metadata(&alias)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read(fixture.key_path()).unwrap(), key);
}

#[cfg(unix)]
#[test]
fn unix_domain_socket_input_is_rejected_as_nonregular() {
    use std::os::unix::fs::FileTypeExt;
    use std::os::unix::net::UnixListener;

    let fixture = Fixture::new("socket-input");
    let socket = fixture.input_path("input.sock");
    let _listener = match UnixListener::bind(&socket) {
        Ok(listener) => listener,
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::PermissionDenied | io::ErrorKind::Unsupported
            ) =>
        {
            // Some sandbox profiles prohibit creating Unix-domain sockets. The
            // application behavior remains covered on hosts which permit one.
            return;
        }
        Err(error) => panic!("failed to create nonregular socket input: {error}"),
    };
    fixture.write_key(&vec![0x42; 1024]);

    let output = fixture.run([socket.as_os_str()]);

    assert_runtime_error(&output);
    assert!(
        fs::symlink_metadata(socket)
            .unwrap()
            .file_type()
            .is_socket()
    );
}

#[cfg(unix)]
#[test]
fn unix_domain_socket_key_is_rejected_without_modifying_input() {
    use std::os::unix::fs::FileTypeExt;
    use std::os::unix::net::UnixListener;

    let fixture = Fixture::new("socket-key");
    let original = b"must not be modified";
    let input = fixture.write_input("payload.bin", original);
    let key_path = fixture.key_path();
    let _listener = match UnixListener::bind(&key_path) {
        Ok(listener) => listener,
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::PermissionDenied | io::ErrorKind::Unsupported
            ) =>
        {
            // Some sandbox profiles prohibit creating Unix-domain sockets. The
            // application behavior remains covered on hosts which permit one.
            return;
        }
        Err(error) => panic!("failed to create nonregular socket key: {error}"),
    };

    let output = fixture.run([input.as_os_str()]);

    assert_runtime_error(&output);
    assert_eq!(fs::read(input).unwrap(), original);
    assert!(
        fs::symlink_metadata(key_path)
            .unwrap()
            .file_type()
            .is_socket()
    );
}

#[cfg(unix)]
#[test]
fn successful_atomic_replacement_preserves_mode_and_replaces_inode() {
    use std::io::{Read, Seek, SeekFrom};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let fixture = Fixture::new("atomic-inode-mode");
    let original = pseudo_random_bytes(131_072, 0x4545);
    let key = pseudo_random_bytes(original.len(), 0x5656);
    let expected = xor_reference(&original, &key);
    let input = fixture.write_input("payload.bin", &original);
    fs::set_permissions(&input, fs::Permissions::from_mode(0o640)).unwrap();
    fixture.write_key(&key);

    // Keeping the old inode open prevents inode-number reuse and proves that the
    // destination was replaced instead of truncated and rewritten.
    let mut old_file = fs::File::open(&input).unwrap();
    let old_metadata = old_file.metadata().unwrap();

    let output = fixture.run([input.as_os_str()]);

    assert_success_quiet(&output);
    let new_metadata = fs::metadata(&input).unwrap();
    assert_eq!(new_metadata.dev(), old_metadata.dev());
    assert_ne!(new_metadata.ino(), old_metadata.ino());
    assert_eq!(new_metadata.mode() & 0o7777, 0o640);
    assert_eq!(fs::read(&input).unwrap(), expected);

    old_file.seek(SeekFrom::Start(0)).unwrap();
    let mut bytes_visible_through_old_inode = Vec::new();
    old_file
        .read_to_end(&mut bytes_visible_through_old_inode)
        .unwrap();
    assert_eq!(bytes_visible_through_old_inode, original);
}

#[cfg(unix)]
#[test]
fn preserves_multiple_common_unix_permission_modes() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    for mode in [0o600, 0o640, 0o751] {
        let fixture = Fixture::new(&format!("mode-{mode:o}"));
        let original = pseudo_random_bytes(8193, mode as u64);
        let key = pseudo_random_bytes(original.len(), !(mode as u64));
        let input = fixture.write_input("payload.bin", &original);
        fs::set_permissions(&input, fs::Permissions::from_mode(mode)).unwrap();
        fixture.write_key(&key);

        let output = fixture.run([input.as_os_str()]);

        assert_success_quiet(&output);
        assert_eq!(fs::metadata(&input).unwrap().mode() & 0o7777, mode);
        assert_eq!(fs::read(input).unwrap(), xor_reference(&original, &key));
    }
}

#[cfg(unix)]
#[test]
fn short_key_preserves_unix_inode_mode_and_modification_time() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let fixture = Fixture::new("short-key-metadata");
    let original = pseudo_random_bytes(8192, 0x1212);
    let input = fixture.write_input("payload.bin", &original);
    fs::set_permissions(&input, fs::Permissions::from_mode(0o641)).unwrap();
    fixture.write_key(&pseudo_random_bytes(original.len() - 1, 0x3434));
    let before = fs::metadata(&input).unwrap();

    let output = fixture.run([input.as_os_str()]);

    assert_runtime_error(&output);
    let after = fs::metadata(&input).unwrap();
    assert_eq!(after.dev(), before.dev());
    assert_eq!(after.ino(), before.ino());
    assert_eq!(after.mode(), before.mode());
    assert_eq!(after.mtime(), before.mtime());
    assert_eq!(after.mtime_nsec(), before.mtime_nsec());
    assert_eq!(after.len(), before.len());
    assert_eq!(fs::read(input).unwrap(), original);
}

#[test]
fn each_fixture_really_separates_executable_and_working_directories() {
    let fixture = Fixture::new("fixture-sanity");
    assert_ne!(fixture.bin_dir, fixture.work_dir);
    assert!(fixture.executable.starts_with(&fixture.bin_dir));
    assert!(fixture.work_dir.starts_with(&fixture.root));
    assert!(fixture.bin_dir.starts_with(&fixture.root));
}
