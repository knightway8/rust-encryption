use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT_TEMP_ID: AtomicUsize = AtomicUsize::new(0);

const AUTH_KEY_LENGTH: usize = 32;
const ENVELOPE_OVERHEAD: usize = 64;
const MAGIC: &[u8; 8] = b"OTP1AUTH";

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
                "otp1-auth-cli-{label}-{}-{timestamp}-{id}",
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
    bin_dir: PathBuf,
    work_dir: PathBuf,
    otp1: PathBuf,
    auth: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let temp = TempDir::new(label);
        let bin_dir = temp.path.join("isolated binaries λ");
        let work_dir = temp.path.join("unrelated working directory");
        fs::create_dir(&bin_dir).expect("create isolated executable directory");
        fs::create_dir(&work_dir).expect("create isolated working directory");

        let otp1 = copy_executable(env!("CARGO_BIN_EXE_otp1"), &bin_dir);
        let auth = copy_executable(env!("CARGO_BIN_EXE_otp1-auth"), &bin_dir);

        Self {
            _temp: temp,
            bin_dir,
            work_dir,
            otp1,
            auth,
        }
    }

    fn auth_key_path(&self) -> PathBuf {
        self.bin_dir.join("auth.key")
    }

    fn otp_key_path(&self) -> PathBuf {
        self.bin_dir.join("key.key")
    }

    fn write_auth_key(&self, bytes: &[u8]) {
        let path = self.auth_key_path();
        fs::write(&path, bytes).expect("write executable-relative auth.key");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .expect("make authentication key private");
        }
    }

    fn write_otp_key(&self, bytes: &[u8]) {
        fs::write(self.otp_key_path(), bytes).expect("write executable-relative key.key");
    }

    fn write_file(&self, name: impl AsRef<Path>, bytes: &[u8]) -> PathBuf {
        let path = self.work_dir.join(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create test file parent");
        }
        fs::write(&path, bytes).unwrap_or_else(|error| {
            panic!("failed to write test file {path:?}: {error}");
        });
        path
    }

    fn run_auth<I, S>(&self, args: I) -> Output
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        run_command(&self.auth, &self.work_dir, args)
    }

    fn run_auth_file(&self, operation: &str, path: &Path) -> Output {
        self.run_auth([OsStr::new(operation), path.as_os_str()])
    }

    fn run_otp1(&self, path: &Path) -> Output {
        run_command(&self.otp1, &self.work_dir, [path.as_os_str()])
    }
}

fn copy_executable(source: &str, destination_directory: &Path) -> PathBuf {
    let source = PathBuf::from(source);
    let destination = destination_directory.join(
        source
            .file_name()
            .expect("Cargo-provided binary path has a filename"),
    );
    fs::copy(&source, &destination).unwrap_or_else(|error| {
        panic!("failed to copy executable from {source:?} to {destination:?}: {error}");
    });
    destination
}

fn run_command<I, S>(executable: &Path, cwd: &Path, args: I) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let args: Vec<OsString> = args
        .into_iter()
        .map(|argument| argument.as_ref().to_os_string())
        .collect();
    for attempt in 0..100 {
        match Command::new(executable)
            .current_dir(cwd)
            .args(&args)
            .output()
        {
            Ok(output) => return output,
            Err(error) if error.kind() == io::ErrorKind::ExecutableFileBusy && attempt != 99 => {
                std::thread::yield_now();
            }
            Err(error) => panic!("launch isolated executable {executable:?}: {error}"),
        }
    }
    unreachable!("the final launch attempt always returns or panics")
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
fn assert_quiet_success(output: &Output) {
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
fn assert_runtime_failure(output: &Output) {
    assert_exit_code(output, 1);
    assert!(output.stdout.is_empty(), "runtime failure wrote stdout");
    assert!(
        !output.stderr.is_empty(),
        "runtime failure should explain itself on stderr"
    );
}

#[track_caller]
fn assert_authentication_failure(output: &Output) {
    assert_exit_code(output, 4);
    assert!(
        output.stdout.is_empty(),
        "authentication failure wrote stdout"
    );
    assert!(
        !output.stderr.is_empty(),
        "authentication failure should explain itself on stderr"
    );
}

#[track_caller]
fn assert_usage_failure(output: &Output) {
    assert_exit_code(output, 2);
    assert!(output.stdout.is_empty(), "usage failure wrote stdout");
    assert!(
        !output.stderr.is_empty(),
        "usage failure should explain itself on stderr"
    );
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

fn xor_reference(input: &[u8], key: &[u8]) -> Vec<u8> {
    assert!(key.len() >= input.len());
    input
        .iter()
        .zip(key)
        .map(|(&plain, &pad)| plain ^ pad)
        .collect()
}

fn directory_entries(path: &Path) -> Vec<OsString> {
    let mut entries: Vec<_> = fs::read_dir(path)
        .unwrap_or_else(|error| panic!("read directory {path:?}: {error}"))
        .map(|entry| entry.expect("read directory entry").file_name())
        .collect();
    entries.sort();
    entries
}

#[derive(Debug, Eq, PartialEq)]
struct MetadataFingerprint {
    // Access time is deliberately omitted: successfully reading a file may
    // update it on filesystems mounted with atime tracking enabled.
    len: u64,
    readonly: bool,
    modified: SystemTime,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    mode: u32,
    #[cfg(unix)]
    links: u64,
}

fn metadata_fingerprint(path: &Path) -> MetadataFingerprint {
    let metadata =
        fs::metadata(path).unwrap_or_else(|error| panic!("failed to inspect {path:?}: {error}"));
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;

    MetadataFingerprint {
        len: metadata.len(),
        readonly: metadata.permissions().readonly(),
        modified: metadata.modified().expect("file has a modification time"),
        #[cfg(unix)]
        device: metadata.dev(),
        #[cfg(unix)]
        inode: metadata.ino(),
        #[cfg(unix)]
        mode: metadata.mode(),
        #[cfg(unix)]
        links: metadata.nlink(),
    }
}

fn make_valid_envelope(fixture: &Fixture, name: &str, payload: &[u8]) -> PathBuf {
    fixture.write_auth_key(&[0x39; AUTH_KEY_LENGTH]);
    let path = fixture.write_file(name, payload);
    assert_quiet_success(&fixture.run_auth_file("seal", &path));
    path
}

#[cfg(unix)]
#[test]
fn keygen_creates_distinct_nonzero_32_byte_keys_and_is_quiet() {
    let first = Fixture::new("keygen-random-first");
    let second = Fixture::new("keygen-random-second");

    assert_quiet_success(&first.run_auth(["keygen"]));
    assert_quiet_success(&second.run_auth(["keygen"]));

    let first_key = fs::read(first.auth_key_path()).expect("read first generated key");
    let second_key = fs::read(second.auth_key_path()).expect("read second generated key");
    assert_eq!(first_key.len(), AUTH_KEY_LENGTH);
    assert_eq!(second_key.len(), AUTH_KEY_LENGTH);
    assert!(first_key.iter().any(|&byte| byte != 0));
    assert!(second_key.iter().any(|&byte| byte != 0));
    assert_ne!(
        first_key, second_key,
        "independent keygen calls repeated a key"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(
            fs::metadata(first.auth_key_path())
                .expect("inspect generated key")
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[cfg(unix)]
#[test]
fn keygen_never_overwrites_an_existing_file() {
    let fixture = Fixture::new("keygen-no-overwrite");
    let existing = b"an existing key file with irreplaceable bytes";
    fixture.write_auth_key(existing);
    let before_bytes = fs::read(fixture.auth_key_path()).expect("read existing key");
    let before_metadata = metadata_fingerprint(&fixture.auth_key_path());
    let before_entries = directory_entries(&fixture.bin_dir);

    let output = fixture.run_auth(["keygen"]);
    assert_runtime_failure(&output);
    assert_eq!(fs::read(fixture.auth_key_path()).unwrap(), before_bytes);
    assert_eq!(
        metadata_fingerprint(&fixture.auth_key_path()),
        before_metadata
    );
    assert_eq!(directory_entries(&fixture.bin_dir), before_entries);
}

#[cfg(unix)]
#[test]
fn keygen_preserves_a_partial_key_until_the_user_removes_it_then_recovers() {
    let fixture = Fixture::new("keygen-partial-recovery");
    let partial_key = b"partial";
    fixture.write_auth_key(partial_key);
    let before_metadata = metadata_fingerprint(&fixture.auth_key_path());
    let before_entries = directory_entries(&fixture.bin_dir);

    assert_runtime_failure(&fixture.run_auth(["keygen"]));
    assert_eq!(fs::read(fixture.auth_key_path()).unwrap(), partial_key);
    assert_eq!(
        metadata_fingerprint(&fixture.auth_key_path()),
        before_metadata
    );
    assert_eq!(directory_entries(&fixture.bin_dir), before_entries);

    fs::remove_file(fixture.auth_key_path()).expect("explicitly remove partial key");
    assert_quiet_success(&fixture.run_auth(["keygen"]));
    let replacement = fs::read(fixture.auth_key_path()).expect("read replacement key");
    assert_eq!(replacement.len(), AUTH_KEY_LENGTH);
    assert_eq!(directory_entries(&fixture.bin_dir), before_entries);
}

#[cfg(unix)]
#[test]
fn keygen_does_not_follow_or_replace_an_existing_auth_key_symlink() {
    use std::os::unix::fs as unix_fs;

    let fixture = Fixture::new("keygen-symlink-no-follow");
    let referent = fixture.bin_dir.join("existing-private-key");
    let referent_bytes = b"irreplaceable key material behind a symlink";
    fs::write(&referent, referent_bytes).expect("write auth-key symlink referent");
    unix_fs::symlink(&referent, fixture.auth_key_path()).expect("create auth.key symlink");
    let referent_metadata = metadata_fingerprint(&referent);
    let before_entries = directory_entries(&fixture.bin_dir);

    let output = fixture.run_auth(["keygen"]);

    assert_runtime_failure(&output);
    assert!(
        fs::symlink_metadata(fixture.auth_key_path())
            .expect("inspect auth.key symlink")
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read(&referent).unwrap(), referent_bytes);
    assert_eq!(metadata_fingerprint(&referent), referent_metadata);
    assert_eq!(directory_entries(&fixture.bin_dir), before_entries);
}

#[test]
fn seal_verify_and_unwrap_are_quiet_and_restore_exact_payload() {
    let fixture = Fixture::new("basic-round-trip");
    fixture.write_auth_key(&[0xa6; AUTH_KEY_LENGTH]);
    let payload = pseudo_random_bytes(2 * 64 * 1024 + 97, 0x1dcb_4432);
    let path = fixture.write_file("payload with spaces.bin", &payload);

    assert_quiet_success(&fixture.run_auth_file("seal", &path));
    let envelope = fs::read(&path).expect("read sealed envelope");
    assert_eq!(envelope.len(), payload.len() + ENVELOPE_OVERHEAD);
    assert_eq!(&envelope[..MAGIC.len()], MAGIC);

    assert_quiet_success(&fixture.run_auth_file("verify", &path));
    assert_eq!(fs::read(&path).unwrap(), envelope);

    assert_quiet_success(&fixture.run_auth_file("unwrap", &path));
    assert_eq!(fs::read(&path).unwrap(), payload);
}

#[test]
fn complete_otp1_authenticated_round_trip_preserves_every_ciphertext_byte() {
    let fixture = Fixture::new("complete-workflow");
    let plaintext = pseudo_random_bytes(3 * 64 * 1024 + 19, 0x8877_6655_4433_2211);
    let otp_key = pseudo_random_bytes(plaintext.len() + 41, 0x1234_abcd_9876_ef01);
    let expected_ciphertext = xor_reference(&plaintext, &otp_key);
    fixture.write_otp_key(&otp_key);
    fixture.write_auth_key(&[0x5c; AUTH_KEY_LENGTH]);
    let path = fixture.write_file("message λ.dat", &plaintext);

    assert_quiet_success(&fixture.run_otp1(&path));
    assert_eq!(fs::read(&path).unwrap(), expected_ciphertext);

    assert_quiet_success(&fixture.run_auth_file("seal", &path));
    assert_quiet_success(&fixture.run_auth_file("verify", &path));
    assert_quiet_success(&fixture.run_auth_file("unwrap", &path));
    assert_eq!(fs::read(&path).unwrap(), expected_ciphertext);

    assert_quiet_success(&fixture.run_otp1(&path));
    assert_eq!(fs::read(&path).unwrap(), plaintext);
}

#[test]
fn auth_key_is_resolved_beside_the_executable_not_in_the_working_directory() {
    let fixture = Fixture::new("executable-relative-key");
    let correct_key = [0x12; AUTH_KEY_LENGTH];
    let decoy_key = [0xe7; AUTH_KEY_LENGTH];
    fixture.write_auth_key(&correct_key);
    fs::write(fixture.work_dir.join("auth.key"), decoy_key).expect("write cwd decoy key");
    let path = fixture.write_file("ciphertext", b"bytes authenticated by the adjacent key");

    assert_quiet_success(&fixture.run_auth_file("seal", &path));
    assert_quiet_success(&fixture.run_auth_file("verify", &path));

    fixture.write_auth_key(&decoy_key);
    fs::write(fixture.work_dir.join("auth.key"), correct_key).expect("replace cwd decoy key");
    let output = fixture.run_auth_file("verify", &path);
    assert_authentication_failure(&output);
}

#[test]
fn missing_key_fails_without_modifying_raw_or_enveloped_files() {
    let fixture = Fixture::new("missing-key");
    let envelope = make_valid_envelope(&fixture, "envelope", b"sealed bytes");
    let envelope_before = fs::read(&envelope).unwrap();
    fs::remove_file(fixture.auth_key_path()).expect("remove isolated test key");
    let raw = fixture.write_file("raw", b"raw bytes");
    let raw_before = fs::read(&raw).unwrap();
    let entries_before = directory_entries(&fixture.work_dir);

    assert_runtime_failure(&fixture.run_auth_file("seal", &raw));
    assert_runtime_failure(&fixture.run_auth_file("verify", &envelope));
    assert_runtime_failure(&fixture.run_auth_file("unwrap", &envelope));

    assert_eq!(fs::read(raw).unwrap(), raw_before);
    assert_eq!(fs::read(envelope).unwrap(), envelope_before);
    assert_eq!(directory_entries(&fixture.work_dir), entries_before);
}

#[test]
fn zero_31_and_33_byte_keys_are_rejected_by_every_operation() {
    let fixture = Fixture::new("invalid-key-lengths");
    let envelope = make_valid_envelope(&fixture, "envelope", b"valid envelope payload");
    let envelope_before = fs::read(&envelope).unwrap();
    let raw = fixture.write_file("raw", b"unsealed data");
    let raw_before = fs::read(&raw).unwrap();
    let entries_before = directory_entries(&fixture.work_dir);

    for length in [0, 31, 33] {
        fixture.write_auth_key(&vec![0x7d; length]);
        assert_runtime_failure(&fixture.run_auth_file("seal", &raw));
        assert_runtime_failure(&fixture.run_auth_file("verify", &envelope));
        assert_runtime_failure(&fixture.run_auth_file("unwrap", &envelope));
        assert_eq!(fs::read(&raw).unwrap(), raw_before, "key length {length}");
        assert_eq!(
            fs::read(&envelope).unwrap(),
            envelope_before,
            "key length {length}"
        );
        assert_eq!(directory_entries(&fixture.work_dir), entries_before);
    }
}

#[test]
fn seal_rejects_the_authentication_key_as_its_own_target() {
    let fixture = Fixture::new("target-is-auth-key");
    fixture.write_auth_key(&[0x5d; AUTH_KEY_LENGTH]);
    let key_path = fixture.auth_key_path();
    let key_bytes = fs::read(&key_path).unwrap();
    let key_metadata = metadata_fingerprint(&key_path);
    let bin_entries = directory_entries(&fixture.bin_dir);
    let work_entries = directory_entries(&fixture.work_dir);

    let output = fixture.run_auth_file("seal", &key_path);

    assert_runtime_failure(&output);
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("refer to the same file"),
        "stderr was {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read(&key_path).unwrap(), key_bytes);
    assert_eq!(metadata_fingerprint(&key_path), key_metadata);
    assert_eq!(directory_entries(&fixture.bin_dir), bin_entries);
    assert_eq!(directory_entries(&fixture.work_dir), work_entries);
}

#[cfg(unix)]
#[test]
fn group_or_other_accessible_authentication_keys_are_rejected_without_changes() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = Fixture::new("public-key-permissions");
    let envelope = make_valid_envelope(&fixture, "envelope", b"authenticated payload");
    let raw = fixture.write_file("raw", b"raw ciphertext");
    fs::set_permissions(fixture.auth_key_path(), fs::Permissions::from_mode(0o640))
        .expect("make authentication key group-readable");

    let raw_before = fs::read(&raw).unwrap();
    let envelope_before = fs::read(&envelope).unwrap();
    let raw_metadata = metadata_fingerprint(&raw);
    let envelope_metadata = metadata_fingerprint(&envelope);
    let key_bytes = fs::read(fixture.auth_key_path()).unwrap();
    let key_metadata = metadata_fingerprint(&fixture.auth_key_path());
    let work_entries = directory_entries(&fixture.work_dir);
    let bin_entries = directory_entries(&fixture.bin_dir);

    for (operation, path) in [
        ("seal", raw.as_path()),
        ("verify", envelope.as_path()),
        ("unwrap", envelope.as_path()),
    ] {
        let output = fixture.run_auth_file(operation, path);
        assert_runtime_failure(&output);
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("group or other"),
            "stderr was {:?}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    assert_eq!(fs::read(&raw).unwrap(), raw_before);
    assert_eq!(fs::read(&envelope).unwrap(), envelope_before);
    assert_eq!(metadata_fingerprint(&raw), raw_metadata);
    assert_eq!(metadata_fingerprint(&envelope), envelope_metadata);
    assert_eq!(fs::read(fixture.auth_key_path()).unwrap(), key_bytes);
    assert_eq!(metadata_fingerprint(&fixture.auth_key_path()), key_metadata);
    assert_eq!(directory_entries(&fixture.work_dir), work_entries);
    assert_eq!(directory_entries(&fixture.bin_dir), bin_entries);
}

#[test]
fn wrong_key_is_an_authentication_failure_and_unwrap_is_non_destructive() {
    let fixture = Fixture::new("wrong-key");
    let path = make_valid_envelope(&fixture, "envelope", b"authenticated payload");
    let before_bytes = fs::read(&path).unwrap();
    let before_metadata = metadata_fingerprint(&path);
    let before_entries = directory_entries(&fixture.work_dir);
    fixture.write_auth_key(&[0xc3; AUTH_KEY_LENGTH]);

    assert_authentication_failure(&fixture.run_auth_file("verify", &path));
    assert_authentication_failure(&fixture.run_auth_file("unwrap", &path));
    assert_eq!(fs::read(&path).unwrap(), before_bytes);
    assert_eq!(metadata_fingerprint(&path), before_metadata);
    assert_eq!(directory_entries(&fixture.work_dir), before_entries);
}

#[test]
fn failure_diagnostics_never_disclose_authentication_key_material() {
    let fixture = Fixture::new("secret-diagnostics");
    fixture.write_auth_key(&[b'A'; AUTH_KEY_LENGTH]);
    let path = fixture.write_file("envelope", b"sensitive ciphertext");
    assert_quiet_success(&fixture.run_auth_file("seal", &path));

    let secret = [b'Z'; AUTH_KEY_LENGTH];
    fixture.write_auth_key(&secret);
    let lowercase_hex = "5a".repeat(AUTH_KEY_LENGTH);
    let uppercase_hex = "5A".repeat(AUTH_KEY_LENGTH);
    let base64 = format!("{}Wlo=", "Wlpa".repeat(10));
    let debug_prefix = b"[90, 90, 90, 90";
    for operation in ["verify", "unwrap"] {
        let output = fixture.run_auth_file(operation, &path);
        assert_authentication_failure(&output);
        for encoding in [
            secret.as_slice(),
            &[b'Z'; 16],
            lowercase_hex.as_bytes(),
            uppercase_hex.as_bytes(),
            base64.as_bytes(),
            debug_prefix,
        ] {
            assert!(!contains_subslice(&output.stdout, encoding));
            assert!(!contains_subslice(&output.stderr, encoding));
        }
    }
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

#[test]
fn separator_supports_dash_prefixed_filenames_for_all_operations() {
    let fixture = Fixture::new("dash-filename");
    fixture.write_auth_key(&[0x61; AUTH_KEY_LENGTH]);
    let path = fixture.write_file("-ciphertext", b"dash-prefixed payload");

    assert_quiet_success(&fixture.run_auth(["seal", "--", "-ciphertext"]));
    assert_quiet_success(&fixture.run_auth(["verify", "--", "-ciphertext"]));
    assert_quiet_success(&fixture.run_auth(["unwrap", "--", "-ciphertext"]));
    assert_eq!(fs::read(path).unwrap(), b"dash-prefixed payload");
}

#[test]
fn help_and_usage_have_stable_stream_and_exit_contracts() {
    let fixture = Fixture::new("help-and-usage");
    for help in ["-h", "--help"] {
        let output = fixture.run_auth([help]);
        assert_exit_code(&output, 0);
        assert!(output.stderr.is_empty());
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(text.contains("otp1-auth keygen"));
        assert!(text.contains("otp1-auth seal"));
        assert!(text.contains("otp1-auth verify"));
        assert!(text.contains("otp1-auth unwrap"));
    }

    let invalid: &[&[&str]] = &[
        &[],
        &["unknown"],
        &["keygen", "extra"],
        &["seal"],
        &["verify", "--"],
        &["unwrap", "one", "two"],
        &["seal", "-filename"],
        &["--help", "extra"],
    ];
    for arguments in invalid {
        assert_usage_failure(&fixture.run_auth(*arguments));
    }
}

#[cfg(unix)]
#[test]
fn non_utf8_filename_round_trips_through_all_operations() {
    use std::os::unix::ffi::OsStringExt;

    let fixture = Fixture::new("non-utf8-filename");
    fixture.write_auth_key(&[0x28; AUTH_KEY_LENGTH]);
    let name = OsString::from_vec(vec![b'c', b'i', b'p', b'h', b'e', b'r', 0x80, 0xff]);
    let payload = b"non-UTF-8 path payload";
    let path = fixture.write_file(PathBuf::from(name), payload);

    assert_quiet_success(&fixture.run_auth_file("seal", &path));
    assert_quiet_success(&fixture.run_auth_file("verify", &path));
    assert_quiet_success(&fixture.run_auth_file("unwrap", &path));
    assert_eq!(fs::read(path).unwrap(), payload);
}

#[test]
fn raw_files_are_authentication_failures_for_verify_and_unwrap() {
    let fixture = Fixture::new("raw-is-invalid");
    fixture.write_auth_key(&[0x4f; AUTH_KEY_LENGTH]);

    for (name, bytes) in [
        ("short", b"plain raw ciphertext".as_slice()),
        ("long", &[0x42; ENVELOPE_OVERHEAD + 20]),
    ] {
        let path = fixture.write_file(name, bytes);
        let before = fs::read(&path).unwrap();
        let metadata = metadata_fingerprint(&path);
        let entries = directory_entries(&fixture.work_dir);
        assert_authentication_failure(&fixture.run_auth_file("verify", &path));
        assert_authentication_failure(&fixture.run_auth_file("unwrap", &path));
        assert_eq!(fs::read(&path).unwrap(), before);
        assert_eq!(metadata_fingerprint(&path), metadata);
        assert_eq!(directory_entries(&fixture.work_dir), entries);
    }
}

#[test]
fn malformed_header_fields_and_lengths_are_rejected_without_replacement() {
    let fixture = Fixture::new("malformed-headers");
    let path = make_valid_envelope(&fixture, "envelope", b"payload for header checks");
    let valid = fs::read(&path).unwrap();

    let mut cases = Vec::new();
    let mut unsupported_version = valid.clone();
    unsupported_version[9] ^= 1;
    cases.push(unsupported_version);
    let mut wrong_header_length = valid.clone();
    wrong_header_length[11] ^= 1;
    cases.push(wrong_header_length);
    let mut unsupported_flags = valid.clone();
    unsupported_flags[15] = 1;
    cases.push(unsupported_flags);
    let mut nonzero_reserved = valid.clone();
    nonzero_reserved[31] = 1;
    cases.push(nonzero_reserved);
    let mut wrong_payload_length = valid.clone();
    wrong_payload_length[23] ^= 1;
    cases.push(wrong_payload_length);
    cases.push(valid[..valid.len() - 1].to_vec());
    let mut extended = valid.clone();
    extended.push(0);
    cases.push(extended);

    for malformed in cases {
        fs::write(&path, &malformed).expect("install malformed envelope case");
        let before_metadata = metadata_fingerprint(&path);
        let before_entries = directory_entries(&fixture.work_dir);
        assert_authentication_failure(&fixture.run_auth_file("verify", &path));
        assert_authentication_failure(&fixture.run_auth_file("unwrap", &path));
        assert_eq!(fs::read(&path).unwrap(), malformed);
        assert_eq!(metadata_fingerprint(&path), before_metadata);
        assert_eq!(directory_entries(&fixture.work_dir), before_entries);
    }
}

#[test]
fn payload_and_tag_tampering_are_detected_before_unwrap_replaces_anything() {
    let fixture = Fixture::new("tampering");
    let path = make_valid_envelope(
        &fixture,
        "envelope",
        &pseudo_random_bytes(64 * 1024 + 7, 0xfedc_ba98),
    );
    let valid = fs::read(&path).unwrap();

    for index in [32, valid.len() - 1] {
        let mut tampered = valid.clone();
        tampered[index] ^= 0x80;
        fs::write(&path, &tampered).expect("install tampered envelope");
        let before_metadata = metadata_fingerprint(&path);
        let before_entries = directory_entries(&fixture.work_dir);
        assert_authentication_failure(&fixture.run_auth_file("verify", &path));
        assert_authentication_failure(&fixture.run_auth_file("unwrap", &path));
        assert_eq!(fs::read(&path).unwrap(), tampered);
        assert_eq!(metadata_fingerprint(&path), before_metadata);
        assert_eq!(directory_entries(&fixture.work_dir), before_entries);
    }
}

#[test]
fn seal_rejects_double_sealing() {
    let fixture = Fixture::new("double-seal");
    fixture.write_auth_key(&[0x9b; AUTH_KEY_LENGTH]);
    let sealed = fixture.write_file("sealed", b"payload");
    assert_quiet_success(&fixture.run_auth_file("seal", &sealed));
    let sealed_before = fs::read(&sealed).unwrap();
    let sealed_metadata = metadata_fingerprint(&sealed);

    assert_runtime_failure(&fixture.run_auth_file("seal", &sealed));
    assert_eq!(fs::read(&sealed).unwrap(), sealed_before);
    assert_eq!(metadata_fingerprint(&sealed), sealed_metadata);
}

#[test]
fn force_raw_seals_magic_prefixed_ciphertext_that_default_seal_rejects() {
    let fixture = Fixture::new("force-raw-magic");
    fixture.write_auth_key(&[0x9b; AUTH_KEY_LENGTH]);
    let raw_magic = fixture.write_file("raw-magic", b"OTP1AUTHnot-an-envelope");
    let raw_before = fs::read(&raw_magic).unwrap();
    let raw_metadata = metadata_fingerprint(&raw_magic);
    let entries = directory_entries(&fixture.work_dir);

    assert_runtime_failure(&fixture.run_auth_file("seal", &raw_magic));
    assert_eq!(fs::read(&raw_magic).unwrap(), raw_before);
    assert_eq!(metadata_fingerprint(&raw_magic), raw_metadata);
    assert_eq!(directory_entries(&fixture.work_dir), entries);

    assert_quiet_success(&fixture.run_auth([
        OsStr::new("seal"),
        OsStr::new("--force-raw"),
        raw_magic.as_os_str(),
    ]));
    let envelope = fs::read(&raw_magic).expect("read forced envelope");
    assert_eq!(envelope.len(), raw_before.len() + ENVELOPE_OVERHEAD);
    assert_eq!(
        &envelope[ENVELOPE_OVERHEAD / 2..envelope.len() - ENVELOPE_OVERHEAD / 2],
        raw_before
    );
    assert_quiet_success(&fixture.run_auth_file("verify", &raw_magic));
    assert_quiet_success(&fixture.run_auth_file("unwrap", &raw_magic));
    assert_eq!(fs::read(&raw_magic).unwrap(), raw_before);
    assert_eq!(directory_entries(&fixture.work_dir), entries);
}

#[test]
fn verify_preserves_file_key_contents_and_path_identities() {
    let fixture = Fixture::new("verify-preservation");
    let path = make_valid_envelope(
        &fixture,
        "envelope",
        &pseudo_random_bytes(2 * 64 * 1024 + 3, 0xface_4411),
    );
    let file_bytes = fs::read(&path).unwrap();
    let file_metadata = metadata_fingerprint(&path);
    let key_bytes = fs::read(fixture.auth_key_path()).unwrap();
    let key_metadata = metadata_fingerprint(&fixture.auth_key_path());
    let work_entries = directory_entries(&fixture.work_dir);
    let bin_entries = directory_entries(&fixture.bin_dir);

    assert_quiet_success(&fixture.run_auth_file("verify", &path));

    assert_eq!(fs::read(&path).unwrap(), file_bytes);
    assert_eq!(metadata_fingerprint(&path), file_metadata);
    assert_eq!(fs::read(fixture.auth_key_path()).unwrap(), key_bytes);
    assert_eq!(metadata_fingerprint(&fixture.auth_key_path()), key_metadata);
    assert_eq!(directory_entries(&fixture.work_dir), work_entries);
    assert_eq!(directory_entries(&fixture.bin_dir), bin_entries);
}

#[cfg(unix)]
#[test]
fn read_only_auth_key_supports_all_operations_without_metadata_changes() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = Fixture::new("read-only-key");
    fixture.write_auth_key(&[0x83; AUTH_KEY_LENGTH]);
    fs::set_permissions(fixture.auth_key_path(), fs::Permissions::from_mode(0o400))
        .expect("make auth key read-only");
    let key_bytes = fs::read(fixture.auth_key_path()).unwrap();
    let key_metadata = metadata_fingerprint(&fixture.auth_key_path());
    let path = fixture.write_file("payload", b"read-only auth key payload");

    assert_quiet_success(&fixture.run_auth_file("seal", &path));
    assert_quiet_success(&fixture.run_auth_file("verify", &path));
    assert_quiet_success(&fixture.run_auth_file("unwrap", &path));

    assert_eq!(fs::read(&path).unwrap(), b"read-only auth key payload");
    assert_eq!(fs::read(fixture.auth_key_path()).unwrap(), key_bytes);
    assert_eq!(metadata_fingerprint(&fixture.auth_key_path()), key_metadata);

    fs::set_permissions(fixture.auth_key_path(), fs::Permissions::from_mode(0o600))
        .expect("restore key permissions for fixture cleanup");
}
