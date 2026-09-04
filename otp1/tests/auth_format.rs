use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use otp1::auth::{self, AUTH_KEY_LENGTH, AuthError, HEADER_LENGTH, TAG_LENGTH};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

const MAGIC: &[u8; 8] = b"OTP1AUTH";
const GOLDEN_KEY: [u8; AUTH_KEY_LENGTH] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
const EMPTY_HEADER: [u8; HEADER_LENGTH] = [
    0x4f, 0x54, 0x50, 0x31, 0x41, 0x55, 0x54, 0x48, 0x00, 0x01, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
const EMPTY_TAG: [u8; TAG_LENGTH] = [
    0x79, 0xd7, 0xd8, 0xf1, 0xc6, 0xa4, 0x0e, 0x4e, 0x84, 0x70, 0xd5, 0x83, 0x88, 0x0a, 0x56, 0x71,
    0x9a, 0x64, 0x0f, 0xaf, 0xb8, 0xfe, 0x5e, 0x58, 0x88, 0x22, 0x92, 0x47, 0x4c, 0xa2, 0x33, 0x62,
];
const EIGHT_BYTE_PAYLOAD: [u8; 8] = [0x00, 0x01, 0x02, 0xff, 0x4f, 0x54, 0x50, 0x31];
const EIGHT_BYTE_HEADER: [u8; HEADER_LENGTH] = [
    0x4f, 0x54, 0x50, 0x31, 0x41, 0x55, 0x54, 0x48, 0x00, 0x01, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
const EIGHT_BYTE_TAG: [u8; TAG_LENGTH] = [
    0xaf, 0xed, 0x40, 0xbd, 0xbf, 0x8a, 0x10, 0x26, 0xca, 0x98, 0x70, 0xdb, 0x88, 0xd1, 0xb1, 0x15,
    0xf6, 0x93, 0x3e, 0x90, 0x46, 0xfe, 0xc7, 0xc3, 0xa5, 0x44, 0x2e, 0xdb, 0x05, 0xfb, 0xa2, 0x2a,
];

static NEXT_DIRECTORY_ID: AtomicUsize = AtomicUsize::new(0);

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn new(label: &str) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();

        for _ in 0..1_000 {
            let id = NEXT_DIRECTORY_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "otp1-auth-format-{label}-{}-{timestamp}-{id}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Self { path },
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("create test directory {path:?}: {error}"),
            }
        }

        panic!("could not allocate a unique authentication-format test directory");
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct Fixture {
    _directory: TestDirectory,
    root: PathBuf,
    target: PathBuf,
    key: PathBuf,
}

impl Fixture {
    fn new(label: &str, target_bytes: &[u8], key_bytes: &[u8]) -> Self {
        let directory = TestDirectory::new(label);
        let root = directory.path.clone();
        let target = root.join("ciphertext.bin");
        let key = root.join("auth.key");
        fs::write(&target, target_bytes).expect("write test target");
        fs::write(&key, key_bytes).expect("write test authentication key");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&key, fs::Permissions::from_mode(0o600))
                .expect("make test authentication key private");
        }
        Self {
            _directory: directory,
            root,
            target,
            key,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
struct FileState {
    contents: Vec<u8>,
    length: u64,
    readonly: bool,
    #[cfg(unix)]
    identity: (u64, u64),
}

impl FileState {
    fn capture(path: &Path) -> Self {
        let metadata = fs::metadata(path).expect("inspect test file");
        Self {
            contents: fs::read(path).expect("read test file"),
            length: metadata.len(),
            readonly: metadata.permissions().readonly(),
            #[cfg(unix)]
            identity: (metadata.dev(), metadata.ino()),
        }
    }
}

fn directory_entries(path: &Path) -> Vec<OsString> {
    let mut entries: Vec<_> = fs::read_dir(path)
        .expect("read test directory")
        .map(|entry| entry.expect("read directory entry").file_name())
        .collect();
    entries.sort();
    entries
}

fn golden_empty_envelope() -> Vec<u8> {
    let mut envelope = Vec::with_capacity(HEADER_LENGTH + TAG_LENGTH);
    envelope.extend_from_slice(&EMPTY_HEADER);
    envelope.extend_from_slice(&EMPTY_TAG);
    envelope
}

fn golden_eight_byte_envelope() -> Vec<u8> {
    let mut envelope = Vec::with_capacity(HEADER_LENGTH + 8 + TAG_LENGTH);
    envelope.extend_from_slice(&EIGHT_BYTE_HEADER);
    envelope.extend_from_slice(&EIGHT_BYTE_PAYLOAD);
    envelope.extend_from_slice(&EIGHT_BYTE_TAG);
    envelope
}

#[track_caller]
fn assert_auth_operations_reject_without_mutation(fixture: &Fixture) {
    let target_before = FileState::capture(&fixture.target);
    let key_before = FileState::capture(&fixture.key);
    let entries_before = directory_entries(&fixture.root);

    let verify_error = auth::verify_file(&fixture.target, &fixture.key)
        .expect_err("verification unexpectedly accepted an invalid envelope");
    assert!(
        verify_error.is_authentication_failure(),
        "expected an authentication-format failure, got {verify_error:?}"
    );
    assert_eq!(FileState::capture(&fixture.target), target_before);
    assert_eq!(FileState::capture(&fixture.key), key_before);
    assert_eq!(directory_entries(&fixture.root), entries_before);

    let unwrap_error = auth::unwrap_in_place(&fixture.target, &fixture.key)
        .expect_err("unwrap unexpectedly accepted an invalid envelope");
    assert!(
        unwrap_error.is_authentication_failure(),
        "expected an authentication-format failure, got {unwrap_error:?}"
    );
    assert_eq!(FileState::capture(&fixture.target), target_before);
    assert_eq!(FileState::capture(&fixture.key), key_before);
    assert_eq!(directory_entries(&fixture.root), entries_before);
}

#[track_caller]
fn assert_seal_rejects_without_mutation(fixture: &Fixture) {
    let target_before = FileState::capture(&fixture.target);
    let key_before = FileState::capture(&fixture.key);
    let entries_before = directory_entries(&fixture.root);

    let error = auth::seal_in_place(&fixture.target, &fixture.key)
        .expect_err("seal unexpectedly accepted a marker-prefixed file");
    assert!(
        matches!(error, AuthError::AlreadyEnvelope { .. }),
        "unexpected seal failure: {error:?}"
    );
    assert_eq!(FileState::capture(&fixture.target), target_before);
    assert_eq!(FileState::capture(&fixture.key), key_before);
    assert_eq!(directory_entries(&fixture.root), entries_before);
}

fn deterministic_bytes(length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| {
            let index = index as u64;
            index.wrapping_mul(0x9e37_79b9_7f4a_7c15).rotate_left(17) as u8
        })
        .collect()
}

#[test]
fn sealing_empty_payload_matches_independent_golden_vector_exactly() {
    let fixture = Fixture::new("golden-empty", &[], &GOLDEN_KEY);

    auth::seal_in_place(&fixture.target, &fixture.key).expect("seal empty payload");

    assert_eq!(fs::read(&fixture.target).unwrap(), golden_empty_envelope());
    auth::verify_file(&fixture.target, &fixture.key).expect("verify golden empty envelope");
}

#[test]
fn sealing_eight_byte_payload_matches_independent_golden_vector_exactly() {
    let fixture = Fixture::new("golden-eight", &EIGHT_BYTE_PAYLOAD, &GOLDEN_KEY);

    auth::seal_in_place(&fixture.target, &fixture.key).expect("seal eight-byte payload");

    assert_eq!(
        fs::read(&fixture.target).unwrap(),
        golden_eight_byte_envelope()
    );
    auth::verify_file(&fixture.target, &fixture.key).expect("verify golden eight-byte envelope");
}

#[test]
fn manually_authored_golden_envelopes_verify_and_unwrap() {
    for (label, envelope, expected_payload) in [
        ("manual-empty", golden_empty_envelope(), Vec::new()),
        (
            "manual-eight",
            golden_eight_byte_envelope(),
            EIGHT_BYTE_PAYLOAD.to_vec(),
        ),
    ] {
        let fixture = Fixture::new(label, &envelope, &GOLDEN_KEY);
        auth::verify_file(&fixture.target, &fixture.key).expect("verify manual envelope");
        auth::unwrap_in_place(&fixture.target, &fixture.key).expect("unwrap manual envelope");
        assert_eq!(fs::read(&fixture.target).unwrap(), expected_payload);
        assert_eq!(fs::read(&fixture.key).unwrap(), GOLDEN_KEY);
    }
}

#[test]
fn changing_one_bit_in_every_envelope_byte_is_always_rejected_atomically() {
    let valid = golden_eight_byte_envelope();

    for offset in 0..valid.len() {
        let mut corrupted = valid.clone();
        corrupted[offset] ^= 0x01;
        let fixture = Fixture::new(&format!("bit-flip-{offset}"), &corrupted, &GOLDEN_KEY);
        assert_auth_operations_reject_without_mutation(&fixture);
    }
}

#[test]
fn every_truncation_and_appended_data_is_rejected_atomically() {
    let valid = golden_eight_byte_envelope();

    for length in 0..valid.len() {
        let fixture = Fixture::new(
            &format!("truncated-{length}"),
            &valid[..length],
            &GOLDEN_KEY,
        );
        assert_auth_operations_reject_without_mutation(&fixture);
    }

    for (index, suffix) in [
        vec![0x00],
        vec![0xde, 0xad, 0xbe, 0xef],
        EIGHT_BYTE_TAG.to_vec(),
    ]
    .into_iter()
    .enumerate()
    {
        let mut appended = valid.clone();
        appended.extend_from_slice(&suffix);
        let fixture = Fixture::new(&format!("appended-{index}"), &appended, &GOLDEN_KEY);
        assert_auth_operations_reject_without_mutation(&fixture);
    }
}

#[test]
fn noncanonical_header_fields_and_impossible_lengths_are_rejected_atomically() {
    let valid = golden_eight_byte_envelope();
    let mut cases = Vec::new();

    let mut unsupported_version = valid.clone();
    unsupported_version[8..10].copy_from_slice(&2_u16.to_be_bytes());
    cases.push(("version", unsupported_version));

    for declared_header_length in [0_u16, 31, 33, u16::MAX] {
        let mut malformed = valid.clone();
        malformed[10..12].copy_from_slice(&declared_header_length.to_be_bytes());
        cases.push(("header-length", malformed));
    }

    let mut flags = valid.clone();
    flags[12..16].copy_from_slice(&1_u32.to_be_bytes());
    cases.push(("flags", flags));

    let mut reserved = valid.clone();
    reserved[24..32].copy_from_slice(&1_u64.to_be_bytes());
    cases.push(("reserved", reserved));

    for declared_payload_length in [0_u64, 7, 9, u64::MAX] {
        let mut malformed = valid.clone();
        malformed[16..24].copy_from_slice(&declared_payload_length.to_be_bytes());
        cases.push(("payload-length", malformed));
    }

    for (index, (label, malformed)) in cases.into_iter().enumerate() {
        let fixture = Fixture::new(&format!("{label}-{index}"), &malformed, &GOLDEN_KEY);
        assert_auth_operations_reject_without_mutation(&fixture);
    }
}

#[test]
fn wrong_authentication_keys_are_rejected_without_modifying_any_file() {
    for (index, wrong_key) in [
        {
            let mut key = GOLDEN_KEY;
            key[0] ^= 0x01;
            key
        },
        [0xff; AUTH_KEY_LENGTH],
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = Fixture::new(
            &format!("wrong-key-{index}"),
            &golden_eight_byte_envelope(),
            &wrong_key,
        );
        assert_auth_operations_reject_without_mutation(&fixture);
    }
}

#[test]
fn round_trips_empty_and_values_around_the_streaming_boundary() {
    for length in [0, 64 * 1024 - 1, 64 * 1024, 64 * 1024 + 1] {
        let original = deterministic_bytes(length);
        let fixture = Fixture::new(&format!("boundary-{length}"), &original, &GOLDEN_KEY);

        auth::seal_in_place(&fixture.target, &fixture.key).expect("seal boundary payload");
        let envelope = fs::read(&fixture.target).unwrap();
        assert_eq!(envelope.len(), HEADER_LENGTH + original.len() + TAG_LENGTH);
        assert_eq!(
            &envelope[HEADER_LENGTH..HEADER_LENGTH + original.len()],
            original
        );
        auth::verify_file(&fixture.target, &fixture.key).expect("verify boundary envelope");
        auth::unwrap_in_place(&fixture.target, &fixture.key).expect("unwrap boundary envelope");

        assert_eq!(fs::read(&fixture.target).unwrap(), original);
        assert_eq!(fs::read(&fixture.key).unwrap(), GOLDEN_KEY);
        assert_eq!(
            directory_entries(&fixture.root),
            vec![OsString::from("auth.key"), OsString::from("ciphertext.bin")]
        );
    }
}

#[test]
fn every_magic_prefixed_input_is_refused_without_creating_output() {
    for (index, suffix) in [
        Vec::new(),
        vec![0x00],
        b"not an envelope".to_vec(),
        vec![0xa5; HEADER_LENGTH + TAG_LENGTH + 3],
    ]
    .into_iter()
    .enumerate()
    {
        let mut input = MAGIC.to_vec();
        input.extend_from_slice(&suffix);
        let fixture = Fixture::new(&format!("marker-{index}"), &input, &GOLDEN_KEY);
        assert_seal_rejects_without_mutation(&fixture);
    }
}

#[test]
fn sealing_a_valid_envelope_twice_is_refused_and_preserves_the_first_envelope() {
    let fixture = Fixture::new("double-seal", b"raw otp1 ciphertext", &GOLDEN_KEY);
    auth::seal_in_place(&fixture.target, &fixture.key).expect("first seal");
    auth::verify_file(&fixture.target, &fixture.key).expect("first envelope must be valid");

    assert_seal_rejects_without_mutation(&fixture);
    auth::verify_file(&fixture.target, &fixture.key)
        .expect("rejected double seal changed envelope");
}
