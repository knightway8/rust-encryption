#![cfg(target_os = "linux")]

use hmac::{Hmac, Mac};
use otp2_auth::{
    AUTH_KEY_LENGTH, AuthError, HEADER_LENGTH, TAG_FILE_LENGTH, TAG_LENGTH, create_tag, verify_file,
};
use sha2::Sha256;
use std::fmt::Write as _;
use std::fs::{self, File, FileTimes, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

const MAGIC: &[u8; 8] = b"otp2TAG\0";
const VERSION: u16 = 1;
const MAC_DOMAIN: &[u8] = b"otp2-auth/detached/v1\0";
const STREAM_BOUNDARY: usize = 64 * 1024;
const TEST_KEY: [u8; AUTH_KEY_LENGTH] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

type HmacSha256 = Hmac<Sha256>;

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn new() -> Self {
        loop {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "otp2-auth-tag-format-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Self { path },
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("cannot create test directory '{}': {error}", path.display()),
            }
        }
    }

    fn join(&self, name: impl AsRef<Path>) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct Fixture {
    directory: TestDirectory,
    file_path: PathBuf,
    tag_path: PathBuf,
    key_path: PathBuf,
}

impl Fixture {
    fn new(payload: &[u8]) -> Self {
        let directory = TestDirectory::new();
        let file_path = directory.join("payload.bin");
        let tag_path = directory.join("payload.bin.otp2auth");
        let key_path = directory.join("auth.key");
        fs::write(&file_path, payload).unwrap();
        write_private_key(&key_path, &TEST_KEY);
        Self {
            directory,
            file_path,
            tag_path,
            key_path,
        }
    }

    fn create_tag(&self) {
        create_tag(&self.file_path, &self.tag_path, &self.key_path, false).unwrap();
    }

    fn verify(&self) -> Result<(), AuthError> {
        verify_file(&self.file_path, &self.tag_path, &self.key_path)
    }
}

fn write_private_key(path: &Path, key: &[u8; AUTH_KEY_LENGTH]) {
    fs::write(path, key).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn canonical_header(file_len: u64) -> [u8; HEADER_LENGTH] {
    let mut header = [0_u8; HEADER_LENGTH];
    header[..8].copy_from_slice(MAGIC);
    header[8..10].copy_from_slice(&VERSION.to_be_bytes());
    header[10..12].copy_from_slice(&(HEADER_LENGTH as u16).to_be_bytes());
    header[16..24].copy_from_slice(&file_len.to_be_bytes());
    header
}

fn tag_for_parts<'a>(key: &[u8], parts: impl IntoIterator<Item = &'a [u8]>) -> [u8; TAG_LENGTH] {
    let mut mac = HmacSha256::new_from_slice(key).unwrap();
    for part in parts {
        mac.update(part);
    }
    let output = mac.finalize().into_bytes();
    let mut tag = [0_u8; TAG_LENGTH];
    tag.copy_from_slice(&output);
    tag
}

fn sidecar_for_header(
    key: &[u8],
    header: [u8; HEADER_LENGTH],
    payload: &[u8],
) -> [u8; TAG_FILE_LENGTH] {
    let tag = tag_for_parts(key, [MAC_DOMAIN, header.as_slice(), payload]);
    let mut sidecar = [0_u8; TAG_FILE_LENGTH];
    sidecar[..HEADER_LENGTH].copy_from_slice(&header);
    sidecar[HEADER_LENGTH..].copy_from_slice(&tag);
    sidecar
}

fn reference_sidecar(key: &[u8], payload: &[u8]) -> [u8; TAG_FILE_LENGTH] {
    sidecar_for_header(key, canonical_header(payload.len() as u64), payload)
}

fn sidecar_with_tag(header: [u8; HEADER_LENGTH], tag: [u8; TAG_LENGTH]) -> [u8; TAG_FILE_LENGTH] {
    let mut sidecar = [0_u8; TAG_FILE_LENGTH];
    sidecar[..HEADER_LENGTH].copy_from_slice(&header);
    sidecar[HEADER_LENGTH..].copy_from_slice(&tag);
    sidecar
}

fn hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut encoded, "{byte:02x}").unwrap();
    }
    encoded
}

fn assert_invalid_tag(result: Result<(), AuthError>, expected_reason: &str) {
    match result {
        Err(AuthError::InvalidTag { reason, .. }) => assert_eq!(reason, expected_reason),
        other => panic!("expected InvalidTag({expected_reason:?}), got {other:?}"),
    }
}

fn assert_authentication_failed(result: Result<(), AuthError>) {
    match result {
        Err(AuthError::AuthenticationFailed { .. }) => {}
        other => panic!("expected AuthenticationFailed, got {other:?}"),
    }
}

fn deterministic_payload(length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| {
            let index = index as u64;
            index.wrapping_mul(0x9e37_79b9_7f4a_7c15).rotate_left(17) as u8 ^ (index >> 7) as u8
        })
        .collect()
}

#[test]
fn exported_sizes_and_canonical_header_layout_are_frozen() {
    assert_eq!(HEADER_LENGTH, 32);
    assert_eq!(TAG_LENGTH, 32);
    assert_eq!(TAG_FILE_LENGTH, 64);
    assert_eq!(
        canonical_header(0x0102_0304_0506_0708),
        [
            b'o', b't', b'p', b'2', b'T', b'A', b'G', 0, 0, 1, 0, 32, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6,
            7, 8, 0, 0, 0, 0, 0, 0, 0, 0,
        ]
    );
}

#[test]
fn empty_and_binary_golden_vectors_match_exactly() {
    const EMPTY_GOLDEN: &str = concat!(
        "6f74703254414700000100200000000000000000000000000000000000000000",
        "9266f14774cfffb59e8820b06656265e39a401716056b36b1d08725cbc06a974"
    );
    const BINARY_GOLDEN: &str = concat!(
        "6f74703254414700000100200000000000000000000000080000000000000000",
        "28d1248d6c9a9ac49d888197b5ff523b612ea93f12e6447cccdfd2730ac96647"
    );
    let binary = [0x00, 0xff, 0x10, 0x80, 0x0a, 0x0d, 0x41, 0x7f];

    for (payload, expected) in [(&[][..], EMPTY_GOLDEN), (&binary[..], BINARY_GOLDEN)] {
        let fixture = Fixture::new(payload);
        fixture.create_tag();
        let actual = fs::read(&fixture.tag_path).unwrap();
        assert_eq!(actual.len(), TAG_FILE_LENGTH);
        assert_eq!(hex(&actual), expected);
        fixture.verify().unwrap();
    }
}

#[test]
fn independently_authored_canonical_sidecars_verify() {
    for payload in [
        Vec::new(),
        vec![0x00, 0xff, 0x80, 0x7f, b'\n', b'\r'],
        (0_u8..=u8::MAX).collect(),
    ] {
        let fixture = Fixture::new(&payload);
        let sidecar = reference_sidecar(&TEST_KEY, &payload);
        fs::write(&fixture.tag_path, sidecar).unwrap();
        fixture.verify().unwrap();
    }
}

#[test]
fn generated_sidecars_match_the_reference_contract_at_stream_boundaries() {
    let lengths = [
        0,
        1,
        HEADER_LENGTH - 1,
        HEADER_LENGTH,
        HEADER_LENGTH + 1,
        STREAM_BOUNDARY - 1,
        STREAM_BOUNDARY,
        STREAM_BOUNDARY + 1,
        2 * STREAM_BOUNDARY - 1,
        2 * STREAM_BOUNDARY,
        2 * STREAM_BOUNDARY + 1,
    ];

    for length in lengths {
        let payload = deterministic_payload(length);
        let fixture = Fixture::new(&payload);
        fixture.create_tag();
        assert_eq!(
            fs::read(&fixture.tag_path).unwrap(),
            reference_sidecar(&TEST_KEY, &payload),
            "sidecar mismatch for payload length {length}"
        );
        fixture.verify().unwrap();
    }
}

#[test]
fn mac_covers_the_domain_canonical_header_and_exact_payload_in_order() {
    let payload = b"binary\0payload\xffwith\nseparators";
    let fixture = Fixture::new(payload);
    let header = canonical_header(payload.len() as u64);
    let canonical_tag = tag_for_parts(
        &TEST_KEY,
        [MAC_DOMAIN, header.as_slice(), payload.as_slice()],
    );
    fs::write(&fixture.tag_path, sidecar_with_tag(header, canonical_tag)).unwrap();
    fixture.verify().unwrap();

    let wrong_tags = [
        tag_for_parts(&TEST_KEY, [header.as_slice(), payload.as_slice()]),
        tag_for_parts(
            &TEST_KEY,
            [
                b"otp2-auth/detached/v1".as_slice(),
                header.as_slice(),
                payload.as_slice(),
            ],
        ),
        tag_for_parts(
            &TEST_KEY,
            [MAC_DOMAIN, payload.as_slice(), header.as_slice()],
        ),
        tag_for_parts(
            &TEST_KEY,
            [MAC_DOMAIN, header.as_slice(), b"binary\0payload"],
        ),
    ];
    for wrong_tag in wrong_tags {
        fs::write(&fixture.tag_path, sidecar_with_tag(header, wrong_tag)).unwrap();
        assert_authentication_failed(fixture.verify());
    }
}

#[test]
fn every_sidecar_truncation_and_append_is_rejected_as_noncanonical() {
    let payload = deterministic_payload(257);
    let fixture = Fixture::new(&payload);
    let canonical = reference_sidecar(&TEST_KEY, &payload);

    for length in 0..TAG_FILE_LENGTH {
        fs::write(&fixture.tag_path, &canonical[..length]).unwrap();
        assert_invalid_tag(fixture.verify(), "length is not the canonical 64 bytes");
    }
    for appended in 1..=TAG_FILE_LENGTH {
        let mut changed = canonical.to_vec();
        changed.extend((0..appended).map(|index| index as u8));
        fs::write(&fixture.tag_path, changed).unwrap();
        assert_invalid_tag(fixture.verify(), "length is not the canonical 64 bytes");
    }
}

#[test]
fn noncanonical_header_fields_are_rejected_even_with_a_matching_hmac() {
    let payload = deterministic_payload(73);
    let fixture = Fixture::new(&payload);
    let canonical = canonical_header(payload.len() as u64);

    for byte in 0..MAGIC.len() {
        let mut header = canonical;
        header[byte] ^= 0x80;
        fs::write(
            &fixture.tag_path,
            sidecar_for_header(&TEST_KEY, header, &payload),
        )
        .unwrap();
        assert_invalid_tag(fixture.verify(), "marker is missing");
    }

    for version in [0, 2, u16::MAX] {
        let mut header = canonical;
        header[8..10].copy_from_slice(&version.to_be_bytes());
        fs::write(
            &fixture.tag_path,
            sidecar_for_header(&TEST_KEY, header, &payload),
        )
        .unwrap();
        assert_invalid_tag(fixture.verify(), "version is unsupported");
    }

    for header_length in [0, 31, 33, u16::MAX] {
        let mut header = canonical;
        header[10..12].copy_from_slice(&header_length.to_be_bytes());
        fs::write(
            &fixture.tag_path,
            sidecar_for_header(&TEST_KEY, header, &payload),
        )
        .unwrap();
        assert_invalid_tag(fixture.verify(), "header length is not canonical");
    }

    for bit in 0..u32::BITS {
        let mut header = canonical;
        header[12..16].copy_from_slice(&(1_u32 << bit).to_be_bytes());
        fs::write(
            &fixture.tag_path,
            sidecar_for_header(&TEST_KEY, header, &payload),
        )
        .unwrap();
        assert_invalid_tag(fixture.verify(), "flags are unsupported");
    }

    for bit in 0..u64::BITS {
        let mut header = canonical;
        header[24..32].copy_from_slice(&(1_u64 << bit).to_be_bytes());
        fs::write(
            &fixture.tag_path,
            sidecar_for_header(&TEST_KEY, header, &payload),
        )
        .unwrap();
        assert_invalid_tag(fixture.verify(), "reserved fields are nonzero");
    }
}

#[test]
fn every_wrong_declared_length_is_rejected_before_mac_verification() {
    let payload = deterministic_payload(73);
    let fixture = Fixture::new(&payload);
    for declared_length in [0, 1, 72, 74, 255, u32::MAX as u64, u64::MAX] {
        let header = canonical_header(declared_length);
        fs::write(
            &fixture.tag_path,
            sidecar_for_header(&TEST_KEY, header, &payload),
        )
        .unwrap();
        assert_invalid_tag(
            fixture.verify(),
            "declared file length does not match the supplied file",
        );
    }
}

#[test]
fn changing_every_bit_of_a_sidecar_is_always_rejected() {
    let payload = deterministic_payload(257);
    let fixture = Fixture::new(&payload);
    let canonical = reference_sidecar(&TEST_KEY, &payload);

    for byte_index in 0..TAG_FILE_LENGTH {
        for bit in 0..u8::BITS {
            let mut changed = canonical;
            changed[byte_index] ^= 1_u8 << bit;
            fs::write(&fixture.tag_path, changed).unwrap();
            let error = fixture.verify().unwrap_err();
            assert!(
                error.is_authentication_failure(),
                "sidecar byte {byte_index}, bit {bit} produced {error:?}"
            );
        }
    }
}

#[test]
fn changing_every_bit_of_an_all_byte_values_payload_is_always_rejected() {
    let payload: Vec<u8> = (0_u8..=u8::MAX).collect();
    let fixture = Fixture::new(&payload);
    fixture.create_tag();
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&fixture.file_path)
        .unwrap();

    for (byte_index, original) in payload.iter().copied().enumerate() {
        for bit in 0..u8::BITS {
            file.seek(SeekFrom::Start(byte_index as u64)).unwrap();
            file.write_all(&[original ^ (1_u8 << bit)]).unwrap();
            file.flush().unwrap();
            assert_authentication_failed(fixture.verify());
            file.seek(SeekFrom::Start(byte_index as u64)).unwrap();
            file.write_all(&[original]).unwrap();
            file.flush().unwrap();
        }
    }
    drop(file);
    fixture.verify().unwrap();
}

#[test]
fn truncation_append_and_same_length_payload_replacement_all_fail() {
    let original = deterministic_payload(257);
    let fixture = Fixture::new(&original);
    fixture.create_tag();

    fs::write(&fixture.file_path, &original[..original.len() - 1]).unwrap();
    assert_invalid_tag(
        fixture.verify(),
        "declared file length does not match the supplied file",
    );

    let mut appended = original.clone();
    appended.push(0);
    fs::write(&fixture.file_path, appended).unwrap();
    assert_invalid_tag(
        fixture.verify(),
        "declared file length does not match the supplied file",
    );

    let mut replacement = original.clone();
    replacement[0] ^= 1;
    let last = replacement.len() - 1;
    replacement[last] ^= 0x80;
    fs::write(&fixture.file_path, replacement).unwrap();
    assert_authentication_failed(fixture.verify());

    fs::write(&fixture.file_path, original).unwrap();
    fixture.verify().unwrap();
}

#[test]
fn a_wrong_key_is_rejected_without_changing_the_sidecar_or_payload() {
    let payload = deterministic_payload(1025);
    let fixture = Fixture::new(&payload);
    fixture.create_tag();
    let sidecar_before = fs::read(&fixture.tag_path).unwrap();
    let mut wrong_key = TEST_KEY;
    wrong_key[0] ^= 1;
    write_private_key(&fixture.key_path, &wrong_key);

    assert_authentication_failed(fixture.verify());
    assert_eq!(fs::read(&fixture.file_path).unwrap(), payload);
    assert_eq!(fs::read(&fixture.tag_path).unwrap(), sidecar_before);
}

#[test]
fn arbitrary_payload_prefixes_are_accepted() {
    let payloads = [
        b"otp2TAG\0".to_vec(),
        b"otp2TAG\0\xff arbitrary binary bytes\0\x80".to_vec(),
        b"unstructured file prefix".to_vec(),
        [b"otp2TAG\0".as_slice(), &[0_u8; 64]].concat(),
    ];

    for payload in payloads {
        let fixture = Fixture::new(&payload);
        fixture.create_tag();
        fixture.verify().unwrap();
        assert_eq!(fs::read(&fixture.file_path).unwrap(), payload);
    }
}

#[test]
fn tags_bind_content_and_length_but_not_path_inode_mode_or_timestamps() {
    let payload = deterministic_payload(4097);
    let fixture = Fixture::new(&payload);
    fixture.create_tag();

    let renamed_path = fixture.directory.join("renamed payload.bin");
    fs::rename(&fixture.file_path, &renamed_path).unwrap();
    verify_file(&renamed_path, &fixture.tag_path, &fixture.key_path).unwrap();

    let copied_path = fixture.directory.join("copied payload.bin");
    fs::copy(&renamed_path, &copied_path).unwrap();
    fs::set_permissions(&copied_path, fs::Permissions::from_mode(0o400)).unwrap();
    let copied_file = File::open(&copied_path).unwrap();
    copied_file
        .set_times(
            FileTimes::new().set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(1_234_567)),
        )
        .unwrap();
    verify_file(&copied_path, &fixture.tag_path, &fixture.key_path).unwrap();
}

#[test]
fn equal_length_payloads_cannot_swap_sidecars() {
    let directory = TestDirectory::new();
    let key_path = directory.join("auth.key");
    write_private_key(&key_path, &TEST_KEY);
    let first_path = directory.join("first.bin");
    let second_path = directory.join("second.bin");
    let first_tag = directory.join("first.tag");
    let second_tag = directory.join("second.tag");
    let first = deterministic_payload(1024);
    let mut second = first.clone();
    second[0] ^= 0x80;
    second[1023] ^= 1;
    fs::write(&first_path, first).unwrap();
    fs::write(&second_path, second).unwrap();
    create_tag(&first_path, &first_tag, &key_path, false).unwrap();
    create_tag(&second_path, &second_tag, &key_path, false).unwrap();

    assert_authentication_failed(verify_file(&first_path, &second_tag, &key_path));
    assert_authentication_failed(verify_file(&second_path, &first_tag, &key_path));
}

#[derive(Debug, Eq, PartialEq)]
struct PayloadSnapshot {
    bytes: Vec<u8>,
    device: u64,
    inode: u64,
    length: u64,
    links: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

fn payload_snapshot(path: &Path) -> PayloadSnapshot {
    let bytes = fs::read(path).unwrap();
    let metadata = fs::metadata(path).unwrap();
    PayloadSnapshot {
        bytes,
        device: metadata.dev(),
        inode: metadata.ino(),
        length: metadata.len(),
        links: metadata.nlink(),
        mode: metadata.mode(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    }
}

#[test]
fn creating_and_verifying_a_tag_never_mutates_the_payload() {
    let payload = deterministic_payload(STREAM_BOUNDARY + 17);
    let fixture = Fixture::new(&payload);
    fs::set_permissions(&fixture.file_path, fs::Permissions::from_mode(0o400)).unwrap();
    let before = payload_snapshot(&fixture.file_path);

    fixture.create_tag();
    fixture.verify().unwrap();

    assert_eq!(payload_snapshot(&fixture.file_path), before);
}
