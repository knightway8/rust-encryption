use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};
use std::thread;

use otp::{
    AUTH_KEY_LEN, ENVELOPE_HEADER_LEN, ENVELOPE_MAGIC, FORMAT_VERSION, IO_BUFFER_SIZE, KEY_ID_LEN,
    OtpError, PAD_BYTES_OFFSET, PAD_HEADER_LEN, PAD_MAGIC, PAD_SECRET_OFFSET, PAD_STATE_OFFSET,
    PadRole, RandomSource, SUITE_XOR_HMAC_SHA256, TAG_LEN, create_pad_pair_with_rng,
    decrypt_file_with_state, destroy_pad, encrypt_file_with_state, file_length, hex_encode,
    inspect_pad, is_reserved_in, parse_size, xor_exact,
};
use tempfile::{TempDir, tempdir};

const PAD_CHECKSUM_LEN: usize = 32;

#[derive(Debug)]
struct CounterRandom {
    next: u8,
    fills: usize,
}

impl CounterRandom {
    fn new(next: u8) -> Self {
        Self { next, fills: 0 }
    }
}

impl RandomSource for CounterRandom {
    fn fill(&mut self, destination: &mut [u8]) -> otp::Result<()> {
        self.fills += 1;
        for byte in destination {
            *byte = self.next;
            self.next = self.next.wrapping_add(1);
        }
        Ok(())
    }
}

#[derive(Debug)]
struct FailOnFill {
    calls: usize,
    fail_on: usize,
    inner: CounterRandom,
}

impl FailOnFill {
    fn new(fail_on: usize) -> Self {
        Self {
            calls: 0,
            fail_on,
            inner: CounterRandom::new(1),
        }
    }
}

impl RandomSource for FailOnFill {
    fn fill(&mut self, destination: &mut [u8]) -> otp::Result<()> {
        self.calls += 1;
        if self.calls == self.fail_on {
            return Err(OtpError::Random("injected random-source failure".into()));
        }
        self.inner.fill(destination)
    }
}

#[derive(Debug, Default)]
struct ZeroRandom;

impl RandomSource for ZeroRandom {
    fn fill(&mut self, destination: &mut [u8]) -> otp::Result<()> {
        destination.fill(0);
        Ok(())
    }
}

struct CreatePathDuringGeneration {
    path: PathBuf,
    inner: CounterRandom,
    created: bool,
}

impl RandomSource for CreatePathDuringGeneration {
    fn fill(&mut self, destination: &mut [u8]) -> otp::Result<()> {
        if !self.created {
            fs::write(&self.path, b"racing writer").unwrap();
            self.created = true;
        }
        self.inner.fill(destination)
    }
}

struct EncryptedFixture {
    temp: TempDir,
    sender: PathBuf,
    receiver: PathBuf,
    encrypted: PathBuf,
    state: PathBuf,
    plaintext: Vec<u8>,
    id: [u8; KEY_ID_LEN],
}

fn counter_bytes(mut next: u8, length: usize) -> Vec<u8> {
    (0..length)
        .map(|_| {
            let byte = next;
            next = next.wrapping_add(1);
            byte
        })
        .collect()
}

fn patterned_bytes(length: usize, salt: u8) -> Vec<u8> {
    (0..length)
        .map(|index| {
            (index as u8)
                .wrapping_mul(131)
                .wrapping_add(salt)
                .rotate_left((index % 8) as u32)
        })
        .collect()
}

fn entry_names(directory: &Path) -> BTreeSet<String> {
    fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect()
}

fn be_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn be_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn assert_invalid_pad(path: &Path, case: &str) {
    match inspect_pad(path) {
        Err(OtpError::InvalidPad(_)) => {}
        other => panic!("{case}: expected InvalidPad, got {other:?}"),
    }
}

fn assert_receiver_fresh(fixture: &EncryptedFixture) {
    let info = inspect_pad(&fixture.receiver).unwrap();
    assert!(!info.consumed, "receiver pad unexpectedly consumed");
    assert!(
        !is_reserved_in(&fixture.state, &fixture.id, PadRole::Receiver).unwrap(),
        "receiver role unexpectedly reserved"
    );
}

fn encrypted_fixture(length: usize) -> EncryptedFixture {
    let temp = tempdir().unwrap();
    let sender = temp.path().join("sender.pad");
    let receiver = temp.path().join("receiver.pad");
    let input = temp.path().join("plain.bin");
    let encrypted = temp.path().join("encrypted.otp");
    let state = temp.path().join("state");
    let plaintext = patterned_bytes(length, 0x53);
    fs::write(&input, &plaintext).unwrap();

    let mut random = CounterRandom::new(23);
    create_pad_pair_with_rng(length as u64, &sender, &receiver, &mut random).unwrap();
    let id = inspect_pad(&receiver).unwrap().id;
    encrypt_file_with_state(&input, &sender, &encrypted, &state).unwrap();

    EncryptedFixture {
        temp,
        sender,
        receiver,
        encrypted,
        state,
        plaintext,
        id,
    }
}

fn decrypt_mutation(fixture: &EncryptedFixture, bytes: &[u8]) -> OtpError {
    let mutated = fixture.temp.path().join("mutated.otp");
    let output = fixture.temp.path().join("mutated.out");
    assert!(!output.exists());
    fs::write(&mutated, bytes).unwrap();
    let error = decrypt_file_with_state(&mutated, &fixture.receiver, &output, &fixture.state)
        .expect_err("mutated envelope unexpectedly decrypted");
    assert!(!output.exists(), "failure committed a plaintext output");
    error
}

#[test]
fn xor_exact_has_known_answers_and_handles_every_byte_value() {
    let input = [0x00, 0xff, 0x55, 0xaa, 0x0f, 0xf0];
    let pad = [0xff, 0x0f, 0xaa, 0x55, 0xf0, 0x0f];
    assert_eq!(
        xor_exact(&input, &pad).unwrap(),
        [0xff, 0xf0, 0xff, 0xff, 0xff, 0xff]
    );

    let all_bytes: Vec<u8> = (0..=u8::MAX).collect();
    let complements: Vec<u8> = all_bytes.iter().map(|byte| !byte).collect();
    assert_eq!(
        xor_exact(&all_bytes, &complements).unwrap(),
        vec![0xff; 256]
    );
    assert_eq!(xor_exact(&all_bytes, &[0; 256]).unwrap(), all_bytes);
    assert_eq!(xor_exact(&[], &[]).unwrap(), Vec::<u8>::new());
}

#[test]
fn xor_exact_is_an_involution_across_boundary_sizes() {
    for length in [
        0,
        1,
        2,
        31,
        32,
        63,
        64,
        65,
        255,
        256,
        IO_BUFFER_SIZE - 1,
        IO_BUFFER_SIZE,
        IO_BUFFER_SIZE + 1,
    ] {
        let input = patterned_bytes(length, 0x31);
        let pad = patterned_bytes(length, 0xa7);
        let ciphertext = xor_exact(&input, &pad).unwrap();
        assert_eq!(ciphertext.len(), length, "length {length}");
        assert_eq!(
            xor_exact(&ciphertext, &pad).unwrap(),
            input,
            "length {length}"
        );
    }
}

#[test]
fn xor_exact_rejects_both_short_and_long_pads() {
    match xor_exact(&[1, 2, 3], &[9, 8]).unwrap_err() {
        OtpError::LengthMismatch {
            pad_bytes: 2,
            input_bytes: 3,
        } => {}
        error => panic!("unexpected error: {error:?}"),
    }
    match xor_exact(&[1, 2], &[9, 8, 7]).unwrap_err() {
        OtpError::LengthMismatch {
            pad_bytes: 3,
            input_bytes: 2,
        } => {}
        error => panic!("unexpected error: {error:?}"),
    }
}

#[test]
fn parse_size_accepts_decimal_binary_case_and_whitespace_forms() {
    let cases = [
        ("0", 0),
        (" 42 ", 42),
        ("1B", 1),
        ("2 b", 2),
        ("3KB", 3_000),
        ("4 mb", 4_000_000),
        ("5Gb", 5_000_000_000),
        ("6 TB", 6_000_000_000_000),
        ("7KiB", 7 * 1_024),
        ("8 kib", 8 * 1_024),
        ("9MiB", 9 * 1_048_576),
        ("10 GiB", 10 * (1_u64 << 30)),
        ("11TiB", 11 * (1_u64 << 40)),
        ("00012kb", 12_000),
    ];
    for (text, expected) in cases {
        assert_eq!(parse_size(text), Ok(expected), "{text:?}");
    }
}

#[test]
fn parse_size_rejects_bad_syntax_unknown_units_and_overflow() {
    for text in [
        "",
        "   ",
        "-1",
        "+1",
        "one",
        "1.5MiB",
        "1Ki",
        "1bytes",
        "1 MB extra",
        "1 0",
        "18446744073709551616",
        "18446744073709551615KiB",
        "18446744073709552KB",
        "１KiB",
    ] {
        assert!(parse_size(text).is_err(), "{text:?} unexpectedly parsed");
    }
}

#[test]
fn deterministic_generation_writes_matching_secrets_and_precise_metadata() {
    let temp = tempdir().unwrap();
    let sender = temp.path().join("sender.pad");
    let receiver = temp.path().join("receiver.pad");
    let capacity = 73_usize;
    let mut random = CounterRandom::new(1);

    create_pad_pair_with_rng(capacity as u64, &sender, &receiver, &mut random).unwrap();
    assert_eq!(random.fills, 3);

    let sender_bytes = fs::read(&sender).unwrap();
    let receiver_bytes = fs::read(&receiver).unwrap();
    let expected_length = PAD_HEADER_LEN + AUTH_KEY_LEN + capacity + PAD_CHECKSUM_LEN;
    assert_eq!(sender_bytes.len(), expected_length);
    assert_eq!(receiver_bytes.len(), expected_length);

    for bytes in [&sender_bytes, &receiver_bytes] {
        assert_eq!(&bytes[0..8], PAD_MAGIC);
        assert_eq!(be_u16(bytes, 8), FORMAT_VERSION);
        assert_eq!(be_u16(bytes, 10), PAD_HEADER_LEN as u16);
        assert_eq!(be_u16(bytes, 12), SUITE_XOR_HMAC_SHA256);
        assert_eq!(&bytes[14..16], &[0, 0]);
        assert_eq!(bytes[PAD_STATE_OFFSET as usize], 0);
        assert_eq!(be_u64(bytes, 56), capacity as u64);
        assert!(bytes[18..24].iter().all(|byte| *byte == 0));
        assert!(bytes[64..80].iter().all(|byte| *byte == 0));
    }
    assert_eq!(sender_bytes[16], PadRole::Sender as u8);
    assert_eq!(receiver_bytes[16], PadRole::Receiver as u8);

    let expected_id = counter_bytes(1, KEY_ID_LEN);
    let expected_authentication_key = counter_bytes(33, AUTH_KEY_LEN);
    let expected_pad = counter_bytes(65, capacity);
    assert_eq!(&sender_bytes[24..56], expected_id.as_slice());
    assert_eq!(
        &sender_bytes[PAD_SECRET_OFFSET as usize..PAD_BYTES_OFFSET as usize],
        expected_authentication_key.as_slice()
    );
    assert_eq!(
        &sender_bytes[PAD_BYTES_OFFSET as usize..PAD_BYTES_OFFSET as usize + capacity],
        expected_pad.as_slice()
    );
    assert_eq!(
        &sender_bytes[PAD_SECRET_OFFSET as usize..expected_length - PAD_CHECKSUM_LEN],
        &receiver_bytes[PAD_SECRET_OFFSET as usize..expected_length - PAD_CHECKSUM_LEN]
    );
    assert_ne!(
        &sender_bytes[expected_length - PAD_CHECKSUM_LEN..],
        &receiver_bytes[expected_length - PAD_CHECKSUM_LEN..],
        "role metadata must be covered by each pad checksum"
    );

    let sender_info = inspect_pad(&sender).unwrap();
    let receiver_info = inspect_pad(&receiver).unwrap();
    assert_eq!(sender_info.id.as_slice(), expected_id.as_slice());
    assert_eq!(sender_info.id, receiver_info.id);
    assert_eq!(sender_info.capacity, capacity as u64);
    assert_eq!(receiver_info.capacity, capacity as u64);
    assert_eq!(sender_info.role, PadRole::Sender);
    assert_eq!(receiver_info.role, PadRole::Receiver);
    assert!(!sender_info.consumed);
    assert!(!receiver_info.consumed);
    assert_eq!(sender_info.id_hex(), hex_encode(&sender_info.id));
}

#[test]
fn generation_is_atomic_when_randomness_fails() {
    let temp = tempdir().unwrap();
    let sender = temp.path().join("sender.pad");
    let receiver = temp.path().join("receiver.pad");
    let before = entry_names(temp.path());
    let mut random = FailOnFill::new(2);

    let error = create_pad_pair_with_rng(257, &sender, &receiver, &mut random).unwrap_err();
    assert!(matches!(error, OtpError::Random(_)));
    assert_eq!(random.calls, 2);
    assert!(!sender.exists());
    assert!(!receiver.exists());
    assert_eq!(entry_names(temp.path()), before, "temporary files leaked");
}

#[test]
fn generation_rejects_an_all_zero_identifier_atomically() {
    let temp = tempdir().unwrap();
    let sender = temp.path().join("sender.pad");
    let receiver = temp.path().join("receiver.pad");
    let before = entry_names(temp.path());

    let error = create_pad_pair_with_rng(8, &sender, &receiver, &mut ZeroRandom).unwrap_err();
    assert!(matches!(error, OtpError::Random(_)));
    assert!(!sender.exists());
    assert!(!receiver.exists());
    assert_eq!(entry_names(temp.path()), before, "temporary files leaked");
}

#[test]
fn generation_rejects_capacity_overflow_before_creating_files() {
    let temp = tempdir().unwrap();
    let sender = temp.path().join("sender.pad");
    let receiver = temp.path().join("receiver.pad");
    let mut random = CounterRandom::new(1);

    let error = create_pad_pair_with_rng(u64::MAX, &sender, &receiver, &mut random).unwrap_err();
    assert!(matches!(error, OtpError::InvalidPad(_)));
    assert_eq!(random.fills, 0);
    assert_eq!(entry_names(temp.path()), BTreeSet::new());
}

#[test]
fn pad_parser_rejects_header_secret_checksum_size_and_trailing_corruption() {
    let temp = tempdir().unwrap();
    let sender = temp.path().join("sender.pad");
    let receiver = temp.path().join("receiver.pad");
    let mutated = temp.path().join("mutated.pad");
    let mut random = CounterRandom::new(7);
    create_pad_pair_with_rng(17, &sender, &receiver, &mut random).unwrap();
    let pristine = fs::read(&receiver).unwrap();

    let mut cases: Vec<(&str, Vec<u8>)> = Vec::new();

    let mut bytes = pristine.clone();
    bytes[0] ^= 0x80;
    cases.push(("magic", bytes));

    let mut bytes = pristine.clone();
    bytes[8..10].copy_from_slice(&(FORMAT_VERSION + 1).to_be_bytes());
    cases.push(("version", bytes));

    let mut bytes = pristine.clone();
    bytes[10..12].copy_from_slice(&((PAD_HEADER_LEN - 1) as u16).to_be_bytes());
    cases.push(("header length", bytes));

    let mut bytes = pristine.clone();
    bytes[12..14].copy_from_slice(&(SUITE_XOR_HMAC_SHA256 + 1).to_be_bytes());
    cases.push(("suite", bytes));

    let mut bytes = pristine.clone();
    bytes[14] = 1;
    cases.push(("flags", bytes));

    let mut bytes = pristine.clone();
    bytes[16] = 99;
    cases.push(("role", bytes));

    let mut bytes = pristine.clone();
    bytes[PAD_STATE_OFFSET as usize] = 2;
    cases.push(("consumption state", bytes));

    let mut bytes = pristine.clone();
    bytes[18] = 1;
    cases.push(("reserved header byte", bytes));

    let mut bytes = pristine.clone();
    bytes[24..56].fill(0);
    cases.push(("zero identifier", bytes));

    let mut bytes = pristine.clone();
    bytes[63] ^= 1;
    cases.push(("declared capacity", bytes));

    let mut bytes = pristine.clone();
    bytes[PAD_SECRET_OFFSET as usize] ^= 1;
    cases.push(("authentication key", bytes));

    let mut bytes = pristine.clone();
    bytes[PAD_BYTES_OFFSET as usize] ^= 1;
    cases.push(("xor pad byte", bytes));

    let mut bytes = pristine.clone();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    cases.push(("checksum", bytes));

    let mut bytes = pristine.clone();
    bytes.push(0);
    cases.push(("trailing byte", bytes));

    cases.push(("empty file", Vec::new()));
    cases.push(("truncated header", pristine[..PAD_HEADER_LEN - 1].to_vec()));
    cases.push((
        "truncated secret",
        pristine[..PAD_BYTES_OFFSET as usize].to_vec(),
    ));
    cases.push((
        "truncated checksum",
        pristine[..pristine.len() - 1].to_vec(),
    ));

    for (name, bytes) in cases {
        fs::write(&mutated, bytes).unwrap();
        assert_invalid_pad(&mutated, name);
    }
    inspect_pad(&receiver).unwrap();
}

#[test]
fn consumed_state_is_checksum_normalized_but_other_state_values_are_not() {
    let temp = tempdir().unwrap();
    let sender = temp.path().join("sender.pad");
    let receiver = temp.path().join("receiver.pad");
    let consumed_copy = temp.path().join("consumed-copy.pad");
    let invalid_copy = temp.path().join("invalid-copy.pad");
    let mut random = CounterRandom::new(9);
    create_pad_pair_with_rng(5, &sender, &receiver, &mut random).unwrap();

    let mut bytes = fs::read(&receiver).unwrap();
    bytes[PAD_STATE_OFFSET as usize] = 1;
    fs::write(&consumed_copy, &bytes).unwrap();
    let info = inspect_pad(&consumed_copy).unwrap();
    assert!(info.consumed);

    bytes[PAD_STATE_OFFSET as usize] = 2;
    fs::write(&invalid_copy, bytes).unwrap();
    assert_invalid_pad(&invalid_copy, "unknown consumption state");
}

#[test]
fn authenticated_file_round_trips_cover_streaming_boundaries() {
    let temp = tempdir().unwrap();
    let sizes = [
        0,
        1,
        31,
        32,
        63,
        64,
        65,
        IO_BUFFER_SIZE - 1,
        IO_BUFFER_SIZE,
        IO_BUFFER_SIZE + 1,
        2 * IO_BUFFER_SIZE + 17,
    ];

    for (case, size) in sizes.into_iter().enumerate() {
        let directory = temp.path().join(format!("case-{case}-{size}"));
        fs::create_dir(&directory).unwrap();
        let sender = directory.join("sender.pad");
        let receiver = directory.join("receiver.pad");
        let input = directory.join("plain.bin");
        let encrypted = directory.join("encrypted.otp");
        let output = directory.join("decrypted.bin");
        let state = directory.join("state");
        let plaintext = patterned_bytes(size, case as u8);
        fs::write(&input, &plaintext).unwrap();

        let mut random = CounterRandom::new((case as u8).wrapping_add(1));
        create_pad_pair_with_rng(size as u64, &sender, &receiver, &mut random).unwrap();
        let id = inspect_pad(&sender).unwrap().id;
        encrypt_file_with_state(&input, &sender, &encrypted, &state).unwrap();

        let envelope = fs::read(&encrypted).unwrap();
        let pad = fs::read(&sender).unwrap();
        assert_eq!(envelope.len(), ENVELOPE_HEADER_LEN + size + TAG_LEN);
        assert_eq!(
            &envelope[ENVELOPE_HEADER_LEN..ENVELOPE_HEADER_LEN + size],
            xor_exact(
                &plaintext,
                &pad[PAD_BYTES_OFFSET as usize..PAD_BYTES_OFFSET as usize + size]
            )
            .unwrap()
            .as_slice(),
            "ciphertext mismatch at size {size}"
        );
        assert!(inspect_pad(&sender).unwrap().consumed);
        assert!(!inspect_pad(&receiver).unwrap().consumed);
        assert!(is_reserved_in(&state, &id, PadRole::Sender).unwrap());
        assert!(!is_reserved_in(&state, &id, PadRole::Receiver).unwrap());

        decrypt_file_with_state(&encrypted, &receiver, &output, &state).unwrap();
        assert_eq!(fs::read(&output).unwrap(), plaintext, "size {size}");
        assert_eq!(file_length(&output).unwrap(), size as u64);
        assert!(inspect_pad(&receiver).unwrap().consumed);
        assert!(is_reserved_in(&state, &id, PadRole::Receiver).unwrap());
    }
}

#[test]
fn envelope_metadata_and_ciphertext_match_the_public_format_contract() {
    let fixture = encrypted_fixture(37);
    let envelope = fs::read(&fixture.encrypted).unwrap();
    let receiver_pad = fs::read(&fixture.receiver).unwrap();

    assert_eq!(envelope.len(), ENVELOPE_HEADER_LEN + 37 + TAG_LEN);
    assert_eq!(&envelope[0..8], ENVELOPE_MAGIC);
    assert_eq!(be_u16(&envelope, 8), FORMAT_VERSION);
    assert_eq!(be_u16(&envelope, 10), ENVELOPE_HEADER_LEN as u16);
    assert_eq!(be_u16(&envelope, 12), SUITE_XOR_HMAC_SHA256);
    assert_eq!(&envelope[14..16], &[0, 0]);
    assert_eq!(&envelope[16..48], fixture.id.as_slice());
    assert_eq!(be_u64(&envelope, 48), 37);
    assert!(envelope[56..64].iter().all(|byte| *byte == 0));

    let expected_ciphertext = xor_exact(
        &fixture.plaintext,
        &receiver_pad[PAD_BYTES_OFFSET as usize..PAD_BYTES_OFFSET as usize + 37],
    )
    .unwrap();
    assert_eq!(
        &envelope[ENVELOPE_HEADER_LEN..ENVELOPE_HEADER_LEN + 37],
        expected_ciphertext.as_slice()
    );
    assert_eq!(&envelope[ENVELOPE_HEADER_LEN + 37..].len(), &TAG_LEN);
}

#[test]
fn malformed_envelope_headers_and_trailing_data_are_rejected_atomically() {
    let fixture = encrypted_fixture(19);
    let pristine = fs::read(&fixture.encrypted).unwrap();
    let mut cases: Vec<(&str, Vec<u8>)> = Vec::new();

    let mut bytes = pristine.clone();
    bytes[0] ^= 0x80;
    cases.push(("magic", bytes));

    let mut bytes = pristine.clone();
    bytes[8..10].copy_from_slice(&(FORMAT_VERSION + 1).to_be_bytes());
    cases.push(("version", bytes));

    let mut bytes = pristine.clone();
    bytes[10..12].copy_from_slice(&((ENVELOPE_HEADER_LEN - 1) as u16).to_be_bytes());
    cases.push(("header length", bytes));

    let mut bytes = pristine.clone();
    bytes[12..14].copy_from_slice(&(SUITE_XOR_HMAC_SHA256 + 1).to_be_bytes());
    cases.push(("suite", bytes));

    let mut bytes = pristine.clone();
    bytes[14] = 1;
    cases.push(("flags", bytes));

    let mut bytes = pristine.clone();
    bytes[16..48].fill(0);
    cases.push(("zero identifier", bytes));

    let mut bytes = pristine.clone();
    bytes[55] ^= 1;
    cases.push(("declared plaintext length", bytes));

    let mut bytes = pristine.clone();
    bytes[56] = 1;
    cases.push(("reserved header byte", bytes));

    let mut bytes = pristine.clone();
    bytes.push(0);
    cases.push(("trailing byte", bytes));

    for (name, bytes) in cases {
        let error = decrypt_mutation(&fixture, &bytes);
        assert!(
            matches!(error, OtpError::InvalidEnvelope(_)),
            "{name}: expected InvalidEnvelope, got {error:?}"
        );
    }
    assert_receiver_fresh(&fixture);

    let output = fixture.temp.path().join("valid-after-malformed.out");
    decrypt_file_with_state(
        &fixture.encrypted,
        &fixture.receiver,
        &output,
        &fixture.state,
    )
    .unwrap();
    assert_eq!(fs::read(output).unwrap(), fixture.plaintext);
}

#[test]
fn every_ciphertext_and_tag_byte_is_authenticated_before_output() {
    let fixture = encrypted_fixture(41);
    let pristine = fs::read(&fixture.encrypted).unwrap();

    for offset in ENVELOPE_HEADER_LEN..pristine.len() {
        let mut bytes = pristine.clone();
        bytes[offset] ^= 1;
        let error = decrypt_mutation(&fixture, &bytes);
        assert!(
            matches!(error, OtpError::AuthenticationFailed),
            "offset {offset}: expected AuthenticationFailed, got {error:?}"
        );
    }
    assert_receiver_fresh(&fixture);

    let output = fixture.temp.path().join("valid-after-tamper.out");
    decrypt_file_with_state(
        &fixture.encrypted,
        &fixture.receiver,
        &output,
        &fixture.state,
    )
    .unwrap();
    assert_eq!(fs::read(output).unwrap(), fixture.plaintext);
}

#[test]
fn every_envelope_truncation_boundary_is_rejected_without_consuming_the_pad() {
    let fixture = encrypted_fixture(9);
    let pristine = fs::read(&fixture.encrypted).unwrap();

    for cut in 0..pristine.len() {
        let error = decrypt_mutation(&fixture, &pristine[..cut]);
        assert!(
            matches!(error, OtpError::InvalidEnvelope(_)),
            "cut {cut}: expected InvalidEnvelope, got {error:?}"
        );
    }
    assert_receiver_fresh(&fixture);

    let output = fixture.temp.path().join("valid-after-truncation.out");
    decrypt_file_with_state(
        &fixture.encrypted,
        &fixture.receiver,
        &output,
        &fixture.state,
    )
    .unwrap();
    assert_eq!(fs::read(output).unwrap(), fixture.plaintext);
}

#[test]
fn envelope_identifier_mutation_and_an_unrelated_pad_are_wrong_pad_errors() {
    let fixture = encrypted_fixture(29);
    let pristine = fs::read(&fixture.encrypted).unwrap();

    let mut changed_id = pristine.clone();
    changed_id[16] ^= 1;
    let error = decrypt_mutation(&fixture, &changed_id);
    assert!(matches!(error, OtpError::WrongPad));
    assert_receiver_fresh(&fixture);

    let other_sender = fixture.temp.path().join("other-sender.pad");
    let other_receiver = fixture.temp.path().join("other-receiver.pad");
    let other_state = fixture.temp.path().join("other-state");
    let other_output = fixture.temp.path().join("other-output.bin");
    let mut random = CounterRandom::new(173);
    create_pad_pair_with_rng(29, &other_sender, &other_receiver, &mut random).unwrap();
    let other_info = inspect_pad(&other_receiver).unwrap();

    let error = decrypt_file_with_state(
        &fixture.encrypted,
        &other_receiver,
        &other_output,
        &other_state,
    )
    .unwrap_err();
    assert!(matches!(error, OtpError::WrongPad));
    assert!(!other_output.exists());
    assert!(!inspect_pad(&other_receiver).unwrap().consumed);
    assert!(!is_reserved_in(&other_state, &other_info.id, PadRole::Receiver).unwrap());
}

#[test]
fn corrupt_pad_material_is_rejected_before_output_or_usage_reservation() {
    let fixture = encrypted_fixture(23);
    let corrupt_receiver = fixture.temp.path().join("corrupt-receiver.pad");
    let output = fixture.temp.path().join("corrupt-pad.out");
    let mut bytes = fs::read(&fixture.receiver).unwrap();
    bytes[PAD_BYTES_OFFSET as usize + 7] ^= 0x40;
    fs::write(&corrupt_receiver, bytes).unwrap();

    let error = decrypt_file_with_state(
        &fixture.encrypted,
        &corrupt_receiver,
        &output,
        &fixture.state,
    )
    .unwrap_err();
    assert!(matches!(error, OtpError::InvalidPad(_)));
    assert!(!output.exists());
    assert!(!inspect_pad(&fixture.receiver).unwrap().consumed);
    assert!(!is_reserved_in(&fixture.state, &fixture.id, PadRole::Receiver).unwrap());
}

#[test]
fn sender_and_receiver_roles_are_enforced_before_use() {
    let temp = tempdir().unwrap();
    let sender = temp.path().join("sender.pad");
    let sender_copy = temp.path().join("sender-copy.pad");
    let receiver = temp.path().join("receiver.pad");
    let input = temp.path().join("plain.bin");
    let encrypted = temp.path().join("encrypted.otp");
    let state = temp.path().join("state");
    fs::write(&input, b"role-check").unwrap();
    let mut random = CounterRandom::new(1);
    create_pad_pair_with_rng(10, &sender, &receiver, &mut random).unwrap();
    fs::copy(&sender, &sender_copy).unwrap();

    let wrong_encrypt_output = temp.path().join("wrong-encrypt.otp");
    let error =
        encrypt_file_with_state(&input, &receiver, &wrong_encrypt_output, &state).unwrap_err();
    match error {
        OtpError::WrongPadRole {
            expected: PadRole::Sender,
            actual: PadRole::Receiver,
        } => {}
        error => panic!("unexpected error: {error:?}"),
    }
    assert!(!wrong_encrypt_output.exists());
    assert!(!inspect_pad(&receiver).unwrap().consumed);

    encrypt_file_with_state(&input, &sender, &encrypted, &state).unwrap();
    let wrong_decrypt_output = temp.path().join("wrong-decrypt.bin");
    let error = decrypt_file_with_state(&encrypted, &sender_copy, &wrong_decrypt_output, &state)
        .unwrap_err();
    match error {
        OtpError::WrongPadRole {
            expected: PadRole::Receiver,
            actual: PadRole::Sender,
        } => {}
        error => panic!("unexpected error: {error:?}"),
    }
    assert!(!wrong_decrypt_output.exists());
    assert!(!inspect_pad(&sender_copy).unwrap().consumed);
}

#[test]
fn encryption_requires_exact_capacity_without_consuming_on_mismatch() {
    let temp = tempdir().unwrap();
    let sender = temp.path().join("sender.pad");
    let receiver = temp.path().join("receiver.pad");
    let state = temp.path().join("state");
    let mut random = CounterRandom::new(1);
    create_pad_pair_with_rng(16, &sender, &receiver, &mut random).unwrap();
    let info = inspect_pad(&sender).unwrap();

    for (name, length) in [("short", 15), ("long", 17)] {
        let input = temp.path().join(format!("{name}.bin"));
        let output = temp.path().join(format!("{name}.otp"));
        fs::write(&input, patterned_bytes(length, 4)).unwrap();
        let error = encrypt_file_with_state(&input, &sender, &output, &state).unwrap_err();
        match error {
            OtpError::LengthMismatch {
                pad_bytes: 16,
                input_bytes,
            } => assert_eq!(input_bytes, length as u64),
            error => panic!("{name}: unexpected error: {error:?}"),
        }
        assert!(!output.exists());
        assert!(!inspect_pad(&sender).unwrap().consumed);
        assert!(!is_reserved_in(&state, &info.id, PadRole::Sender).unwrap());
    }

    let exact = temp.path().join("exact.bin");
    let encrypted = temp.path().join("exact.otp");
    fs::write(&exact, patterned_bytes(16, 8)).unwrap();
    encrypt_file_with_state(&exact, &sender, &encrypted, &state).unwrap();
    assert!(encrypted.exists());
    assert!(inspect_pad(&sender).unwrap().consumed);
    assert!(is_reserved_in(&state, &info.id, PadRole::Sender).unwrap());
}

#[test]
fn sender_reuse_and_an_unconsumed_copy_are_blocked_by_durable_state() {
    let temp = tempdir().unwrap();
    let sender = temp.path().join("sender.pad");
    let sender_copy = temp.path().join("sender-copy.pad");
    let receiver = temp.path().join("receiver.pad");
    let input = temp.path().join("plain.bin");
    let first_output = temp.path().join("first.otp");
    let copied_output = temp.path().join("copied.otp");
    let reused_output = temp.path().join("reused.otp");
    let state = temp.path().join("state");
    fs::write(&input, b"single-use!").unwrap();
    let mut random = CounterRandom::new(1);
    create_pad_pair_with_rng(11, &sender, &receiver, &mut random).unwrap();
    fs::copy(&sender, &sender_copy).unwrap();
    let id = inspect_pad(&sender).unwrap().id;

    encrypt_file_with_state(&input, &sender, &first_output, &state).unwrap();
    assert!(is_reserved_in(&state, &id, PadRole::Sender).unwrap());
    assert!(inspect_pad(&sender).unwrap().consumed);

    let before = entry_names(temp.path());
    let error = encrypt_file_with_state(&input, &sender_copy, &copied_output, &state).unwrap_err();
    assert!(matches!(error, OtpError::PadAlreadyUsed));
    assert!(!copied_output.exists());
    assert!(!inspect_pad(&sender_copy).unwrap().consumed);
    assert_eq!(entry_names(temp.path()), before, "temporary output leaked");

    let error = encrypt_file_with_state(&input, &sender, &reused_output, &state).unwrap_err();
    assert!(matches!(error, OtpError::PadAlreadyUsed));
    assert!(!reused_output.exists());
}

#[test]
fn receiver_reuse_and_an_unconsumed_copy_are_blocked_atomically() {
    let fixture = encrypted_fixture(27);
    let receiver_copy = fixture.temp.path().join("receiver-copy.pad");
    let first_output = fixture.temp.path().join("first-plain.bin");
    let copied_output = fixture.temp.path().join("copied-plain.bin");
    let reused_output = fixture.temp.path().join("reused-plain.bin");
    fs::copy(&fixture.receiver, &receiver_copy).unwrap();

    decrypt_file_with_state(
        &fixture.encrypted,
        &fixture.receiver,
        &first_output,
        &fixture.state,
    )
    .unwrap();
    assert_eq!(fs::read(&first_output).unwrap(), fixture.plaintext);
    assert!(is_reserved_in(&fixture.state, &fixture.id, PadRole::Receiver).unwrap());

    let before = entry_names(fixture.temp.path());
    let error = decrypt_file_with_state(
        &fixture.encrypted,
        &receiver_copy,
        &copied_output,
        &fixture.state,
    )
    .unwrap_err();
    assert!(matches!(error, OtpError::PadAlreadyUsed));
    assert!(!copied_output.exists());
    assert!(!inspect_pad(&receiver_copy).unwrap().consumed);
    assert_eq!(
        entry_names(fixture.temp.path()),
        before,
        "authenticated temporary plaintext leaked"
    );

    let error = decrypt_file_with_state(
        &fixture.encrypted,
        &fixture.receiver,
        &reused_output,
        &fixture.state,
    )
    .unwrap_err();
    assert!(matches!(error, OtpError::PadAlreadyUsed));
    assert!(!reused_output.exists());
}

#[test]
fn concurrent_sender_copies_cannot_both_reserve_the_same_key_id() {
    let temp = tempdir().unwrap();
    let sender_a = temp.path().join("sender-a.pad");
    let sender_b = temp.path().join("sender-b.pad");
    let receiver = temp.path().join("receiver.pad");
    let input = temp.path().join("plain.bin");
    let output_a = temp.path().join("a.otp");
    let output_b = temp.path().join("b.otp");
    let state = temp.path().join("state");
    fs::write(&input, patterned_bytes(1024, 5)).unwrap();
    let mut random = CounterRandom::new(1);
    create_pad_pair_with_rng(1024, &sender_a, &receiver, &mut random).unwrap();
    fs::copy(&sender_a, &sender_b).unwrap();
    let id = inspect_pad(&sender_a).unwrap().id;

    let barrier = Arc::new(Barrier::new(2));
    let spawn_encrypt = |pad: PathBuf, output: PathBuf| {
        let barrier = Arc::clone(&barrier);
        let input = input.clone();
        let state = state.clone();
        thread::spawn(move || {
            barrier.wait();
            encrypt_file_with_state(input, pad, output, state)
        })
    };
    let first = spawn_encrypt(sender_a.clone(), output_a.clone());
    let second = spawn_encrypt(sender_b.clone(), output_b.clone());
    let results = [first.join().unwrap(), second.join().unwrap()];

    let mut successes = 0;
    let mut reuse_errors = 0;
    for result in results {
        match result {
            Ok(()) => successes += 1,
            Err(OtpError::PadAlreadyUsed) => reuse_errors += 1,
            Err(error) => panic!("unexpected concurrent result: {error:?}"),
        }
    }
    assert_eq!(successes, 1);
    assert_eq!(reuse_errors, 1);
    assert_eq!(
        usize::from(output_a.exists()) + usize::from(output_b.exists()),
        1
    );
    assert_eq!(
        usize::from(inspect_pad(&sender_a).unwrap().consumed)
            + usize::from(inspect_pad(&sender_b).unwrap().consumed),
        1
    );
    assert!(is_reserved_in(&state, &id, PadRole::Sender).unwrap());
}

#[test]
fn encryption_refuses_existing_output_without_consuming_or_modifying_it() {
    let temp = tempdir().unwrap();
    let sender = temp.path().join("sender.pad");
    let receiver = temp.path().join("receiver.pad");
    let input = temp.path().join("plain.bin");
    let output = temp.path().join("existing.otp");
    let later_output = temp.path().join("later.otp");
    let state = temp.path().join("state");
    let sentinel = b"do not overwrite";
    fs::write(&input, b"12345678").unwrap();
    fs::write(&output, sentinel).unwrap();
    let mut random = CounterRandom::new(1);
    create_pad_pair_with_rng(8, &sender, &receiver, &mut random).unwrap();
    let id = inspect_pad(&sender).unwrap().id;

    let error = encrypt_file_with_state(&input, &sender, &output, &state).unwrap_err();
    match error {
        OtpError::OutputExists(path) => assert_eq!(path, output),
        error => panic!("unexpected error: {error:?}"),
    }
    assert_eq!(fs::read(&output).unwrap(), sentinel);
    assert!(!inspect_pad(&sender).unwrap().consumed);
    assert!(!is_reserved_in(&state, &id, PadRole::Sender).unwrap());

    encrypt_file_with_state(&input, &sender, &later_output, &state).unwrap();
    assert!(later_output.exists());
}

#[test]
fn decryption_refuses_existing_output_without_consuming_or_modifying_it() {
    let fixture = encrypted_fixture(14);
    let output = fixture.temp.path().join("existing.bin");
    let later_output = fixture.temp.path().join("later.bin");
    let sentinel = b"preserve this plaintext";
    fs::write(&output, sentinel).unwrap();

    let error = decrypt_file_with_state(
        &fixture.encrypted,
        &fixture.receiver,
        &output,
        &fixture.state,
    )
    .unwrap_err();
    match error {
        OtpError::OutputExists(path) => assert_eq!(path, output),
        error => panic!("unexpected error: {error:?}"),
    }
    assert_eq!(fs::read(&output).unwrap(), sentinel);
    assert_receiver_fresh(&fixture);

    decrypt_file_with_state(
        &fixture.encrypted,
        &fixture.receiver,
        &later_output,
        &fixture.state,
    )
    .unwrap();
    assert_eq!(fs::read(later_output).unwrap(), fixture.plaintext);
}

#[test]
fn tamper_failure_preserves_an_existing_destination_and_receiver_state() {
    let fixture = encrypted_fixture(24);
    let mut tampered = fs::read(&fixture.encrypted).unwrap();
    tampered[ENVELOPE_HEADER_LEN + 5] ^= 0x20;
    let tampered_path = fixture.temp.path().join("tampered.otp");
    let output = fixture.temp.path().join("existing.bin");
    let sentinel = b"existing destination survives";
    fs::write(&tampered_path, tampered).unwrap();
    fs::write(&output, sentinel).unwrap();

    let error = decrypt_file_with_state(&tampered_path, &fixture.receiver, &output, &fixture.state)
        .unwrap_err();
    assert!(matches!(error, OtpError::AuthenticationFailed));
    assert_eq!(fs::read(output).unwrap(), sentinel);
    assert_receiver_fresh(&fixture);
}

#[test]
fn pair_generation_rejects_preexisting_or_identical_destinations_atomically() {
    let temp = tempdir().unwrap();
    let sender = temp.path().join("sender.pad");
    let receiver = temp.path().join("receiver.pad");
    let sentinel = b"existing receiver";
    fs::write(&receiver, sentinel).unwrap();
    let before = entry_names(temp.path());
    let mut random = CounterRandom::new(1);

    let error = create_pad_pair_with_rng(8, &sender, &receiver, &mut random).unwrap_err();
    assert!(matches!(error, OtpError::OutputExists(_)));
    assert_eq!(random.fills, 0);
    assert!(!sender.exists());
    assert_eq!(fs::read(&receiver).unwrap(), sentinel);
    assert_eq!(entry_names(temp.path()), before, "temporary pad leaked");

    let same = temp.path().join("same.pad");
    let error = create_pad_pair_with_rng(8, &same, &same, &mut random).unwrap_err();
    assert!(matches!(error, OtpError::SameFile(_)));
    assert!(!same.exists());
}

#[test]
fn commit_time_sender_collision_preserves_the_racer_and_reports_orphan_receiver() {
    let temp = tempdir().unwrap();
    let sender = temp.path().join("sender.pad");
    let receiver = temp.path().join("receiver.pad");
    let mut random = CreatePathDuringGeneration {
        path: sender.clone(),
        inner: CounterRandom::new(1),
        created: false,
    };

    let error = create_pad_pair_with_rng(7, &sender, &receiver, &mut random).unwrap_err();
    match error {
        OtpError::PartialPadPair {
            receiver: reported,
            source,
        } => {
            assert_eq!(reported, receiver);
            assert!(matches!(*source, OtpError::OutputExists(ref path) if path == &sender));
        }
        other => panic!("unexpected error: {other:?}"),
    }
    assert_eq!(fs::read(&sender).unwrap(), b"racing writer");
    let orphan = inspect_pad(&receiver).unwrap();
    assert_eq!(orphan.role, PadRole::Receiver);
    assert!(!orphan.consumed);
}

#[test]
fn explicit_destroy_truncates_a_valid_pad_and_overwrites_hardlinked_contents() {
    let temp = tempdir().unwrap();
    let sender = temp.path().join("sender.pad");
    let receiver = temp.path().join("receiver.pad");
    let alias = temp.path().join("receiver-hardlink.pad");
    let mut random = CounterRandom::new(1);
    create_pad_pair_with_rng(211, &sender, &receiver, &mut random).unwrap();

    match fs::hard_link(&receiver, &alias) {
        Ok(()) => {
            destroy_pad(&receiver).unwrap();
            assert!(receiver.exists());
            assert_eq!(fs::metadata(&receiver).unwrap().len(), 0);
            assert!(alias.exists());
            assert_eq!(fs::metadata(&alias).unwrap().len(), 0);
        }
        Err(error) => {
            eprintln!("hard links unavailable; checking truncation only: {error}");
            destroy_pad(&receiver).unwrap();
            assert!(receiver.exists());
            assert_eq!(fs::metadata(&receiver).unwrap().len(), 0);
        }
    }
    assert!(sender.exists());
}

#[test]
fn explicit_destroy_accepts_a_consumed_pad_and_keeps_the_durable_reservation() {
    let fixture = encrypted_fixture(18);
    assert!(inspect_pad(&fixture.sender).unwrap().consumed);
    assert!(is_reserved_in(&fixture.state, &fixture.id, PadRole::Sender).unwrap());

    destroy_pad(&fixture.sender).unwrap();
    assert!(fixture.sender.exists());
    assert_eq!(fs::metadata(&fixture.sender).unwrap().len(), 0);
    assert!(is_reserved_in(&fixture.state, &fixture.id, PadRole::Sender).unwrap());
}

#[test]
fn explicit_destroy_refuses_corrupt_or_non_pad_files_without_altering_them() {
    let temp = tempdir().unwrap();
    let sender = temp.path().join("sender.pad");
    let receiver = temp.path().join("receiver.pad");
    let corrupt = temp.path().join("corrupt.pad");
    let ordinary = temp.path().join("ordinary.bin");
    let mut random = CounterRandom::new(1);
    create_pad_pair_with_rng(12, &sender, &receiver, &mut random).unwrap();

    let mut corrupt_bytes = fs::read(&receiver).unwrap();
    corrupt_bytes[PAD_SECRET_OFFSET as usize] ^= 1;
    fs::write(&corrupt, &corrupt_bytes).unwrap();
    let error = destroy_pad(&corrupt).unwrap_err();
    assert!(matches!(error, OtpError::InvalidPad(_)));
    assert_eq!(fs::read(&corrupt).unwrap(), corrupt_bytes);

    let ordinary_bytes = b"not a managed pad";
    fs::write(&ordinary, ordinary_bytes).unwrap();
    let error = destroy_pad(&ordinary).unwrap_err();
    assert!(matches!(error, OtpError::InvalidPad(_)));
    assert_eq!(fs::read(&ordinary).unwrap(), ordinary_bytes);
}

#[test]
fn format_v1_matches_independently_computed_golden_vectors() {
    let temp = tempdir().unwrap();
    let sender = temp.path().join("sender.pad");
    let receiver = temp.path().join("receiver.pad");
    let plaintext = temp.path().join("plain.bin");
    let encrypted = temp.path().join("encrypted.otp");
    let state = temp.path().join("state");
    fs::write(&plaintext, [0x10, 0x20, 0x30]).unwrap();

    let mut random = CounterRandom::new(1);
    create_pad_pair_with_rng(3, &sender, &receiver, &mut random).unwrap();

    let expected_sender = concat!(
        "4f54505041443031000100500001000001000000000000000102030405060708",
        "090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2000000000000000",
        "03000000000000000000000000000000002122232425262728292a2b2c2d2e2",
        "f303132333435363738393a3b3c3d3e3f4041424390e7203dfba54b8a736b2",
        "a208515f341bea5fcf30366de01e93cd33485364745"
    );
    let expected_receiver = concat!(
        "4f54505041443031000100500001000002000000000000000102030405060708",
        "090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2000000000000000",
        "03000000000000000000000000000000002122232425262728292a2b2c2d2e2",
        "f303132333435363738393a3b3c3d3e3f404142432bf78ed942fb6f293fbd3",
        "35276af1178bcb28b2b499fb8876b21ebc5e0935f75"
    );
    assert_eq!(hex_encode(&fs::read(&sender).unwrap()), expected_sender);
    assert_eq!(hex_encode(&fs::read(&receiver).unwrap()), expected_receiver);

    encrypt_file_with_state(&plaintext, &sender, &encrypted, &state).unwrap();
    let expected_envelope = concat!(
        "4f5450454e43303100010040000100000102030405060708090a0b0c0d0e0f10",
        "1112131415161718191a1b1c1d1e1f2000000000000000030000000000000000",
        "516273befa366642dcc02cddfaeb98db9083bcae140c4040dcc3822330e0e8ae",
        "045eaf"
    );
    assert_eq!(
        hex_encode(&fs::read(&encrypted).unwrap()),
        expected_envelope
    );
}

#[test]
fn file_length_and_hex_encoding_cover_public_utility_contracts() {
    let temp = tempdir().unwrap();
    let file = temp.path().join("data.bin");
    fs::write(&file, [0_u8; 123]).unwrap();
    assert_eq!(file_length(&file).unwrap(), 123);
    assert!(matches!(file_length(temp.path()), Err(OtpError::Io { .. })));
    assert_eq!(hex_encode(&[]), "");
    assert_eq!(
        hex_encode(&[0x00, 0x01, 0x0f, 0x10, 0xab, 0xff]),
        "00010f10abff"
    );
}
