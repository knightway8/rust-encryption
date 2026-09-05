use super::*;
use clap::Parser;
use proptest::prelude::*;
use rstest::rstest;
use std::{
    fs,
    io::{Cursor, Read, Write},
    path::Path,
    sync::atomic::Ordering,
};

struct ShortRead<R> {
    inner: R,
    chunk: usize,
    interrupt: bool,
}
impl<R: Read> Read for ShortRead<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.interrupt {
            self.interrupt = false;
            return Err(io::ErrorKind::Interrupted.into());
        }
        let n = buf.len().min(self.chunk);
        self.inner.read(&mut buf[..n])
    }
}

struct ShortWrite {
    bytes: Vec<u8>,
    chunk: usize,
    fail_after: Option<usize>,
    fail_flush: bool,
}
impl Write for ShortWrite {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.fail_after.is_some_and(|n| self.bytes.len() >= n) {
            return Err(io::Error::other("injected write failure"));
        }
        let n = buf
            .len()
            .min(self.chunk)
            .min(self.fail_after.map_or(usize::MAX, |n| n - self.bytes.len()));
        self.bytes.extend_from_slice(&buf[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.fail_flush {
            Err(io::Error::other("injected flush failure"))
        } else {
            Ok(())
        }
    }
}

fn encrypted(plaintext: &[u8]) -> (age::x25519::Identity, Vec<u8>) {
    let identity = age::x25519::Identity::generate();
    let mut output = Vec::new();
    encrypt_stream(
        plaintext,
        &mut output,
        Encryption::Recipients(vec![identity.to_public()]),
        &Operation::default(),
    )
    .unwrap();
    (identity, output)
}

#[rstest]
fn roundtrip_boundaries(
    #[values(
        0, 1, 2, 15, 16, 17, 31, 32, 63, 64, 255, 256, 4095, 4096, 65535, 65536, 65537, 131071,
        131072, 131073
    )]
    size: usize,
    #[values(0u8, 255, 37)] pattern: u8,
    #[values(7, 8192, 65536)] chunk: usize,
) {
    let plaintext: Vec<u8> = (0..size).map(|n| (n as u8).wrapping_mul(pattern)).collect();
    let identity = age::x25519::Identity::generate();
    let input = ShortRead {
        inner: &plaintext[..],
        chunk,
        interrupt: true,
    };
    let mut output = ShortWrite {
        bytes: vec![],
        chunk,
        fail_after: None,
        fail_flush: false,
    };
    assert_eq!(
        encrypt_stream(
            input,
            &mut output,
            Encryption::Recipients(vec![identity.to_public()]),
            &Operation::default()
        )
        .unwrap(),
        size as u64
    );
    let mut decrypted = Vec::new();
    let input = ShortRead {
        inner: &output.bytes[..],
        chunk,
        interrupt: false,
    };
    assert_eq!(
        decrypt_stream(
            input,
            &mut decrypted,
            Decryption::Identities(vec![identity]),
            &Operation::default()
        )
        .unwrap(),
        size as u64
    );
    assert_eq!(decrypted, plaintext);
}

#[rstest]
fn each_recipient_can_decrypt(#[values(1, 2, 3, 8, 16, 32, 64)] count: usize) {
    let keys: Vec<_> = (0..count)
        .map(|_| age::x25519::Identity::generate())
        .collect();
    let mut bytes = Vec::new();
    encrypt_stream(
        &b"many recipients"[..],
        &mut bytes,
        Encryption::Recipients(keys.iter().map(|k| k.to_public()).collect()),
        &Operation::default(),
    )
    .unwrap();
    for key in keys {
        let mut recovered = Vec::new();
        decrypt_stream(
            &bytes[..],
            &mut recovered,
            Decryption::Identities(vec![key]),
            &Operation::default(),
        )
        .unwrap();
        assert_eq!(recovered, b"many recipients");
    }
}

#[test]
fn nonmatching_identity_before_correct_identity() {
    let (key, bytes) = encrypted(b"secret");
    let mut plaintext = Vec::new();
    decrypt_stream(
        &bytes[..],
        &mut plaintext,
        Decryption::Identities(vec![age::x25519::Identity::generate(), key]),
        &Operation::default(),
    )
    .unwrap();
    assert_eq!(plaintext, b"secret");
}

#[test]
fn independent_encryption_is_randomized() {
    let key = age::x25519::Identity::generate();
    let mut seen = std::collections::HashSet::new();
    for _ in 0..32 {
        let mut output = Vec::new();
        encrypt_stream(
            &b"same plaintext"[..],
            &mut output,
            Encryption::Recipients(vec![key.to_public()]),
            &Operation::default(),
        )
        .unwrap();
        assert!(seen.insert(output));
    }
}

#[rstest]
fn ciphertext_bit_flips_fail(
    #[values(0, 1, 10, 20, 25, 40, 60, 80, 100, 120, 150, 180, 200)] offset: usize,
    #[values(1u8, 2, 4, 8, 16, 32, 64, 128)] mask: u8,
) {
    let (key, mut bytes) = encrypted(&[42; 256]);
    bytes[offset] ^= mask;
    assert!(
        decrypt_stream(
            &bytes[..],
            io::sink(),
            Decryption::Identities(vec![key]),
            &Operation::default()
        )
        .is_err()
    );
}

#[test]
fn every_truncation_of_short_ciphertext_fails() {
    let (key, bytes) = encrypted(b"sample payload");
    for length in 0..bytes.len() {
        assert!(
            decrypt_stream(
                &bytes[..length],
                io::sink(),
                Decryption::Identities(vec![key.clone()]),
                &Operation::default()
            )
            .is_err(),
            "accepted prefix length {length}"
        );
    }
}

#[rstest]
fn trailing_data_fails(#[values(1, 15, 16, 17, 64, 65536, 65552)] length: usize) {
    let (key, mut bytes) = encrypted(b"sample");
    bytes.extend(vec![0; length]);
    assert!(
        decrypt_stream(
            &bytes[..],
            io::sink(),
            Decryption::Identities(vec![key]),
            &Operation::default()
        )
        .is_err()
    );
}

#[test]
fn concatenated_valid_files_fail() {
    let (key, mut bytes) = encrypted(b"sample");
    bytes.extend(bytes.clone());
    assert!(
        decrypt_stream(
            &bytes[..],
            io::sink(),
            Decryption::Identities(vec![key]),
            &Operation::default()
        )
        .is_err()
    );
}

#[rstest]
fn stream_block_reordering_fails(#[values(false, true)] duplicate: bool) {
    let (key, mut bytes) = encrypted(&vec![69; 3 * 65536]);
    let start = bytes.windows(4).position(|w| w == b"--- ").unwrap();
    let body = start + bytes[start..].iter().position(|&b| b == b'\n').unwrap() + 1 + 16;
    let chunk = 65536 + 16;
    let first = bytes[body..body + chunk].to_vec();
    if duplicate {
        bytes[body + chunk..body + 2 * chunk].copy_from_slice(&first);
    } else {
        let second = bytes[body + chunk..body + 2 * chunk].to_vec();
        bytes[body..body + chunk].copy_from_slice(&second);
        bytes[body + chunk..body + 2 * chunk].copy_from_slice(&first);
    }
    assert!(
        decrypt_stream(
            &bytes[..],
            io::sink(),
            Decryption::Identities(vec![key]),
            &Operation::default()
        )
        .is_err()
    );
}

#[rstest]
fn write_failures_propagate(
    #[values(0, 1, 10, 128, 256, 65536)] after: usize,
    #[values(false, true)] decrypt: bool,
) {
    let mut writer = ShortWrite {
        bytes: vec![],
        chunk: 13,
        fail_after: Some(after),
        fail_flush: false,
    };
    let (key, ciphertext) = encrypted(&vec![123; 70000]);
    let result = if decrypt {
        decrypt_stream(
            &ciphertext[..],
            &mut writer,
            Decryption::Identities(vec![key]),
            &Operation::default(),
        )
    } else {
        encrypt_stream(
            &vec![123; 70000][..],
            &mut writer,
            Encryption::Recipients(vec![key.to_public()]),
            &Operation::default(),
        )
    };
    assert!(result.is_err());
}

#[rstest]
fn flush_failures_propagate(#[values(false, true)] decrypt: bool) {
    let mut writer = ShortWrite {
        bytes: vec![],
        chunk: 1024,
        fail_after: None,
        fail_flush: true,
    };
    let (key, ciphertext) = encrypted(b"hello");
    let result = if decrypt {
        decrypt_stream(
            &ciphertext[..],
            &mut writer,
            Decryption::Identities(vec![key]),
            &Operation::default(),
        )
    } else {
        encrypt_stream(
            &b"hello"[..],
            &mut writer,
            Encryption::Recipients(vec![key.to_public()]),
            &Operation::default(),
        )
    };
    assert!(result.is_err());
}

#[test]
fn zero_length_write_fails_instead_of_looping() {
    let mut writer = ShortWrite {
        bytes: vec![],
        chunk: 0,
        fail_after: None,
        fail_flush: false,
    };
    assert!(transfer(&b"x"[..], &mut writer, &Operation::default()).is_err());
}

#[rstest]
fn size_limit_is_exact(
    #[values(0, 1, 16, 65535, 65536, 65537)] size: usize,
    #[values(false, true)] decrypt: bool,
) {
    let plaintext = vec![31; size];
    let (key, ciphertext) = encrypted(&plaintext);
    for limit in [size.saturating_sub(1), size, size + 1] {
        let op = Operation {
            max_bytes: Some(limit as u64),
            ..Operation::default()
        };
        let result = if decrypt {
            decrypt_stream(
                &ciphertext[..],
                io::sink(),
                Decryption::Identities(vec![key.clone()]),
                &op,
            )
        } else {
            encrypt_stream(
                &plaintext[..],
                io::sink(),
                Encryption::Recipients(vec![key.to_public()]),
                &op,
            )
        };
        assert_eq!(result.is_ok(), size <= limit);
    }
}

#[rstest]
fn cancelled_operations_do_not_start(#[values(false, true)] decrypt: bool) {
    let op = Operation::default();
    op.cancelled.store(true, Ordering::Relaxed);
    let key = age::x25519::Identity::generate();
    let mut output = Vec::new();
    let result = if decrypt {
        decrypt_stream(
            &b"bad"[..],
            &mut output,
            Decryption::Identities(vec![key]),
            &op,
        )
    } else {
        encrypt_stream(
            &b"hi"[..],
            &mut output,
            Encryption::Recipients(vec![key.to_public()]),
            &op,
        )
    };
    assert!(matches!(result, Err(Error::Cancelled)));
    assert!(output.is_empty());
}

#[test]
fn cancellation_during_transfer_is_observed() {
    struct CancelReader(Arc<AtomicBool>);
    impl Read for CancelReader {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            self.0.store(true, Ordering::Relaxed);
            bytes[0] = 42;
            Ok(1)
        }
    }
    let op = Operation::default();
    let mut output = Vec::new();
    assert!(matches!(
        transfer(CancelReader(op.cancelled.clone()), &mut output, &op),
        Err(Error::Cancelled)
    ));
    assert!(output.is_empty());
}

#[test]
fn read_error_propagates() {
    struct Failing;
    impl Read for Failing {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("injected read error"))
        }
    }
    assert!(transfer(Failing, io::sink(), &Operation::default()).is_err());
}

#[rstest]
fn header_allocation_is_bounded(#[values(false, true)] newlines: bool) {
    let mut input = b"age-encryption.org/v1\n".to_vec();
    input.extend(vec![
        if newlines { b'\n' } else { b'x' };
        MAX_HEADER_BYTES * 2
    ]);
    let mut input = Cursor::new(input);
    assert!(bounded_input(&mut input, &Operation::default()).is_err());
    assert!(input.position() <= (MAX_HEADER_BYTES + 8192) as u64);
}

#[rstest]
#[case("")]
#[case("-")]
#[case("abc\0def")]
fn invalid_file_paths(#[case] path: &str) {
    assert!(files::validate_path(Path::new(path)).is_err());
}

#[cfg(windows)]
#[rstest]
#[case("NUL")]
#[case("con.txt")]
#[case("AUX")]
#[case("PRN")]
#[case("COM1")]
#[case("LPT9.txt")]
#[case("COM¹")]
#[case("file:stream")]
#[case("file.")]
#[case("file ")]
#[case("a\nb")]
#[case("a?b")]
#[case("CONIN$")]
#[case("CONOUT$")]
#[case("\\\\.\\PhysicalDrive0")]
fn windows_unsafe_paths(#[case] path: &str) {
    assert!(files::validate_path(Path::new(path)).is_err(), "{path}");
}

#[rstest]
#[case("hello.txt", "hello.txt.age")]
#[case("hello", "hello.age")]
#[case("hello.age", "hello.age.age")]
#[case("folder with spaces/notes.txt", "folder with spaces/notes.txt.age")]
#[case("日本語🔒", "日本語🔒.age")]
fn encrypted_output_names(#[case] input: &str, #[case] expected: &str) {
    assert_eq!(files::encrypted_path(Path::new(input)), Path::new(expected));
}

#[rstest]
#[case("hello.txt.age", "hello.txt")]
#[case("hello.age", "hello")]
#[case("folder/日本語.age", "folder/日本語")]
#[case("hello.age.age", "hello.age")]
fn decrypted_output_names(#[case] input: &str, #[case] expected: &str) {
    assert_eq!(
        files::decrypted_path(Path::new(input)).unwrap(),
        Path::new(expected)
    );
}

#[rstest]
#[case("hello.AGE")]
#[case("hello")]
#[case(".age")]
fn ambiguous_decrypted_output_needs_explicit_name(#[case] input: &str) {
    assert!(files::decrypted_path(Path::new(input)).is_err());
}

#[test]
fn output_transaction_rejects_a_racing_destination() {
    let dir = tempfile::tempdir().unwrap();
    let destination = dir.path().join("result");
    let mut output = Output::create(&destination).unwrap();
    output.file().write_all(b"new data").unwrap();
    fs::write(&destination, b"original").unwrap();
    assert!(output.commit().is_err());
    assert_eq!(fs::read(&destination).unwrap(), b"original");
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn abandoned_transaction_cleans_up() {
    let dir = tempfile::tempdir().unwrap();
    {
        let mut output = Output::create(&dir.path().join("result")).unwrap();
        output
            .file()
            .write_all(b"private partial plaintext")
            .unwrap();
    }
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[test]
fn concurrent_publishers_never_replace_the_winner() {
    let dir = tempfile::tempdir().unwrap();
    let destination = dir.path().join("winner");
    let barrier = Arc::new(std::sync::Barrier::new(12));
    let handles: Vec<_> = (0u8..12)
        .map(|byte| {
            let destination = destination.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let mut output = Output::create(&destination).unwrap();
                output.file().write_all(&[byte; 4096]).unwrap();
                barrier.wait();
                output.commit().ok().map(|()| byte)
            })
        })
        .collect();
    let winners: Vec<_> = handles
        .into_iter()
        .filter_map(|h| h.join().unwrap())
        .collect();
    assert_eq!(winners.len(), 1);
    assert_eq!(fs::read(destination).unwrap(), vec![winners[0]; 4096]);
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[cfg(windows)]
#[test]
fn open_input_prevents_concurrent_writes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input");
    fs::write(&path, b"stable content").unwrap();
    let input = files::Input::open(&path).unwrap();
    assert!(fs::OpenOptions::new().write(true).open(&path).is_err());
    assert!(fs::remove_file(&path).is_err());
    input.unchanged().unwrap();
}

#[cfg(unix)]
#[test]
fn modified_input_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input");
    fs::write(&path, b"original").unwrap();
    let input = files::Input::open(&path).unwrap();
    fs::write(&path, b"modified with a different length").unwrap();
    assert!(input.unchanged().is_err());
}

#[test]
fn private_creation_never_replaces_existing_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("file");
    fs::write(&path, b"original").unwrap();
    assert!(platform::create_private(&path).is_err());
    assert_eq!(fs::read(path).unwrap(), b"original");
}

#[rstest]
#[case(vec!["best"])]
#[case(vec!["best", "unknown"])]
#[case(vec!["best", "encrypt"])]
#[case(vec!["best", "decrypt"])]
#[case(vec!["best", "verify"])]
#[case(vec!["best", "keygen"])]
#[case(vec!["best", "encrypt", "f", "--password", "oops"])]
#[case(vec!["best", "encrypt", "f", "--force"])]
#[case(vec!["best", "encrypt", "f", "-r", "key", "--password-file", "pw"])]
#[case(vec!["best", "decrypt", "f", "-i", "key", "--password-file", "pw"])]
#[case(vec!["best", "decrypt", "f", "-i", "key", "--max-work-factor", "20"])]
#[case(vec!["best", "decrypt", "f", "--max-work-factor", "21"])]
#[case(vec!["best", "decrypt", "f", "--max-work-factor", "0"])]
#[case(vec!["best", "decrypt", "f", "--max-work-factor", "256"])]
#[case(vec!["best", "verify", "f", "--max-bytes", "-1"])]
#[case(vec!["best", "verify", "f", "--max-bytes", "18446744073709551616"])]
fn invalid_cli_combinations(#[case] args: Vec<&str>) {
    assert!(cli::Cli::try_parse_from(args).is_err());
}

#[test]
fn clap_definition_is_consistent() {
    use clap::CommandFactory;
    cli::Cli::command().debug_assert();
}

#[test]
fn excessive_work_error_formatting_cannot_overflow() {
    for required in 0..=255 {
        for target in 0..=255 {
            let error = Error::Decrypt(age::DecryptError::ExcessiveWork { required, target });
            assert!(error.to_string().contains("scrypt cost exceeds"));
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]
    #[test]
    fn random_binary_roundtrips(plaintext in prop::collection::vec(any::<u8>(), 0..16384)) {
        let (key, encrypted) = encrypted(&plaintext);
        let mut recovered = Vec::new();
        decrypt_stream(&encrypted[..], &mut recovered, Decryption::Identities(vec![key]), &Operation::default()).unwrap();
        prop_assert_eq!(plaintext, recovered);
    }

    #[test]
    fn random_payload_mutation_fails(plaintext in prop::collection::vec(any::<u8>(), 1..4096), offset in any::<usize>(), mask in 1u8..=255) {
        let (key, mut bytes) = encrypted(&plaintext);
        let index = bytes.len() - 1 - (offset % (plaintext.len() + 16));
        bytes[index] ^= mask;
        prop_assert!(decrypt_stream(&bytes[..], io::sink(), Decryption::Identities(vec![key]), &Operation::default()).is_err());
    }

    #[test]
    fn arbitrary_inputs_are_rejected_without_panics(bytes in prop::collection::vec(any::<u8>(), 0..8192)) {
        let key = age::x25519::Identity::generate();
        prop_assert!(decrypt_stream(&bytes[..], io::sink(), Decryption::Identities(vec![key]), &Operation::default()).is_err());
    }
}
