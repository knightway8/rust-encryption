use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305_v11::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use rand_core::{OsRng, RngCore};
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

use crate::x4x::Error;
use crate::x4x::format::{
    EncryptionOptions, FRAME_HEADER_LEN, FrameHeader, HEADER_LEN, Header, TAG_LEN, associated_data,
    nonce,
};
use crate::x4x::password;

/// Encrypt `input` into a newly created `output` using production KDF settings.
///
/// The input is left untouched. The operation refuses to overwrite any output
/// and atomically publishes the completed ciphertext only after it is flushed
/// and synchronized to disk.
///
/// # Errors
///
/// Returns an error for invalid passwords or options, unsafe or conflicting
/// paths, unavailable randomness, cryptographic failure, or any I/O failure.
pub fn encrypt_file(input: &Path, output: &Path, password: &[u8]) -> Result<(), Error> {
    encrypt_file_with_options(input, output, password, EncryptionOptions::default())
}

pub(crate) fn encrypt_file_with_options(
    input: &Path,
    output: &Path,
    password: &[u8],
    options: EncryptionOptions,
) -> Result<(), Error> {
    password::validate(password)?;
    options.validate()?;
    let input_file = open_input_and_validate_output(input, output)?;

    let mut salt = [0_u8; 16];
    let mut nonce_prefix = [0_u8; 16];
    OsRng
        .try_fill_bytes(&mut salt)
        .map_err(|e| Error::Randomness(e.to_string()))?;
    OsRng
        .try_fill_bytes(&mut nonce_prefix)
        .map_err(|e| Error::Randomness(e.to_string()))?;
    let header = Header::new(options, salt, nonce_prefix)?;
    let key = derive_key(password, &header)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice())
        .map_err(|_| Error::CryptographicFailure)?;

    let mut output_file = AtomicOutput::create(output)?;
    {
        let mut reader = BufReader::new(input_file);
        let mut writer = BufWriter::new(output_file.file_mut());
        writer
            .write_all(header.as_bytes())
            .map_err(|e| Error::io("cannot write encrypted output", output, e))?;

        let chunk_size = options.chunk_size as usize;
        let mut current = read_chunk(&mut reader, chunk_size, input)?;
        let mut frame_index = 0_u64;
        loop {
            let next = read_chunk(&mut reader, chunk_size, input)?;
            let final_frame = next.is_empty();
            let plaintext_len = u32::try_from(current.len())
                .map_err(|_| Error::InvalidFormat("plaintext frame exceeds format limit"))?;
            let frame = FrameHeader::new(plaintext_len, final_frame);
            let frame_nonce = XNonce::from(nonce(&header.nonce_prefix, frame_index));
            let aad = associated_data(&header, frame_index, &frame);
            let ciphertext = cipher
                .encrypt(
                    &frame_nonce,
                    Payload {
                        msg: &current,
                        aad: &aad,
                    },
                )
                .map_err(|_| Error::CryptographicFailure)?;

            writer
                .write_all(frame.as_bytes())
                .and_then(|()| writer.write_all(&ciphertext))
                .map_err(|e| Error::io("cannot write encrypted output", output, e))?;

            if final_frame {
                break;
            }
            current = next;
            frame_index = frame_index
                .checked_add(1)
                .ok_or(Error::InvalidFormat("too many frames"))?;
        }

        writer
            .flush()
            .map_err(|e| Error::io("cannot flush encrypted output", output, e))?;
    }
    output_file.commit()
}

/// Authenticate and decrypt `input` into a newly created `output`.
///
/// Plaintext is written to a private temporary file. It becomes visible at the
/// requested path only after every frame and the final marker authenticate.
///
/// # Errors
///
/// Returns an error for invalid passwords or containers, authentication
/// failure, unsafe or conflicting paths, or any I/O failure.
pub fn decrypt_file(input: &Path, output: &Path, password: &[u8]) -> Result<(), Error> {
    password::validate(password)?;
    let input_file = open_input_and_validate_output(input, output)?;
    let mut reader = BufReader::new(input_file);
    let header = read_header(&mut reader, input)?;
    let key = derive_key(password, &header)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice())
        .map_err(|_| Error::CryptographicFailure)?;

    let mut output_file = AtomicOutput::create(output)?;
    {
        let mut writer = BufWriter::new(output_file.file_mut());
        let mut frame_index = 0_u64;
        loop {
            let raw_frame = read_frame_header(&mut reader, input)?
                .ok_or(Error::InvalidFormat("missing authenticated final frame"))?;
            let frame = FrameHeader::parse(raw_frame, header.options.chunk_size)?;
            let ciphertext_len = frame.plaintext_len as usize + TAG_LEN;
            let mut ciphertext = vec![0_u8; ciphertext_len];
            read_exact_format(&mut reader, &mut ciphertext, input, "truncated frame")?;

            let frame_nonce = XNonce::from(nonce(&header.nonce_prefix, frame_index));
            let aad = associated_data(&header, frame_index, &frame);
            let plaintext = cipher
                .decrypt(
                    &frame_nonce,
                    Payload {
                        msg: &ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| Error::AuthenticationFailed)?;
            if plaintext.len() != frame.plaintext_len as usize {
                return Err(Error::InvalidFormat("authenticated length mismatch"));
            }
            writer
                .write_all(&plaintext)
                .map_err(|e| Error::io("cannot write decrypted output", output, e))?;

            if frame.final_frame {
                ensure_eof(&mut reader, input)?;
                break;
            }
            frame_index = frame_index
                .checked_add(1)
                .ok_or(Error::InvalidFormat("too many frames"))?;
        }

        writer
            .flush()
            .map_err(|e| Error::io("cannot flush decrypted output", output, e))?;
    }
    output_file.commit()
}

fn derive_key(password: &[u8], header: &Header) -> Result<Zeroizing<[u8; 32]>, Error> {
    let options = header.options;
    let params = Params::new(
        options.memory_kib,
        options.iterations,
        options.parallelism,
        Some(32),
    )
    .map_err(|_| Error::CryptographicFailure)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0_u8; 32]);
    argon2
        .hash_password_into(password, &header.salt, key.as_mut())
        .map_err(|_| Error::CryptographicFailure)?;
    Ok(key)
}

fn read_header(reader: &mut impl Read, path: &Path) -> Result<Header, Error> {
    let mut raw = [0_u8; HEADER_LEN];
    read_exact_format(reader, &mut raw, path, "truncated header")?;
    Header::parse(raw)
}

fn read_frame_header(
    reader: &mut impl Read,
    path: &Path,
) -> Result<Option<[u8; FRAME_HEADER_LEN]>, Error> {
    let mut raw = [0_u8; FRAME_HEADER_LEN];
    loop {
        match reader.read(&mut raw[..1]) {
            Ok(0) => return Ok(None),
            Ok(1) => break,
            Ok(_) => return Err(Error::InvalidFormat("invalid reader result")),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(Error::io("cannot read encrypted input", path, e)),
        }
    }
    read_exact_format(reader, &mut raw[1..], path, "truncated frame header")?;
    Ok(Some(raw))
}

fn read_exact_format(
    reader: &mut impl Read,
    buffer: &mut [u8],
    path: &Path,
    eof_message: &'static str,
) -> Result<(), Error> {
    match reader.read_exact(buffer) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
            Err(Error::InvalidFormat(eof_message))
        }
        Err(e) => Err(Error::io("cannot read encrypted input", path, e)),
    }
}

fn read_chunk(reader: &mut impl Read, capacity: usize, path: &Path) -> Result<Vec<u8>, Error> {
    let mut buffer = vec![0_u8; capacity];
    let mut filled = 0;
    while filled < capacity {
        match reader.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(count) => filled += count,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(Error::io("cannot read input", path, e)),
        }
    }
    buffer.truncate(filled);
    Ok(buffer)
}

fn ensure_eof(reader: &mut impl Read, path: &Path) -> Result<(), Error> {
    let mut byte = [0_u8; 1];
    loop {
        match reader.read(&mut byte) {
            Ok(0) => return Ok(()),
            Ok(_) => return Err(Error::InvalidFormat("trailing data after final frame")),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(Error::io("cannot read encrypted input", path, e)),
        }
    }
}

fn open_input_and_validate_output(input: &Path, output: &Path) -> Result<File, Error> {
    let input_file = File::open(input).map_err(|e| Error::io("cannot open input", input, e))?;
    let canonical_input = input
        .canonicalize()
        .map_err(|e| Error::io("cannot resolve input path", input, e))?;

    if output.exists() {
        if output.canonicalize().ok().as_ref() == Some(&canonical_input) {
            return Err(Error::SamePath);
        }
        return Err(Error::OutputExists(output.to_owned()));
    }

    let parent = output_parent(output);
    let canonical_parent = parent
        .canonicalize()
        .map_err(|e| Error::io("cannot resolve output directory", parent, e))?;
    let file_name = output.file_name().ok_or_else(|| {
        Error::io(
            "invalid output path",
            output,
            io::Error::new(io::ErrorKind::InvalidInput, "output has no file name"),
        )
    })?;
    if canonical_parent.join(file_name) == canonical_input {
        return Err(Error::SamePath);
    }
    Ok(input_file)
}

fn output_parent(output: &Path) -> &Path {
    output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

struct AtomicOutput {
    temporary: NamedTempFile,
    destination: PathBuf,
}

impl AtomicOutput {
    fn create(destination: &Path) -> Result<Self, Error> {
        let parent = output_parent(destination);
        let temporary = NamedTempFile::new_in(parent)
            .map_err(|e| Error::io("cannot create private temporary output", parent, e))?;
        Ok(Self {
            temporary,
            destination: destination.to_owned(),
        })
    }

    fn file_mut(&mut self) -> &mut File {
        self.temporary.as_file_mut()
    }

    fn commit(self) -> Result<(), Error> {
        self.temporary
            .as_file()
            .sync_all()
            .map_err(|e| Error::io("cannot synchronize temporary output", &self.destination, e))?;
        match self.temporary.persist_noclobber(&self.destination) {
            Ok(_file) => {
                #[cfg(unix)]
                sync_output_directory(&self.destination)?;
                Ok(())
            }
            Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => {
                Err(Error::OutputExists(self.destination))
            }
            Err(error) => Err(Error::io(
                "cannot publish completed output",
                &self.destination,
                error.error,
            )),
        }
    }
}

#[cfg(unix)]
fn sync_output_directory(output: &Path) -> Result<(), Error> {
    let parent = output_parent(output);
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|e| Error::io("cannot synchronize output directory", parent, e))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::fs;
    use std::io::Cursor;
    use std::sync::{Arc, Barrier};
    use std::thread;

    use tempfile::{TempDir, tempdir};

    use super::*;
    use crate::x4x::format::{MAX_MEMORY_KIB, MIN_CHUNK_SIZE, MIN_MEMORY_KIB};

    const PASSWORD: &[u8] = b"a high entropy test passphrase";

    fn test_options() -> EncryptionOptions {
        EncryptionOptions {
            memory_kib: MIN_MEMORY_KIB,
            iterations: 1,
            parallelism: 1,
            chunk_size: MIN_CHUNK_SIZE,
        }
    }

    struct BrokenReader;

    impl Read for BrokenReader {
        fn read(&mut self, _output: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("injected"))
        }
    }

    struct Fixture {
        directory: TempDir,
        source: PathBuf,
        encrypted: PathBuf,
        decrypted: PathBuf,
    }

    impl Fixture {
        fn new(data: &[u8]) -> Self {
            let directory = tempdir().unwrap();
            let source = directory.path().join("source.bin");
            let encrypted = directory.path().join("source.bin.x4x");
            let decrypted = directory.path().join("restored.bin");
            fs::write(&source, data).unwrap();
            encrypt_file_with_options(&source, &encrypted, PASSWORD, test_options()).unwrap();
            Self {
                directory,
                source,
                encrypted,
                decrypted,
            }
        }

        fn decrypt(&self) -> Result<(), Error> {
            decrypt_file(&self.encrypted, &self.decrypted, PASSWORD)
        }
    }

    fn patterned_bytes(len: usize) -> Vec<u8> {
        (0..len)
            .map(|index| {
                u8::try_from((index.wrapping_mul(31) ^ (index >> 3)) & 0xff)
                    .expect("masked pattern byte fits in u8")
            })
            .collect()
    }

    fn assert_round_trip(data: &[u8]) {
        let fixture = Fixture::new(data);
        fixture.decrypt().unwrap();
        assert_eq!(fs::read(&fixture.decrypted).unwrap(), data);
    }

    fn rewrite_header_u32(fixture: &Fixture, offset: usize, value: u32) {
        let mut bytes = fs::read(&fixture.encrypted).unwrap();
        bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        fs::write(&fixture.encrypted, bytes).unwrap();
    }

    #[test]
    fn round_trips_empty_file() {
        assert_round_trip(&[]);
    }

    #[test]
    fn round_trips_single_byte() {
        assert_round_trip(&[0xa5]);
    }

    #[test]
    fn round_trips_binary_data_including_every_byte_value() {
        assert_round_trip(&(0_u8..=255).collect::<Vec<_>>());
    }

    #[test]
    fn round_trips_boundaries_around_every_chunk_transition() {
        let chunk = MIN_CHUNK_SIZE as usize;
        for len in [
            chunk - 1,
            chunk,
            chunk + 1,
            2 * chunk - 1,
            2 * chunk,
            2 * chunk + 1,
            5 * chunk + 73,
        ] {
            assert_round_trip(&patterned_bytes(len));
        }
    }

    #[test]
    fn wrong_password_never_creates_plaintext_output() {
        let fixture = Fixture::new(b"classified content");
        assert!(matches!(
            decrypt_file(&fixture.encrypted, &fixture.decrypted, b"wrong password"),
            Err(Error::AuthenticationFailed)
        ));
        assert!(!fixture.decrypted.exists());
    }

    #[test]
    fn salt_and_nonce_make_repeated_encryptions_distinct() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("plain");
        let first = directory.path().join("first");
        let second = directory.path().join("second");
        fs::write(&source, b"same plaintext").unwrap();
        encrypt_file_with_options(&source, &first, PASSWORD, test_options()).unwrap();
        encrypt_file_with_options(&source, &second, PASSWORD, test_options()).unwrap();
        assert_ne!(fs::read(first).unwrap(), fs::read(second).unwrap());
    }

    #[test]
    fn encryption_does_not_modify_source() {
        let data = patterned_bytes(10_000);
        let fixture = Fixture::new(&data);
        assert_eq!(fs::read(&fixture.source).unwrap(), data);
    }

    #[test]
    fn tampered_salt_is_detected() {
        let fixture = Fixture::new(b"authenticate the header");
        let mut bytes = fs::read(&fixture.encrypted).unwrap();
        bytes[28] ^= 0x80;
        fs::write(&fixture.encrypted, bytes).unwrap();
        assert!(matches!(
            fixture.decrypt(),
            Err(Error::AuthenticationFailed)
        ));
        assert!(!fixture.decrypted.exists());
    }

    #[test]
    fn tampered_nonce_prefix_is_detected() {
        let fixture = Fixture::new(b"authenticate the nonce");
        let mut bytes = fs::read(&fixture.encrypted).unwrap();
        bytes[44] ^= 0x40;
        fs::write(&fixture.encrypted, bytes).unwrap();
        assert!(matches!(
            fixture.decrypt(),
            Err(Error::AuthenticationFailed)
        ));
    }

    #[test]
    fn tampered_ciphertext_is_detected() {
        let fixture = Fixture::new(&patterned_bytes(100));
        let mut bytes = fs::read(&fixture.encrypted).unwrap();
        bytes[HEADER_LEN + FRAME_HEADER_LEN + 17] ^= 1;
        fs::write(&fixture.encrypted, bytes).unwrap();
        assert!(matches!(
            fixture.decrypt(),
            Err(Error::AuthenticationFailed)
        ));
    }

    #[test]
    fn tampered_authentication_tag_is_detected() {
        let fixture = Fixture::new(b"tag protected");
        let mut bytes = fs::read(&fixture.encrypted).unwrap();
        let last = bytes.last_mut().unwrap();
        *last ^= 1;
        fs::write(&fixture.encrypted, bytes).unwrap();
        assert!(matches!(
            fixture.decrypt(),
            Err(Error::AuthenticationFailed)
        ));
    }

    #[test]
    fn changing_final_marker_is_detected() {
        let fixture = Fixture::new(&patterned_bytes(MIN_CHUNK_SIZE as usize));
        let mut bytes = fs::read(&fixture.encrypted).unwrap();
        bytes[HEADER_LEN + 4] = 0;
        fs::write(&fixture.encrypted, bytes).unwrap();
        assert!(matches!(
            fixture.decrypt(),
            Err(Error::AuthenticationFailed)
        ));
    }

    #[test]
    fn unknown_frame_flags_are_rejected() {
        let fixture = Fixture::new(b"frame flags");
        let mut bytes = fs::read(&fixture.encrypted).unwrap();
        bytes[HEADER_LEN + 4] |= 0x80;
        fs::write(&fixture.encrypted, bytes).unwrap();
        assert!(matches!(fixture.decrypt(), Err(Error::InvalidFormat(_))));
    }

    #[test]
    fn oversized_frame_length_is_rejected_before_allocation() {
        let fixture = Fixture::new(b"length");
        let mut bytes = fs::read(&fixture.encrypted).unwrap();
        bytes[HEADER_LEN..HEADER_LEN + 4].copy_from_slice(&(MIN_CHUNK_SIZE + 1).to_be_bytes());
        fs::write(&fixture.encrypted, bytes).unwrap();
        assert!(matches!(fixture.decrypt(), Err(Error::InvalidFormat(_))));
    }

    #[test]
    fn hostile_memory_cost_is_rejected_before_kdf() {
        let fixture = Fixture::new(b"bounded resources");
        let mut bytes = fs::read(&fixture.encrypted).unwrap();
        bytes[12..16].copy_from_slice(&(MAX_MEMORY_KIB + 1).to_be_bytes());
        fs::write(&fixture.encrypted, bytes).unwrap();
        assert!(matches!(fixture.decrypt(), Err(Error::UnsafeParameters(_))));
    }

    #[test]
    fn every_representative_truncation_is_rejected_without_output() {
        let data = patterned_bytes(MIN_CHUNK_SIZE as usize + 31);
        let fixture = Fixture::new(&data);
        let original = fs::read(&fixture.encrypted).unwrap();
        let second_frame = HEADER_LEN + FRAME_HEADER_LEN + MIN_CHUNK_SIZE as usize + TAG_LEN;
        let points = [
            0,
            1,
            HEADER_LEN - 1,
            HEADER_LEN,
            HEADER_LEN + 1,
            second_frame - 1,
            second_frame,
            original.len() - 1,
        ];
        for (case, length) in points.into_iter().enumerate() {
            fs::write(&fixture.encrypted, &original[..length]).unwrap();
            let output = fixture
                .decrypted
                .with_file_name(format!("truncated-{case}"));
            assert!(decrypt_file(&fixture.encrypted, &output, PASSWORD).is_err());
            assert!(!output.exists());
        }
    }

    #[test]
    fn removing_the_final_frame_is_detected() {
        let fixture = Fixture::new(&patterned_bytes(MIN_CHUNK_SIZE as usize + 10));
        let bytes = fs::read(&fixture.encrypted).unwrap();
        let second_frame = HEADER_LEN + FRAME_HEADER_LEN + MIN_CHUNK_SIZE as usize + TAG_LEN;
        fs::write(&fixture.encrypted, &bytes[..second_frame]).unwrap();
        assert!(matches!(fixture.decrypt(), Err(Error::InvalidFormat(_))));
    }

    #[test]
    fn bytes_appended_after_final_frame_are_rejected() {
        let fixture = Fixture::new(b"no unauthenticated trailers");
        let mut bytes = fs::read(&fixture.encrypted).unwrap();
        bytes.extend_from_slice(b"trailer");
        fs::write(&fixture.encrypted, bytes).unwrap();
        assert!(matches!(fixture.decrypt(), Err(Error::InvalidFormat(_))));
        assert!(!fixture.decrypted.exists());
    }

    #[test]
    fn reordered_frames_are_detected() {
        let fixture = Fixture::new(&patterned_bytes(2 * MIN_CHUNK_SIZE as usize));
        let bytes = fs::read(&fixture.encrypted).unwrap();
        let frame_len = FRAME_HEADER_LEN + MIN_CHUNK_SIZE as usize + TAG_LEN;
        let first_start = HEADER_LEN;
        let second_start = first_start + frame_len;
        let mut reordered = bytes[..HEADER_LEN].to_vec();
        reordered.extend_from_slice(&bytes[second_start..second_start + frame_len]);
        reordered.extend_from_slice(&bytes[first_start..first_start + frame_len]);
        fs::write(&fixture.encrypted, reordered).unwrap();
        assert!(matches!(
            fixture.decrypt(),
            Err(Error::AuthenticationFailed)
        ));
    }

    #[test]
    fn duplicated_final_frame_is_rejected_as_trailing_data() {
        let fixture = Fixture::new(b"one final frame only");
        let mut bytes = fs::read(&fixture.encrypted).unwrap();
        let frame = bytes[HEADER_LEN..].to_vec();
        bytes.extend_from_slice(&frame);
        fs::write(&fixture.encrypted, bytes).unwrap();
        assert!(matches!(fixture.decrypt(), Err(Error::InvalidFormat(_))));
    }

    #[test]
    fn malformed_header_only_file_is_rejected() {
        let fixture = Fixture::new(b"payload");
        let bytes = fs::read(&fixture.encrypted).unwrap();
        fs::write(&fixture.encrypted, &bytes[..HEADER_LEN]).unwrap();
        assert!(matches!(fixture.decrypt(), Err(Error::InvalidFormat(_))));
    }

    #[test]
    fn existing_encryption_output_is_never_overwritten() {
        let directory = tempdir().unwrap();
        let input = directory.path().join("input");
        let output = directory.path().join("output");
        fs::write(&input, b"new data").unwrap();
        fs::write(&output, b"valuable existing data").unwrap();
        assert!(matches!(
            encrypt_file_with_options(&input, &output, PASSWORD, test_options()),
            Err(Error::OutputExists(_))
        ));
        assert_eq!(fs::read(output).unwrap(), b"valuable existing data");
    }

    #[test]
    fn existing_decryption_output_is_never_overwritten() {
        let fixture = Fixture::new(b"new plaintext");
        fs::write(&fixture.decrypted, b"valuable existing data").unwrap();
        assert!(matches!(fixture.decrypt(), Err(Error::OutputExists(_))));
        assert_eq!(
            fs::read(&fixture.decrypted).unwrap(),
            b"valuable existing data"
        );
    }

    #[test]
    fn input_and_output_same_path_is_rejected() {
        let directory = tempdir().unwrap();
        let input = directory.path().join("input");
        fs::write(&input, b"must survive").unwrap();
        assert!(matches!(
            encrypt_file_with_options(&input, &input, PASSWORD, test_options()),
            Err(Error::SamePath)
        ));
        assert_eq!(fs::read(input).unwrap(), b"must survive");
    }

    #[test]
    fn empty_and_oversized_passwords_are_rejected() {
        let directory = tempdir().unwrap();
        let input = directory.path().join("input");
        let output = directory.path().join("output");
        fs::write(&input, b"data").unwrap();
        assert!(matches!(
            encrypt_file_with_options(&input, &output, b"", test_options()),
            Err(Error::EmptyPassword)
        ));
        assert!(matches!(
            encrypt_file_with_options(
                &input,
                &output,
                &vec![0; password::MAX_PASSWORD_LEN + 1],
                test_options()
            ),
            Err(Error::PasswordTooLarge)
        ));
    }

    #[test]
    fn missing_input_and_output_directory_report_context() {
        let directory = tempdir().unwrap();
        let missing = directory.path().join("missing");
        let output = directory.path().join("output");
        assert!(matches!(
            encrypt_file_with_options(&missing, &output, PASSWORD, test_options()),
            Err(Error::Io { .. })
        ));

        let input = directory.path().join("input");
        fs::write(&input, b"data").unwrap();
        let impossible = directory.path().join("no-directory").join("output");
        assert!(matches!(
            encrypt_file_with_options(&input, &impossible, PASSWORD, test_options()),
            Err(Error::Io { .. })
        ));
    }

    #[test]
    fn failed_decryption_removes_private_temporary_file() {
        let fixture = Fixture::new(b"leave no plaintext temp file");
        let before: BTreeSet<_> = fs::read_dir(fixture.directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        let result = decrypt_file(&fixture.encrypted, &fixture.decrypted, b"incorrect");
        assert!(matches!(result, Err(Error::AuthenticationFailed)));
        let after: BTreeSet<_> = fs::read_dir(fixture.directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(before, after);
    }

    #[test]
    fn read_chunk_handles_short_and_interrupted_reads() {
        struct DifficultReader {
            inner: Cursor<Vec<u8>>,
            interrupt_next: bool,
        }

        impl Read for DifficultReader {
            fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
                if self.interrupt_next {
                    self.interrupt_next = false;
                    return Err(io::Error::from(io::ErrorKind::Interrupted));
                }
                self.interrupt_next = true;
                let requested = output.len().min(3);
                self.inner.read(&mut output[..requested])
            }
        }

        let mut reader = DifficultReader {
            inner: Cursor::new((0_u8..20).collect()),
            interrupt_next: true,
        };
        assert_eq!(
            read_chunk(&mut reader, 17, Path::new("test")).unwrap(),
            (0_u8..17).collect::<Vec<_>>()
        );
        assert_eq!(
            read_chunk(&mut reader, 17, Path::new("test")).unwrap(),
            (17_u8..20).collect::<Vec<_>>()
        );
    }

    #[test]
    fn ciphertext_size_matches_the_canonical_frame_layout() {
        let chunk = MIN_CHUNK_SIZE as usize;
        for plaintext_len in [0, 1, chunk - 1, chunk, chunk + 1, 2 * chunk, 3 * chunk + 9] {
            let fixture = Fixture::new(&patterned_bytes(plaintext_len));
            let frame_count = plaintext_len.max(1).div_ceil(chunk);
            let expected = HEADER_LEN + plaintext_len + frame_count * (FRAME_HEADER_LEN + TAG_LEN);
            assert_eq!(
                fs::metadata(&fixture.encrypted).unwrap().len(),
                expected as u64
            );
        }
    }

    #[test]
    fn empty_ciphertext_contains_an_authenticated_final_frame() {
        let fixture = Fixture::new(&[]);
        assert_eq!(
            fs::metadata(&fixture.encrypted).unwrap().len(),
            (HEADER_LEN + FRAME_HEADER_LEN + TAG_LEN) as u64
        );
        fixture.decrypt().unwrap();
        assert!(fs::read(&fixture.decrypted).unwrap().is_empty());
    }

    #[test]
    fn valid_but_tampered_memory_cost_is_authenticated() {
        let fixture = Fixture::new(b"header parameter authentication");
        rewrite_header_u32(&fixture, 12, MIN_MEMORY_KIB + 1);
        assert!(matches!(
            fixture.decrypt(),
            Err(Error::AuthenticationFailed)
        ));
        assert!(!fixture.decrypted.exists());
    }

    #[test]
    fn valid_but_tampered_iteration_count_is_authenticated() {
        let fixture = Fixture::new(b"header parameter authentication");
        rewrite_header_u32(&fixture, 16, 2);
        assert!(matches!(
            fixture.decrypt(),
            Err(Error::AuthenticationFailed)
        ));
        assert!(!fixture.decrypted.exists());
    }

    #[test]
    fn valid_but_tampered_parallelism_is_authenticated() {
        let fixture = Fixture::new(b"header parameter authentication");
        rewrite_header_u32(&fixture, 20, 2);
        assert!(matches!(
            fixture.decrypt(),
            Err(Error::AuthenticationFailed)
        ));
        assert!(!fixture.decrypted.exists());
    }

    #[test]
    fn valid_but_tampered_chunk_size_is_authenticated() {
        let fixture = Fixture::new(b"header parameter authentication");
        rewrite_header_u32(&fixture, 24, MIN_CHUNK_SIZE * 2);
        assert!(matches!(
            fixture.decrypt(),
            Err(Error::AuthenticationFailed)
        ));
        assert!(!fixture.decrypted.exists());
    }

    #[test]
    fn every_partial_frame_header_is_rejected() {
        let fixture = Fixture::new(b"frame header truncation");
        let original = fs::read(&fixture.encrypted).unwrap();
        for present in 1..FRAME_HEADER_LEN {
            fs::write(&fixture.encrypted, &original[..HEADER_LEN + present]).unwrap();
            let output = fixture
                .decrypted
                .with_file_name(format!("partial-header-{present}"));
            assert!(matches!(
                decrypt_file(&fixture.encrypted, &output, PASSWORD),
                Err(Error::InvalidFormat("truncated frame header"))
            ));
            assert!(!output.exists());
        }
    }

    #[test]
    fn every_partial_final_tag_is_rejected() {
        let fixture = Fixture::new(&[]);
        let original = fs::read(&fixture.encrypted).unwrap();
        let tag_start = HEADER_LEN + FRAME_HEADER_LEN;
        for present in 0..TAG_LEN {
            fs::write(&fixture.encrypted, &original[..tag_start + present]).unwrap();
            let output = fixture
                .decrypted
                .with_file_name(format!("partial-tag-{present}"));
            assert!(matches!(
                decrypt_file(&fixture.encrypted, &output, PASSWORD),
                Err(Error::InvalidFormat("truncated frame"))
            ));
            assert!(!output.exists());
        }
    }

    #[test]
    fn late_chunk_corruption_cleans_partially_written_plaintext() {
        let data = patterned_bytes(3 * MIN_CHUNK_SIZE as usize + 71);
        let fixture = Fixture::new(&data);
        let mut bytes = fs::read(&fixture.encrypted).unwrap();
        let last_ciphertext_byte = bytes.len() - TAG_LEN - 1;
        bytes[last_ciphertext_byte] ^= 0x20;
        fs::write(&fixture.encrypted, bytes).unwrap();
        assert!(matches!(
            fixture.decrypt(),
            Err(Error::AuthenticationFailed)
        ));
        assert!(!fixture.decrypted.exists());
        let names: BTreeSet<_> = fs::read_dir(fixture.directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names.len(), 2, "temporary plaintext file was not removed");
    }

    #[test]
    fn unicode_paths_round_trip() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("秘密-🔐-данные.bin");
        let encrypted = directory.path().join("暗号化-🔒.x4x");
        let decrypted = directory.path().join("復元-✅.bin");
        let data = patterned_bytes(MIN_CHUNK_SIZE as usize + 123);
        fs::write(&source, &data).unwrap();
        encrypt_file_with_options(&source, &encrypted, PASSWORD, test_options()).unwrap();
        decrypt_file(&encrypted, &decrypted, PASSWORD).unwrap();
        assert_eq!(fs::read(decrypted).unwrap(), data);
    }

    #[test]
    fn decryption_never_modifies_ciphertext() {
        let fixture = Fixture::new(&patterned_bytes(2 * MIN_CHUNK_SIZE as usize + 3));
        let before = fs::read(&fixture.encrypted).unwrap();
        fixture.decrypt().unwrap();
        assert_eq!(fs::read(&fixture.encrypted).unwrap(), before);
    }

    #[test]
    fn normalized_same_path_is_rejected() {
        let directory = tempdir().unwrap();
        let input = directory.path().join("input");
        let subdirectory = directory.path().join("subdirectory");
        fs::create_dir(&subdirectory).unwrap();
        fs::write(&input, b"preserve me").unwrap();
        let aliased_output = subdirectory.join("..").join("input");
        assert!(matches!(
            encrypt_file_with_options(&input, &aliased_output, PASSWORD, test_options()),
            Err(Error::SamePath)
        ));
        assert_eq!(fs::read(input).unwrap(), b"preserve me");
    }

    #[test]
    fn malformed_magic_creates_no_output_or_temporary_file() {
        let fixture = Fixture::new(b"malformed header");
        let mut bytes = fs::read(&fixture.encrypted).unwrap();
        bytes[0] ^= 1;
        fs::write(&fixture.encrypted, bytes).unwrap();
        let before: BTreeSet<_> = fs::read_dir(fixture.directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert!(matches!(
            fixture.decrypt(),
            Err(Error::InvalidFormat("bad magic"))
        ));
        let after: BTreeSet<_> = fs::read_dir(fixture.directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(before, after);
        assert!(!fixture.decrypted.exists());
    }

    #[test]
    fn many_deterministic_lengths_round_trip() {
        let chunk = MIN_CHUNK_SIZE as usize;
        let mut state = 0x9e37_79b9_u32;
        for case in 0..24 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let length = (state as usize % (4 * chunk + 1)) + case;
            assert_round_trip(&patterned_bytes(length));
        }
    }

    #[test]
    fn round_trip_crosses_one_thousand_frame_boundaries() {
        let data = patterned_bytes(1_025 * MIN_CHUNK_SIZE as usize + 37);
        assert_round_trip(&data);
    }

    #[test]
    fn binary_password_with_nuls_and_non_utf8_bytes_round_trips() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("source");
        let encrypted = directory.path().join("encrypted");
        let decrypted = directory.path().join("decrypted");
        let binary_password = [0, 0xff, 0x80, b'p', 0, b'w'];
        let data = patterned_bytes(MIN_CHUNK_SIZE as usize + 5);
        fs::write(&source, &data).unwrap();
        encrypt_file_with_options(&source, &encrypted, &binary_password, test_options()).unwrap();
        decrypt_file(&encrypted, &decrypted, &binary_password).unwrap();
        assert_eq!(fs::read(decrypted).unwrap(), data);
    }

    #[test]
    fn maximum_length_password_round_trips() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("source");
        let encrypted = directory.path().join("encrypted");
        let decrypted = directory.path().join("decrypted");
        let password = vec![0x5a; password::MAX_PASSWORD_LEN];
        fs::write(&source, b"maximum password length").unwrap();
        encrypt_file_with_options(&source, &encrypted, &password, test_options()).unwrap();
        decrypt_file(&encrypted, &decrypted, &password).unwrap();
        assert_eq!(fs::read(decrypted).unwrap(), b"maximum password length");
    }

    #[test]
    fn subtly_different_passwords_all_fail_closed() {
        let fixture = Fixture::new(b"password distinction");
        for (case, wrong) in [
            b"a high entropy test passphrasf".as_slice(),
            b"a high entropy test passphrase ".as_slice(),
            b"a high entropy test passphrase\n".as_slice(),
            b"A high entropy test passphrase".as_slice(),
            b"a high entropy test passphras".as_slice(),
        ]
        .into_iter()
        .enumerate()
        {
            let output = fixture.decrypted.with_file_name(format!("wrong-{case}"));
            assert!(matches!(
                decrypt_file(&fixture.encrypted, &output, wrong),
                Err(Error::AuthenticationFailed)
            ));
            assert!(!output.exists());
        }
    }

    #[test]
    fn every_byte_of_an_empty_encrypted_file_is_integrity_checked() {
        let fixture = Fixture::new(&[]);
        let original = fs::read(&fixture.encrypted).unwrap();
        for offset in 0..original.len() {
            let mut mutated = original.clone();
            mutated[offset] ^= 1;
            fs::write(&fixture.encrypted, mutated).unwrap();
            let output = fixture
                .decrypted
                .with_file_name(format!("byte-mutation-{offset}"));
            assert!(
                decrypt_file(&fixture.encrypted, &output, PASSWORD).is_err(),
                "mutation at byte {offset} was accepted"
            );
            assert!(!output.exists());
        }
    }

    #[test]
    fn frames_cannot_be_spliced_between_files() {
        let first = Fixture::new(&patterned_bytes(MIN_CHUNK_SIZE as usize + 91));
        let second = Fixture::new(&patterned_bytes(MIN_CHUNK_SIZE as usize + 91));
        let mut first_bytes = fs::read(&first.encrypted).unwrap();
        let second_bytes = fs::read(&second.encrypted).unwrap();
        let frame_len = FRAME_HEADER_LEN + MIN_CHUNK_SIZE as usize + TAG_LEN;
        first_bytes[HEADER_LEN..HEADER_LEN + frame_len]
            .copy_from_slice(&second_bytes[HEADER_LEN..HEADER_LEN + frame_len]);
        fs::write(&first.encrypted, first_bytes).unwrap();
        assert!(matches!(first.decrypt(), Err(Error::AuthenticationFailed)));
        assert!(!first.decrypted.exists());
    }

    #[test]
    fn header_from_another_file_cannot_be_substituted() {
        let first = Fixture::new(b"first ciphertext");
        let second = Fixture::new(b"second ciphertext");
        let mut first_bytes = fs::read(&first.encrypted).unwrap();
        let second_bytes = fs::read(&second.encrypted).unwrap();
        first_bytes[..HEADER_LEN].copy_from_slice(&second_bytes[..HEADER_LEN]);
        fs::write(&first.encrypted, first_bytes).unwrap();
        assert!(matches!(first.decrypt(), Err(Error::AuthenticationFailed)));
    }

    #[test]
    fn removing_a_middle_frame_is_detected() {
        let fixture = Fixture::new(&patterned_bytes(3 * MIN_CHUNK_SIZE as usize));
        let bytes = fs::read(&fixture.encrypted).unwrap();
        let frame_len = FRAME_HEADER_LEN + MIN_CHUNK_SIZE as usize + TAG_LEN;
        let second_start = HEADER_LEN + frame_len;
        let mut without_middle = bytes[..second_start].to_vec();
        without_middle.extend_from_slice(&bytes[second_start + frame_len..]);
        fs::write(&fixture.encrypted, without_middle).unwrap();
        assert!(matches!(
            fixture.decrypt(),
            Err(Error::AuthenticationFailed)
        ));
        assert!(!fixture.decrypted.exists());
    }

    #[test]
    fn duplicating_a_nonfinal_frame_is_detected() {
        let fixture = Fixture::new(&patterned_bytes(2 * MIN_CHUNK_SIZE as usize + 1));
        let bytes = fs::read(&fixture.encrypted).unwrap();
        let frame_len = FRAME_HEADER_LEN + MIN_CHUNK_SIZE as usize + TAG_LEN;
        let first_frame = &bytes[HEADER_LEN..HEADER_LEN + frame_len];
        let mut duplicated = bytes[..HEADER_LEN + frame_len].to_vec();
        duplicated.extend_from_slice(first_frame);
        duplicated.extend_from_slice(&bytes[HEADER_LEN + frame_len..]);
        fs::write(&fixture.encrypted, duplicated).unwrap();
        assert!(matches!(
            fixture.decrypt(),
            Err(Error::AuthenticationFailed)
        ));
        assert!(!fixture.decrypted.exists());
    }

    #[test]
    fn concatenating_two_valid_encrypted_files_is_rejected() {
        let first = Fixture::new(b"first");
        let second = Fixture::new(b"second");
        let mut concatenated = fs::read(&first.encrypted).unwrap();
        concatenated.extend_from_slice(&fs::read(&second.encrypted).unwrap());
        fs::write(&first.encrypted, concatenated).unwrap();
        assert!(matches!(first.decrypt(), Err(Error::InvalidFormat(_))));
        assert!(!first.decrypted.exists());
    }

    #[test]
    fn read_only_input_can_be_encrypted_without_modification() {
        let directory = tempdir().unwrap();
        let input = directory.path().join("readonly");
        let output = directory.path().join("encrypted");
        fs::write(&input, b"read-only content").unwrap();
        let original_permissions = fs::metadata(&input).unwrap().permissions();
        let mut read_only_permissions = original_permissions.clone();
        read_only_permissions.set_readonly(true);
        fs::set_permissions(&input, read_only_permissions).unwrap();

        let result = encrypt_file_with_options(&input, &output, PASSWORD, test_options());
        fs::set_permissions(&input, original_permissions).unwrap();
        result.unwrap();
        assert_eq!(fs::read(input).unwrap(), b"read-only content");
    }

    #[test]
    fn simultaneous_encryptions_publish_exactly_one_complete_file() {
        const WORKERS: usize = 6;
        let directory = tempdir().unwrap();
        let input = directory.path().join("input");
        let output = directory.path().join("encrypted");
        let restored = directory.path().join("restored");
        let data = patterned_bytes(8 * MIN_CHUNK_SIZE as usize + 19);
        fs::write(&input, &data).unwrap();
        let barrier = Arc::new(Barrier::new(WORKERS));

        let handles: Vec<_> = (0..WORKERS)
            .map(|_| {
                let input = input.clone();
                let output = output.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    encrypt_file_with_options(&input, &output, PASSWORD, test_options())
                })
            })
            .collect();
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        for error in results.into_iter().filter_map(Result::err) {
            assert!(matches!(error, Error::OutputExists(_)));
        }
        decrypt_file(&output, &restored, PASSWORD).unwrap();
        assert_eq!(fs::read(restored).unwrap(), data);
    }

    #[test]
    fn simultaneous_decryptions_publish_exactly_one_complete_file() {
        const WORKERS: usize = 6;
        let fixture = Fixture::new(&patterned_bytes(8 * MIN_CHUNK_SIZE as usize + 23));
        let barrier = Arc::new(Barrier::new(WORKERS));

        let handles: Vec<_> = (0..WORKERS)
            .map(|_| {
                let encrypted = fixture.encrypted.clone();
                let decrypted = fixture.decrypted.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    decrypt_file(&encrypted, &decrypted, PASSWORD)
                })
            })
            .collect();
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        for error in results.into_iter().filter_map(Result::err) {
            assert!(matches!(error, Error::OutputExists(_)));
        }
        assert_eq!(
            fs::read(&fixture.decrypted).unwrap(),
            patterned_bytes(8 * MIN_CHUNK_SIZE as usize + 23)
        );
    }

    #[test]
    fn hard_link_destination_is_never_overwritten() {
        let directory = tempdir().unwrap();
        let input = directory.path().join("input");
        let hard_link = directory.path().join("hard-link");
        fs::write(&input, b"hard-linked content").unwrap();
        fs::hard_link(&input, &hard_link).unwrap();
        assert!(matches!(
            encrypt_file_with_options(&input, &hard_link, PASSWORD, test_options()),
            Err(Error::OutputExists(_) | Error::SamePath)
        ));
        assert_eq!(fs::read(input).unwrap(), b"hard-linked content");
        assert_eq!(fs::read(hard_link).unwrap(), b"hard-linked content");
    }

    #[test]
    fn existing_directory_destination_is_not_touched() {
        let directory = tempdir().unwrap();
        let input = directory.path().join("input");
        let destination = directory.path().join("existing-directory");
        fs::write(&input, b"data").unwrap();
        fs::create_dir(&destination).unwrap();
        assert!(matches!(
            encrypt_file_with_options(&input, &destination, PASSWORD, test_options()),
            Err(Error::OutputExists(_))
        ));
        assert!(destination.is_dir());
    }

    #[test]
    fn read_frame_header_distinguishes_clean_eof_from_partial_header() {
        let mut empty = Cursor::new(Vec::<u8>::new());
        assert_eq!(
            read_frame_header(&mut empty, Path::new("test")).unwrap(),
            None
        );

        let mut partial = Cursor::new(vec![0; FRAME_HEADER_LEN - 1]);
        assert!(matches!(
            read_frame_header(&mut partial, Path::new("test")),
            Err(Error::InvalidFormat("truncated frame header"))
        ));
    }

    #[test]
    fn frame_header_reader_retries_an_interrupted_first_read() {
        struct InterruptOnce {
            inner: Cursor<Vec<u8>>,
            interrupted: bool,
        }
        impl Read for InterruptOnce {
            fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
                if !self.interrupted {
                    self.interrupted = true;
                    return Err(io::Error::from(io::ErrorKind::Interrupted));
                }
                self.inner.read(output)
            }
        }

        let expected = *FrameHeader::new(0, true).as_bytes();
        let mut reader = InterruptOnce {
            inner: Cursor::new(expected.to_vec()),
            interrupted: false,
        };
        assert_eq!(
            read_frame_header(&mut reader, Path::new("test")).unwrap(),
            Some(expected)
        );
    }

    #[test]
    fn low_level_read_errors_keep_operation_and_path_context() {
        struct FailingReader;
        impl Read for FailingReader {
            fn read(&mut self, _output: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::PermissionDenied, "injected"))
            }
        }

        let error = read_chunk(&mut FailingReader, 32, Path::new("important.bin")).unwrap_err();
        match error {
            Error::Io {
                operation,
                path,
                source,
            } => {
                assert_eq!(operation, "cannot read input");
                assert_eq!(path, Path::new("important.bin"));
                assert_eq!(source.kind(), io::ErrorKind::PermissionDenied);
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn ensure_eof_retries_interruption_and_rejects_later_data() {
        struct InterruptThenByte(bool);
        impl Read for InterruptThenByte {
            fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
                if !self.0 {
                    self.0 = true;
                    return Err(io::Error::from(io::ErrorKind::Interrupted));
                }
                output[0] = 7;
                Ok(1)
            }
        }
        assert!(matches!(
            ensure_eof(&mut InterruptThenByte(false), Path::new("test")),
            Err(Error::InvalidFormat("trailing data after final frame"))
        ));
    }

    #[test]
    fn read_exact_maps_only_unexpected_eof_to_format_error() {
        let mut short = Cursor::new(vec![1, 2]);
        let mut output = [0; 3];
        assert!(matches!(
            read_exact_format(&mut short, &mut output, Path::new("test"), "short"),
            Err(Error::InvalidFormat("short"))
        ));

        assert!(matches!(
            read_exact_format(&mut BrokenReader, &mut output, Path::new("test"), "short"),
            Err(Error::Io { .. })
        ));
    }

    #[test]
    fn derived_key_matches_the_version_one_known_answer() {
        let header = Header::new(test_options(), [0x42; 16], [0x24; 16]).unwrap();
        let key = derive_key(b"x4x known-answer password", &header).unwrap();
        assert_eq!(
            *key,
            [
                113, 101, 218, 239, 50, 250, 154, 6, 74, 224, 165, 216, 192, 33, 2, 158, 130, 64,
                176, 151, 64, 205, 213, 70, 122, 117, 223, 123, 59, 251, 172, 207,
            ]
        );
    }

    #[test]
    fn complete_version_one_frame_matches_known_answer() {
        let header = Header::new(test_options(), [0x42; 16], [0x24; 16]).unwrap();
        let key = derive_key(b"x4x known-answer password", &header).unwrap();
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice()).unwrap();
        let plaintext = b"x4x version one vector";
        let frame = FrameHeader::new(
            u32::try_from(plaintext.len()).expect("test vector length fits in u32"),
            true,
        );
        let frame_nonce = XNonce::from(nonce(&header.nonce_prefix, 0));
        let aad = associated_data(&header, 0, &frame);
        let ciphertext = cipher
            .encrypt(
                &frame_nonce,
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .unwrap();
        assert_eq!(
            ciphertext,
            [
                73, 73, 16, 136, 141, 227, 232, 14, 34, 116, 217, 156, 240, 233, 7, 12, 185, 28,
                192, 112, 190, 138, 118, 178, 41, 207, 86, 62, 143, 100, 186, 98, 65, 13, 34, 102,
                113, 177,
            ]
        );
        assert_eq!(
            cipher
                .decrypt(
                    &frame_nonce,
                    Payload {
                        msg: &ciphertext,
                        aad: &aad,
                    },
                )
                .unwrap(),
            plaintext
        );
    }

    #[test]
    fn corruption_in_each_frame_is_detected_without_output() {
        let chunk = MIN_CHUNK_SIZE as usize;
        let frame_span = FRAME_HEADER_LEN + chunk + TAG_LEN;
        let frame_count = 12;
        let fixture = Fixture::new(&patterned_bytes((frame_count - 1) * chunk + 37));
        let original = fs::read(&fixture.encrypted).unwrap();
        for frame_index in 0..frame_count {
            let mut mutated = original.clone();
            let frame_start = HEADER_LEN + frame_index * frame_span;
            let plaintext_len = if frame_index + 1 == frame_count {
                37
            } else {
                chunk
            };
            mutated[frame_start + FRAME_HEADER_LEN + plaintext_len / 2] ^= 0x80;
            fs::write(&fixture.encrypted, mutated).unwrap();
            let output = fixture
                .decrypted
                .with_file_name(format!("corrupt-frame-{frame_index}"));
            assert!(matches!(
                decrypt_file(&fixture.encrypted, &output, PASSWORD),
                Err(Error::AuthenticationFailed)
            ));
            assert!(!output.exists());
        }
    }

    #[test]
    fn truncation_at_every_frame_boundary_is_detected() {
        let chunk = MIN_CHUNK_SIZE as usize;
        let frame_span = FRAME_HEADER_LEN + chunk + TAG_LEN;
        let frame_count = 10;
        let fixture = Fixture::new(&patterned_bytes((frame_count - 1) * chunk + 7));
        let original = fs::read(&fixture.encrypted).unwrap();
        for completed_frames in 0..frame_count {
            let boundary = HEADER_LEN + completed_frames * frame_span;
            fs::write(&fixture.encrypted, &original[..boundary]).unwrap();
            let output = fixture
                .decrypted
                .with_file_name(format!("boundary-{completed_frames}"));
            assert!(decrypt_file(&fixture.encrypted, &output, PASSWORD).is_err());
            assert!(!output.exists());
        }
    }

    #[test]
    fn shrinking_authenticated_final_length_is_detected() {
        let fixture = Fixture::new(&patterned_bytes(100));
        rewrite_header_u32(&fixture, HEADER_LEN, 99);
        assert!(matches!(
            fixture.decrypt(),
            Err(Error::AuthenticationFailed)
        ));
        assert!(!fixture.decrypted.exists());
    }

    #[test]
    fn expanding_final_length_without_data_is_reported_as_truncation() {
        let fixture = Fixture::new(&patterned_bytes(100));
        rewrite_header_u32(&fixture, HEADER_LEN, 101);
        assert!(matches!(
            fixture.decrypt(),
            Err(Error::InvalidFormat("truncated frame"))
        ));
        assert!(!fixture.decrypted.exists());
    }

    #[test]
    fn wrong_password_and_ciphertext_damage_share_the_same_error() {
        let wrong_password_fixture = Fixture::new(b"oracle resistance");
        let wrong_password_error = decrypt_file(
            &wrong_password_fixture.encrypted,
            &wrong_password_fixture.decrypted,
            b"incorrect",
        )
        .unwrap_err();

        let damaged_fixture = Fixture::new(b"oracle resistance");
        let mut bytes = fs::read(&damaged_fixture.encrypted).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        fs::write(&damaged_fixture.encrypted, bytes).unwrap();
        let damage_error = damaged_fixture.decrypt().unwrap_err();

        assert!(matches!(wrong_password_error, Error::AuthenticationFailed));
        assert!(matches!(damage_error, Error::AuthenticationFailed));
        assert_eq!(wrong_password_error.to_string(), damage_error.to_string());
    }

    #[test]
    fn successful_operations_leave_no_temporary_files() {
        let fixture = Fixture::new(b"clean successful transaction");
        let after_encrypt: BTreeSet<_> = fs::read_dir(fixture.directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(after_encrypt.len(), 2);
        fixture.decrypt().unwrap();
        let after_decrypt: BTreeSet<_> = fs::read_dir(fixture.directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(after_decrypt.len(), 3);
    }

    #[test]
    fn failed_password_attempt_never_modifies_ciphertext() {
        let fixture = Fixture::new(&patterned_bytes(MIN_CHUNK_SIZE as usize + 5));
        let before = fs::read(&fixture.encrypted).unwrap();
        assert!(decrypt_file(&fixture.encrypted, &fixture.decrypted, b"wrong").is_err());
        assert_eq!(fs::read(&fixture.encrypted).unwrap(), before);
    }

    #[test]
    fn password_validation_happens_before_any_filesystem_access() {
        assert!(matches!(
            encrypt_file_with_options(
                Path::new("missing-input"),
                Path::new("missing-output"),
                b"",
                test_options()
            ),
            Err(Error::EmptyPassword)
        ));
        assert!(matches!(
            decrypt_file(Path::new("missing-input"), Path::new("missing-output"), b""),
            Err(Error::EmptyPassword)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn completed_outputs_are_owner_only_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let fixture = Fixture::new(b"private permissions");
        fixture.decrypt().unwrap();
        assert_eq!(
            fs::metadata(&fixture.encrypted)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&fixture.decrypted)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}
