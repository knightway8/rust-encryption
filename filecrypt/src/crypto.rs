use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::Path;

use aead::KeyInit;
use aead_stream::{DecryptorLE31, EncryptorLE31, StreamLE31};
use aes_gcm_siv::Aes256GcmSiv;
use chacha20poly1305::XChaCha20Poly1305;
use hkdf::Hkdf;
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{FileCryptError, Result};
use crate::format::{
    Algorithm, CHUNK_SIZE, FOOTER_SIZE, HEADER_SIZE, Header, MAX_PLAINTEXT_SIZE, RECORD_DATA,
    RECORD_END, RECORD_HEADER_SIZE, RecordHeader, TAG_SIZE, make_aad, make_footer, verify_footer,
};
use crate::key::MasterKey;
use crate::staging::{StagedFile, output_parent, path_exists_without_following};

enum StreamEncryptor {
    Aes(Box<EncryptorLE31<Aes256GcmSiv>>),
    XChaCha(EncryptorLE31<XChaCha20Poly1305>),
}

impl StreamEncryptor {
    fn new(header: &Header, key: &MasterKey) -> Result<Self> {
        let derived = derive_file_key(header, key)?;
        match header.algorithm {
            Algorithm::Aes256GcmSiv => {
                let cipher = Aes256GcmSiv::new_from_slice(derived.expose_secret())
                    .map_err(|_| FileCryptError::Crypto)?;
                let mut nonce =
                    aead_stream::Nonce::<Aes256GcmSiv, StreamLE31<Aes256GcmSiv>>::default();
                nonce.copy_from_slice(&header.stream_nonce[..8]);
                Ok(Self::Aes(Box::new(EncryptorLE31::from_aead(
                    cipher, &nonce,
                ))))
            }
            Algorithm::XChaCha20Poly1305 => {
                let cipher = XChaCha20Poly1305::new_from_slice(derived.expose_secret())
                    .map_err(|_| FileCryptError::Crypto)?;
                let mut nonce = aead_stream::Nonce::<
                    XChaCha20Poly1305,
                    StreamLE31<XChaCha20Poly1305>,
                >::default();
                nonce.copy_from_slice(&header.stream_nonce[..20]);
                Ok(Self::XChaCha(EncryptorLE31::from_aead(cipher, &nonce)))
            }
        }
    }

    fn next(&mut self, aad: &[u8], buffer: &mut Vec<u8>) -> Result<()> {
        match self {
            Self::Aes(stream) => stream
                .encrypt_next_in_place(aad, buffer)
                .map_err(|_| FileCryptError::Crypto),
            Self::XChaCha(stream) => stream
                .encrypt_next_in_place(aad, buffer)
                .map_err(|_| FileCryptError::Crypto),
        }
    }

    fn last(self, aad: &[u8], buffer: &mut Vec<u8>) -> Result<()> {
        match self {
            Self::Aes(stream) => (*stream)
                .encrypt_last_in_place(aad, buffer)
                .map_err(|_| FileCryptError::Crypto),
            Self::XChaCha(stream) => stream
                .encrypt_last_in_place(aad, buffer)
                .map_err(|_| FileCryptError::Crypto),
        }
    }
}

enum StreamDecryptor {
    Aes(Box<DecryptorLE31<Aes256GcmSiv>>),
    XChaCha(DecryptorLE31<XChaCha20Poly1305>),
}

impl StreamDecryptor {
    fn new(header: &Header, key: &MasterKey) -> Result<Self> {
        let derived = derive_file_key(header, key)?;
        match header.algorithm {
            Algorithm::Aes256GcmSiv => {
                let cipher = Aes256GcmSiv::new_from_slice(derived.expose_secret())
                    .map_err(|_| FileCryptError::Crypto)?;
                let mut nonce =
                    aead_stream::Nonce::<Aes256GcmSiv, StreamLE31<Aes256GcmSiv>>::default();
                nonce.copy_from_slice(&header.stream_nonce[..8]);
                Ok(Self::Aes(Box::new(DecryptorLE31::from_aead(
                    cipher, &nonce,
                ))))
            }
            Algorithm::XChaCha20Poly1305 => {
                let cipher = XChaCha20Poly1305::new_from_slice(derived.expose_secret())
                    .map_err(|_| FileCryptError::Crypto)?;
                let mut nonce = aead_stream::Nonce::<
                    XChaCha20Poly1305,
                    StreamLE31<XChaCha20Poly1305>,
                >::default();
                nonce.copy_from_slice(&header.stream_nonce[..20]);
                Ok(Self::XChaCha(DecryptorLE31::from_aead(cipher, &nonce)))
            }
        }
    }

    fn next(&mut self, aad: &[u8], buffer: &mut Vec<u8>) -> Result<()> {
        match self {
            Self::Aes(stream) => stream
                .decrypt_next_in_place(aad, buffer)
                .map_err(|_| FileCryptError::AuthenticationFailed),
            Self::XChaCha(stream) => stream
                .decrypt_next_in_place(aad, buffer)
                .map_err(|_| FileCryptError::AuthenticationFailed),
        }
    }

    fn last(self, aad: &[u8], buffer: &mut Vec<u8>) -> Result<()> {
        match self {
            Self::Aes(stream) => (*stream)
                .decrypt_last_in_place(aad, buffer)
                .map_err(|_| FileCryptError::AuthenticationFailed),
            Self::XChaCha(stream) => stream
                .decrypt_last_in_place(aad, buffer)
                .map_err(|_| FileCryptError::AuthenticationFailed),
        }
    }
}

/// Encrypt a regular file as authenticated 1 MiB STREAM records.
///
/// The output is built in a private sibling temporary file and published only
/// after it is fully written and synchronized. An existing destination is
/// never replaced, including one created concurrently during encryption.
///
/// # Errors
///
/// Returns an error if the input or key is invalid, secure randomness or an
/// I/O operation fails, the input is too large or changes length while read,
/// or the destination already exists (including a concurrent creation).
pub fn encrypt_file(
    algorithm: Algorithm,
    input_path: &Path,
    output_path: &Path,
    key: &MasterKey,
) -> Result<()> {
    preflight_output(output_path)?;
    let (mut input, plaintext_len) = open_regular_input(input_path)?;
    if plaintext_len > MAX_PLAINTEXT_SIZE {
        return Err(FileCryptError::FileTooLarge {
            maximum: MAX_PLAINTEXT_SIZE,
        });
    }

    let mut salt = [0_u8; 32];
    getrandom::fill(&mut salt).map_err(|error| FileCryptError::Random(error.to_string()))?;
    let mut stream_nonce = [0_u8; 20];
    getrandom::fill(&mut stream_nonce[..algorithm.stream_nonce_size()])
        .map_err(|error| FileCryptError::Random(error.to_string()))?;

    let header = Header::new(algorithm, plaintext_len, salt, stream_nonce);
    let encryptor = StreamEncryptor::new(&header, key)?;
    let parent = output_parent(output_path);
    let mut temporary = create_temporary(parent)?;
    let temporary_path = temporary.path().to_path_buf();

    encrypt_to_writer(
        &mut input,
        temporary.as_file_mut(),
        input_path,
        &temporary_path,
        &header,
        encryptor,
    )?;

    commit_temporary(temporary, output_path)
}

/// Decrypt and authenticate a filecrypt stream.
///
/// No plaintext is published at `output_path` until the authenticated footer
/// and physical end-of-file have both been verified.
///
/// # Errors
///
/// Returns an error if the input is not a supported, fully authenticated
/// filecrypt stream, the key is wrong, an I/O operation fails, or the
/// destination already exists (including a concurrent creation).
pub fn decrypt_file(input_path: &Path, output_path: &Path, key: &MasterKey) -> Result<Algorithm> {
    preflight_output(output_path)?;
    let (mut input, _) = open_regular_input(input_path)?;

    let mut raw_header = [0_u8; HEADER_SIZE];
    read_exact_integrity(&mut input, &mut raw_header, input_path)?;
    let header = Header::parse(raw_header)?;
    let algorithm = header.algorithm;
    let decryptor = StreamDecryptor::new(&header, key)?;

    let parent = output_parent(output_path);
    let mut temporary = create_temporary(parent)?;
    let temporary_path = temporary.path().to_path_buf();
    decrypt_to_writer(
        &mut input,
        temporary.as_file_mut(),
        input_path,
        &temporary_path,
        &header,
        decryptor,
    )?;
    commit_temporary(temporary, output_path)?;
    Ok(algorithm)
}

fn derive_file_key(header: &Header, master: &MasterKey) -> Result<SecretBox<[u8; 32]>> {
    let hkdf = Hkdf::<Sha256>::new(Some(&header.salt), master.expose_secret());
    let mut derived = SecretBox::<[u8; 32]>::default();
    hkdf.expand(header.algorithm.kdf_info(), derived.expose_secret_mut())
        .map_err(|_| FileCryptError::Crypto)?;
    Ok(derived)
}

fn encrypt_to_writer(
    input: &mut File,
    output: &mut File,
    input_path: &Path,
    output_path: &Path,
    header: &Header,
    mut encryptor: StreamEncryptor,
) -> Result<()> {
    output
        .write_all(&header.raw)
        .map_err(|source| FileCryptError::io("write encrypted header", output_path, source))?;

    let chunk_count = header.data_record_count();
    let mut remaining = header.plaintext_len;
    let mut buffer = Zeroizing::new(Vec::with_capacity(CHUNK_SIZE + TAG_SIZE));

    for sequence in 0..chunk_count {
        let plaintext_size = usize::try_from(remaining.min(CHUNK_SIZE as u64))
            .map_err(|_| FileCryptError::Crypto)?;
        buffer.resize(plaintext_size, 0);
        input
            .read_exact(&mut buffer)
            .map_err(|source| match source.kind() {
                io::ErrorKind::UnexpectedEof => FileCryptError::InputChanged,
                _ => FileCryptError::io("read input", input_path, source),
            })?;

        let ciphertext_size = plaintext_size
            .checked_add(TAG_SIZE)
            .ok_or(FileCryptError::Crypto)?;
        let ciphertext_size = u32::try_from(ciphertext_size).map_err(|_| FileCryptError::Crypto)?;
        let record = RecordHeader::new(RECORD_DATA, ciphertext_size, sequence);
        let aad = make_aad(&header.raw, &record.raw);
        encryptor.next(&aad, &mut buffer)?;

        output
            .write_all(&record.raw)
            .and_then(|()| output.write_all(&buffer))
            .map_err(|source| FileCryptError::io("write encrypted data", output_path, source))?;
        buffer.clear();
        remaining -= plaintext_size as u64;
    }

    if remaining != 0 || read_one(input, input_path)?.is_some() {
        return Err(FileCryptError::InputChanged);
    }

    let footer_plaintext = make_footer(chunk_count, header.plaintext_len);
    buffer.extend_from_slice(&footer_plaintext);
    let footer_ciphertext_size =
        u32::try_from(FOOTER_SIZE + TAG_SIZE).map_err(|_| FileCryptError::Crypto)?;
    let record = RecordHeader::new(RECORD_END, footer_ciphertext_size, chunk_count);
    let aad = make_aad(&header.raw, &record.raw);
    encryptor.last(&aad, &mut buffer)?;
    output
        .write_all(&record.raw)
        .and_then(|()| output.write_all(&buffer))
        .map_err(|source| FileCryptError::io("write encrypted footer", output_path, source))?;
    output
        .flush()
        .map_err(|source| FileCryptError::io("flush encrypted output", output_path, source))?;
    Ok(())
}

fn decrypt_to_writer(
    input: &mut File,
    output: &mut File,
    input_path: &Path,
    output_path: &Path,
    header: &Header,
    mut decryptor: StreamDecryptor,
) -> Result<()> {
    let chunk_count = header.data_record_count();
    let mut remaining = header.plaintext_len;
    let mut buffer = Zeroizing::new(Vec::with_capacity(CHUNK_SIZE + TAG_SIZE));

    for sequence in 0..chunk_count {
        let record = read_record_header(input, input_path)?;
        let expected_plaintext = usize::try_from(remaining.min(CHUNK_SIZE as u64))
            .map_err(|_| FileCryptError::AuthenticationFailed)?;
        let expected_ciphertext = expected_plaintext
            .checked_add(TAG_SIZE)
            .ok_or(FileCryptError::AuthenticationFailed)?;
        let expected_ciphertext =
            u32::try_from(expected_ciphertext).map_err(|_| FileCryptError::AuthenticationFailed)?;
        if record.record_type != RECORD_DATA
            || record.sequence != sequence
            || record.ciphertext_len != expected_ciphertext
        {
            return Err(FileCryptError::AuthenticationFailed);
        }

        buffer.resize(record.ciphertext_len as usize, 0);
        read_exact_integrity(input, &mut buffer, input_path)?;
        let aad = make_aad(&header.raw, &record.raw);
        decryptor.next(&aad, &mut buffer)?;
        if buffer.len() != expected_plaintext {
            return Err(FileCryptError::AuthenticationFailed);
        }
        output.write_all(&buffer).map_err(|source| {
            FileCryptError::io("write temporary plaintext", output_path, source)
        })?;
        buffer.clear();
        remaining -= expected_plaintext as u64;
    }

    if remaining != 0 {
        return Err(FileCryptError::AuthenticationFailed);
    }

    let record = read_record_header(input, input_path)?;
    if record.record_type != RECORD_END
        || record.sequence != chunk_count
        || record.ciphertext_len as usize != FOOTER_SIZE + TAG_SIZE
    {
        return Err(FileCryptError::AuthenticationFailed);
    }
    buffer.resize(record.ciphertext_len as usize, 0);
    read_exact_integrity(input, &mut buffer, input_path)?;
    let aad = make_aad(&header.raw, &record.raw);
    decryptor.last(&aad, &mut buffer)?;
    verify_footer(&buffer, chunk_count, header.plaintext_len)?;

    if read_one(input, input_path)?.is_some() {
        return Err(FileCryptError::AuthenticationFailed);
    }
    output
        .flush()
        .map_err(|source| FileCryptError::io("flush plaintext output", output_path, source))?;
    Ok(())
}

fn read_record_header(input: &mut File, input_path: &Path) -> Result<RecordHeader> {
    let mut raw = [0_u8; RECORD_HEADER_SIZE];
    read_exact_integrity(input, &mut raw, input_path)?;
    RecordHeader::parse(raw)
}

fn read_exact_integrity(reader: &mut impl Read, buffer: &mut [u8], path: &Path) -> Result<()> {
    reader.read_exact(buffer).map_err(|source| {
        if source.kind() == io::ErrorKind::UnexpectedEof {
            FileCryptError::AuthenticationFailed
        } else {
            FileCryptError::io("read encrypted input", path, source)
        }
    })
}

fn read_one(reader: &mut impl Read, path: &Path) -> Result<Option<u8>> {
    let mut byte = [0_u8; 1];
    loop {
        match reader.read(&mut byte) {
            Ok(0) => return Ok(None),
            Ok(_) => return Ok(Some(byte[0])),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(FileCryptError::io("read input", path, error)),
        }
    }
}

fn open_regular_input(path: &Path) -> Result<(File, u64)> {
    #[cfg(unix)]
    let file = {
        // Opening a FIFO for ordinary blocking reads can wait forever before
        // metadata is available for the regular-file check. Open
        // nonblocking first, validate the opened object, then restore normal
        // blocking behavior for the accepted regular file below.
        let flags =
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NONBLOCK;
        let descriptor = rustix::fs::open(path, flags, rustix::fs::Mode::empty())
            .map_err(|source| FileCryptError::io("open input", path, io::Error::from(source)))?;
        File::from(descriptor)
    };
    #[cfg(not(unix))]
    let file = File::open(path).map_err(|source| FileCryptError::io("open input", path, source))?;

    let metadata = file
        .metadata()
        .map_err(|source| FileCryptError::io("inspect input", path, source))?;
    if !metadata.is_file() {
        return Err(FileCryptError::InputNotRegular(path.to_path_buf()));
    }

    #[cfg(unix)]
    {
        let flags = rustix::fs::fcntl_getfl(&file).map_err(|source| {
            FileCryptError::io(
                "inspect input descriptor flags",
                path,
                io::Error::from(source),
            )
        })?;
        rustix::fs::fcntl_setfl(&file, flags.difference(rustix::fs::OFlags::NONBLOCK)).map_err(
            |source| {
                FileCryptError::io(
                    "restore blocking input reads",
                    path,
                    io::Error::from(source),
                )
            },
        )?;
    }

    Ok((file, metadata.len()))
}

fn preflight_output(path: &Path) -> Result<()> {
    if path.file_name().is_none() {
        return Err(FileCryptError::InvalidOutputPath(path.to_path_buf()));
    }
    let parent = output_parent(path);
    let metadata = fs::metadata(parent)
        .map_err(|source| FileCryptError::io("inspect output directory", parent, source))?;
    if !metadata.is_dir() {
        return Err(FileCryptError::InvalidOutputPath(path.to_path_buf()));
    }
    if path_exists_without_following(path)? {
        return Err(FileCryptError::OutputExists(path.to_path_buf()));
    }
    Ok(())
}

fn create_temporary(parent: &Path) -> Result<StagedFile> {
    StagedFile::create(parent, ".filecrypt-")
}

fn commit_temporary(temporary: StagedFile, destination: &Path) -> Result<()> {
    temporary.commit(destination, "publish output without replacement")
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    #[cfg(unix)]
    use std::sync::mpsc;
    #[cfg(unix)]
    use std::time::Duration;

    use crate::format::MAX_DATA_RECORDS;

    use super::*;

    const AES_VECTOR_HEX: &str = concat!(
        "464352595054303101000100000010002100000000000000",
        "202122232425262728292a2b2c2d2e2f3031323334353637",
        "38393a3b3c3d3e3fa0a1a2a3a4a5a6a70000000000000000",
        "000000000000000000000000000000000000000000000000",
        "010000003100000000000000000000005d2b9f765222cc0c",
        "7d6ecf19411319ed6c52bdb92149067ccd926d89ede3d25c",
        "13023a1684f6bfb51ca75f128b7deb8c050200000028000000",
        "0100000000000000b09cbd1adf5c6364775363e586824b25",
        "0beaef4ec6a274b51c80f0c0f5b7d321ff865d32fc0b82dc",
    );
    const XCHACHA_VECTOR_HEX: &str = concat!(
        "464352595054303101000200000010002100000000000000",
        "202122232425262728292a2b2c2d2e2f3031323334353637",
        "38393a3b3c3d3e3fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
        "b0b1b2b30000000000000000000000000000000000000000",
        "01000000310000000000000000000000811d12b15f4effef",
        "8264e8db3a3c045c8bab8cff461e2fc9e05240931ffb05bc",
        "82c6b2b0504fe72a92b9ca150d26fb42200200000028000000",
        "010000000000000052fb4220b2126f0383d71e81a59cd6dc",
        "7062a1b7eb15ee9b9d8c0cc59d140685558fd7010465adde",
    );

    fn deterministic_key() -> MasterKey {
        let mut key = MasterKey::default();
        for (byte, value) in key.expose_secret_mut().iter_mut().zip(0_u8..32) {
            *byte = value;
        }
        key
    }

    fn deterministic_header(algorithm: Algorithm, plaintext_len: u64) -> Header {
        let salt = std::array::from_fn(|index| {
            0x20_u8.wrapping_add(u8::try_from(index).unwrap_or_default())
        });
        let nonce = std::array::from_fn(|index| {
            0xa0_u8.wrapping_add(u8::try_from(index).unwrap_or_default())
        });
        Header::new(algorithm, plaintext_len, salt, nonce)
    }

    fn decode_hex(encoded: &str) -> Option<Vec<u8>> {
        fn nibble(byte: u8) -> Option<u8> {
            match byte {
                b'0'..=b'9' => Some(byte - b'0'),
                b'a'..=b'f' => Some(byte - b'a' + 10),
                b'A'..=b'F' => Some(byte - b'A' + 10),
                _ => None,
            }
        }

        if encoded.len() % 2 != 0 {
            return None;
        }
        encoded
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| Some((nibble(pair[0])? << 4) | nibble(pair[1])?))
            .collect()
    }

    fn authenticated_empty_stream(
        algorithm: Algorithm,
        key: &MasterKey,
        footer: [u8; FOOTER_SIZE],
    ) -> Result<Vec<u8>> {
        let header = deterministic_header(algorithm, 0);
        let record = RecordHeader::new(RECORD_END, 40, 0);
        let aad = make_aad(&header.raw, &record.raw);
        let mut ciphertext = footer.to_vec();
        StreamEncryptor::new(&header, key)?.last(&aad, &mut ciphertext)?;

        let mut stream = Vec::with_capacity(HEADER_SIZE + RECORD_HEADER_SIZE + ciphertext.len());
        stream.extend_from_slice(&header.raw);
        stream.extend_from_slice(&record.raw);
        stream.extend_from_slice(&ciphertext);
        Ok(stream)
    }

    #[test]
    fn deterministic_wire_vectors_match_independent_implementations() -> Result<()> {
        // These complete streams were generated independently with Python
        // cryptography's HKDF/AESGCMSIV and libsodium's XChaCha20-Poly1305,
        // constructing the LE31 nonces, record AAD, and framing by hand.
        let directory = tempfile::tempdir()
            .map_err(|source| FileCryptError::io("create test directory", "<test>", source))?;
        let key = deterministic_key();
        let plaintext: Vec<u8> = (0_u8..33).collect();

        for (algorithm, encoded) in [
            (Algorithm::Aes256GcmSiv, AES_VECTOR_HEX),
            (Algorithm::XChaCha20Poly1305, XCHACHA_VECTOR_HEX),
        ] {
            let id = algorithm as u8;
            let input_path = directory.path().join(format!("vector-{id}.plain"));
            let encrypted_path = directory.path().join(format!("vector-{id}.enc"));
            let decrypted_path = directory.path().join(format!("vector-{id}.out"));
            fs::write(&input_path, &plaintext).map_err(|source| {
                FileCryptError::io("write test plaintext", &input_path, source)
            })?;
            let mut input = File::open(&input_path)
                .map_err(|source| FileCryptError::io("open test plaintext", &input_path, source))?;
            let mut output = File::create(&encrypted_path).map_err(|source| {
                FileCryptError::io("create test ciphertext", &encrypted_path, source)
            })?;
            let header = deterministic_header(algorithm, 33);
            let encryptor = StreamEncryptor::new(&header, &key)?;
            encrypt_to_writer(
                &mut input,
                &mut output,
                &input_path,
                &encrypted_path,
                &header,
                encryptor,
            )?;
            drop(output);

            let actual = fs::read(&encrypted_path).map_err(|source| {
                FileCryptError::io("read test ciphertext", &encrypted_path, source)
            })?;
            let expected = decode_hex(encoded).ok_or(FileCryptError::Crypto)?;
            assert_eq!(actual, expected, "suite {id} wire vector changed");

            let detected = decrypt_file(&encrypted_path, &decrypted_path, &key)?;
            assert_eq!(detected, algorithm);
            assert_eq!(
                fs::read(&decrypted_path).map_err(|source| FileCryptError::io(
                    "read test round trip",
                    &decrypted_path,
                    source
                ))?,
                plaintext
            );
        }
        Ok(())
    }

    #[test]
    fn file_key_derivation_matches_independent_known_answers() -> Result<()> {
        let key = deterministic_key();
        for (algorithm, expected_hex) in [
            (
                Algorithm::Aes256GcmSiv,
                "1bbc9c6d65c4dd9403e451aad63f69d3d4705fb0c28be4493833a772f03eb307",
            ),
            (
                Algorithm::XChaCha20Poly1305,
                "eff766f6767e0ea505e77bf1923fc137a9444fcca2f489d0802fd872b0148026",
            ),
        ] {
            let header = deterministic_header(algorithm, 33);
            let derived = derive_file_key(&header, &key)?;
            assert_eq!(
                Some(derived.expose_secret().to_vec()),
                decode_hex(expected_hex)
            );
        }
        Ok(())
    }

    #[test]
    fn stream_final_marker_cannot_be_substituted() -> Result<()> {
        for algorithm in [Algorithm::Aes256GcmSiv, Algorithm::XChaCha20Poly1305] {
            let key = deterministic_key();
            let header = deterministic_header(algorithm, 5);
            let record = RecordHeader::new(RECORD_DATA, 21, 0);
            let aad = make_aad(&header.raw, &record.raw);

            let mut encrypted_as_last = b"frame".to_vec();
            StreamEncryptor::new(&header, &key)?.last(&aad, &mut encrypted_as_last)?;
            let mut decryptor = StreamDecryptor::new(&header, &key)?;
            assert!(matches!(
                decryptor.next(&aad, &mut encrypted_as_last),
                Err(FileCryptError::AuthenticationFailed)
            ));

            let mut encrypted_as_next = b"frame".to_vec();
            let mut encryptor = StreamEncryptor::new(&header, &key)?;
            encryptor.next(&aad, &mut encrypted_as_next)?;
            assert!(matches!(
                StreamDecryptor::new(&header, &key)?.last(&aad, &mut encrypted_as_next),
                Err(FileCryptError::AuthenticationFailed)
            ));
        }
        Ok(())
    }

    #[test]
    fn every_aad_ciphertext_and_tag_byte_is_authenticated() -> Result<()> {
        for algorithm in [Algorithm::Aes256GcmSiv, Algorithm::XChaCha20Poly1305] {
            let key = deterministic_key();
            let header = deterministic_header(algorithm, 9);
            let record = RecordHeader::new(RECORD_END, 25, 0);
            let aad = make_aad(&header.raw, &record.raw);
            let mut ciphertext = b"integrity".to_vec();
            StreamEncryptor::new(&header, &key)?.last(&aad, &mut ciphertext)?;

            let mut control = ciphertext.clone();
            StreamDecryptor::new(&header, &key)?.last(&aad, &mut control)?;
            assert_eq!(control, b"integrity");

            for offset in 0..aad.len() {
                let mut changed_aad = aad;
                changed_aad[offset] ^= 1;
                let mut candidate = ciphertext.clone();
                assert!(matches!(
                    StreamDecryptor::new(&header, &key)?.last(&changed_aad, &mut candidate),
                    Err(FileCryptError::AuthenticationFailed)
                ));
            }

            for offset in 0..ciphertext.len() {
                let mut candidate = ciphertext.clone();
                candidate[offset] ^= 1;
                assert!(matches!(
                    StreamDecryptor::new(&header, &key)?.last(&aad, &mut candidate),
                    Err(FileCryptError::AuthenticationFailed)
                ));
            }
        }
        Ok(())
    }

    #[test]
    fn authenticated_but_inconsistent_footers_are_rejected_without_output() -> Result<()> {
        let directory = tempfile::tempdir()
            .map_err(|source| FileCryptError::io("create test directory", "<test>", source))?;
        let key = deterministic_key();
        let mut bad_magic = make_footer(0, 0);
        bad_magic[0] ^= 1;

        for algorithm in [Algorithm::Aes256GcmSiv, Algorithm::XChaCha20Poly1305] {
            for (index, footer) in [make_footer(1, 0), make_footer(0, 1), bad_magic]
                .into_iter()
                .enumerate()
            {
                let id = algorithm as u8;
                let encrypted = directory.path().join(format!("footer-{id}-{index}.enc"));
                let output = directory.path().join(format!("footer-{id}-{index}.out"));
                fs::write(
                    &encrypted,
                    authenticated_empty_stream(algorithm, &key, footer)?,
                )
                .map_err(|source| {
                    FileCryptError::io("write test ciphertext", &encrypted, source)
                })?;

                assert!(matches!(
                    decrypt_file(&encrypted, &output, &key),
                    Err(FileCryptError::AuthenticationFailed)
                ));
                assert!(!output.exists());
            }
        }
        Ok(())
    }

    #[test]
    fn empty_stream_rejects_all_noncanonical_end_headers() -> Result<()> {
        let directory = tempfile::tempdir()
            .map_err(|source| FileCryptError::io("create test directory", "<test>", source))?;
        let key = deterministic_key();

        for algorithm in [Algorithm::Aes256GcmSiv, Algorithm::XChaCha20Poly1305] {
            let valid = authenticated_empty_stream(algorithm, &key, make_footer(0, 0))?;
            let mut variants = Vec::new();

            for record_type in [0, RECORD_DATA, 3, 255] {
                let mut changed = valid.clone();
                changed[HEADER_SIZE] = record_type;
                variants.push(changed);
            }
            for relative_offset in 1..4 {
                let mut changed = valid.clone();
                changed[HEADER_SIZE + relative_offset] = 1;
                variants.push(changed);
            }
            for ciphertext_len in [0_u32, 1, 15, 39, 41, 1_048_576, u32::MAX] {
                let mut changed = valid.clone();
                changed[HEADER_SIZE + 4..HEADER_SIZE + 8]
                    .copy_from_slice(&ciphertext_len.to_le_bytes());
                variants.push(changed);
            }
            for sequence in [1_u64, MAX_DATA_RECORDS, u64::MAX] {
                let mut changed = valid.clone();
                changed[HEADER_SIZE + 8..HEADER_SIZE + 16].copy_from_slice(&sequence.to_le_bytes());
                variants.push(changed);
            }

            for (index, bytes) in variants.into_iter().enumerate() {
                let id = algorithm as u8;
                let encrypted = directory.path().join(format!("record-{id}-{index}.enc"));
                let output = directory.path().join(format!("record-{id}-{index}.out"));
                fs::write(&encrypted, bytes).map_err(|source| {
                    FileCryptError::io("write test ciphertext", &encrypted, source)
                })?;
                assert!(matches!(
                    decrypt_file(&encrypted, &output, &key),
                    Err(FileCryptError::AuthenticationFailed)
                ));
                assert!(!output.exists());
            }
        }
        Ok(())
    }

    struct InterruptOnce {
        interrupted: bool,
        byte: u8,
    }

    impl Read for InterruptOnce {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if !self.interrupted {
                self.interrupted = true;
                return Err(io::Error::new(io::ErrorKind::Interrupted, "test interrupt"));
            }
            if buffer.is_empty() {
                return Ok(0);
            }
            buffer[0] = self.byte;
            Ok(1)
        }
    }

    struct AlwaysError(io::ErrorKind);

    impl Read for AlwaysError {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(self.0, "injected read failure"))
        }
    }

    #[test]
    fn read_one_handles_eof_data_interrupts_and_errors() -> Result<()> {
        let path = Path::new("test-input");
        assert_eq!(read_one(&mut Cursor::new([]), path)?, None);
        assert_eq!(read_one(&mut Cursor::new([0xa5, 0x5a]), path)?, Some(0xa5));
        assert_eq!(
            read_one(
                &mut InterruptOnce {
                    interrupted: false,
                    byte: 0x7e,
                },
                path,
            )?,
            Some(0x7e)
        );
        assert!(matches!(
            read_one(&mut AlwaysError(io::ErrorKind::PermissionDenied), path),
            Err(FileCryptError::Io {
                action: "read input",
                path: error_path,
                ..
            }) if error_path == path
        ));
        Ok(())
    }

    #[test]
    fn integrity_reads_distinguish_truncation_from_io_failure() {
        let path = Path::new("encrypted-input");
        let mut buffer = [0_u8; 3];
        assert!(matches!(
            read_exact_integrity(&mut Cursor::new([1_u8, 2]), &mut buffer, path),
            Err(FileCryptError::AuthenticationFailed)
        ));
        assert!(matches!(
            read_exact_integrity(
                &mut AlwaysError(io::ErrorKind::PermissionDenied),
                &mut buffer,
                path,
            ),
            Err(FileCryptError::Io {
                action: "read encrypted input",
                path: error_path,
                ..
            }) if error_path == path
        ));
    }

    #[test]
    fn writer_detects_sources_shorter_or_longer_than_opening_length() -> Result<()> {
        let directory = tempfile::tempdir()
            .map_err(|source| FileCryptError::io("create test directory", "<test>", source))?;
        let key = deterministic_key();

        for (index, (plaintext, declared_len)) in [(&b"abc"[..], 4_u64), (&b"abcd"[..], 3_u64)]
            .into_iter()
            .enumerate()
        {
            let input_path = directory.path().join(format!("changed-{index}.plain"));
            let output_path = directory.path().join(format!("changed-{index}.enc"));
            fs::write(&input_path, plaintext)
                .map_err(|source| FileCryptError::io("write test input", &input_path, source))?;
            let mut input = File::open(&input_path)
                .map_err(|source| FileCryptError::io("open test input", &input_path, source))?;
            let mut output = File::create(&output_path)
                .map_err(|source| FileCryptError::io("create test output", &output_path, source))?;
            let header = deterministic_header(Algorithm::Aes256GcmSiv, declared_len);
            let encryptor = StreamEncryptor::new(&header, &key)?;

            assert!(matches!(
                encrypt_to_writer(
                    &mut input,
                    &mut output,
                    &input_path,
                    &output_path,
                    &header,
                    encryptor,
                ),
                Err(FileCryptError::InputChanged)
            ));
        }
        Ok(())
    }

    #[test]
    fn output_with_nondirectory_parent_is_invalid_not_an_io_error() -> Result<()> {
        let directory = tempfile::tempdir()
            .map_err(|source| FileCryptError::io("create test directory", "<test>", source))?;
        let parent_file = directory.path().join("regular-file");
        fs::write(&parent_file, b"not a directory")
            .map_err(|source| FileCryptError::io("write test parent", &parent_file, source))?;
        let output = parent_file.join("child");

        assert!(matches!(
            preflight_output(&output),
            Err(FileCryptError::InvalidOutputPath(path)) if path == output
        ));
        Ok(())
    }

    #[test]
    fn regular_input_open_reports_directories_as_nonregular() -> Result<()> {
        let directory = tempfile::tempdir()
            .map_err(|source| FileCryptError::io("create test directory", "<test>", source))?;
        assert!(matches!(
            open_regular_input(directory.path()),
            Err(FileCryptError::InputNotRegular(path)) if path == directory.path()
        ));
        Ok(())
    }

    #[cfg(unix)]
    fn assert_fifo_rejected_promptly(path: &Path) {
        let worker_path = path.to_path_buf();
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let rejected = matches!(
                open_regular_input(&worker_path),
                Err(FileCryptError::InputNotRegular(rejected_path))
                    if rejected_path == worker_path
            );
            let _ = sender.send(rejected);
        });

        assert_eq!(receiver.recv_timeout(Duration::from_secs(2)), Ok(true));
    }

    #[cfg(unix)]
    #[test]
    fn direct_and_symlinked_fifos_are_rejected_without_blocking() -> Result<()> {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir()
            .map_err(|source| FileCryptError::io("create test directory", "<test>", source))?;
        let fifo = directory.path().join("input.fifo");
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            &fifo,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )
        .map_err(|source| FileCryptError::io("create test FIFO", &fifo, io::Error::from(source)))?;
        let link = directory.path().join("input-link");
        symlink(&fifo, &link)
            .map_err(|source| FileCryptError::io("create test symlink", &link, source))?;

        assert_fifo_rejected_promptly(&fifo);
        assert_fifo_rejected_promptly(&link);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn accepted_regular_input_has_blocking_reads_restored() -> Result<()> {
        let directory = tempfile::tempdir()
            .map_err(|source| FileCryptError::io("create test directory", "<test>", source))?;
        let path = directory.path().join("regular");
        fs::write(&path, b"contents")
            .map_err(|source| FileCryptError::io("write test input", &path, source))?;
        let (file, length) = open_regular_input(&path)?;
        let flags = rustix::fs::fcntl_getfl(&file).map_err(|source| {
            FileCryptError::io("inspect test descriptor", &path, io::Error::from(source))
        })?;

        assert_eq!(length, 8);
        assert!(!flags.contains(rustix::fs::OFlags::NONBLOCK));
        Ok(())
    }

    #[test]
    fn final_publish_does_not_clobber_a_racing_destination() -> Result<()> {
        let directory = tempfile::tempdir()
            .map_err(|source| FileCryptError::io("create test directory", "<test>", source))?;
        let destination = directory.path().join("output.bin");
        fs::write(&destination, b"racing writer")
            .map_err(|source| FileCryptError::io("write test destination", &destination, source))?;

        let mut temporary = create_temporary(directory.path())?;
        let temporary_path = temporary.path().to_path_buf();
        temporary
            .as_file_mut()
            .write_all(b"filecrypt data")
            .map_err(|source| {
                FileCryptError::io("write test temporary", &temporary_path, source)
            })?;
        let result = commit_temporary(temporary, &destination);
        assert!(matches!(result, Err(FileCryptError::OutputExists(_))));
        let contents = fs::read(&destination)
            .map_err(|source| FileCryptError::io("read test destination", &destination, source))?;
        assert_eq!(contents, b"racing writer");
        Ok(())
    }
}
