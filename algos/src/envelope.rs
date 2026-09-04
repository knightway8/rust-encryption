use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;

use crate::crypto;
use crate::format::{CHUNK_SIZE, HEADER_LEN, Header, RECORD_HEADER_LEN, RecordHeader};
use crate::kdf::{file_mac_key, password_master, record_key, record_nonce};
use crate::{Error, Result, Suite};
use tempfile::NamedTempFile;

const AAD_DOMAIN: &[u8] = b"algos/envelope/v1/record";

pub(crate) fn encrypt_file(
    suite: Suite,
    input_path: &Path,
    output_path: &Path,
    password: &[u8],
) -> Result<()> {
    ensure_output_absent(output_path)?;
    let mut input = File::open(input_path)?;
    let metadata = input.metadata()?;
    if !metadata.is_file() {
        return Err(invalid_input("input is not a regular file"));
    }
    let plaintext_len = metadata.len();

    let mut salt = [0_u8; 16];
    let mut nonce_seed = [0_u8; 24];
    getrandom::fill(&mut salt).map_err(|_| Error::Crypto)?;
    getrandom::fill(&mut nonce_seed).map_err(|_| Error::Crypto)?;
    let master = password_master(password, &salt)?;

    let mut temporary = temporary_output(output_path)?;
    encrypt_stream(
        suite,
        &mut input,
        temporary.as_file_mut(),
        plaintext_len,
        &master,
        salt,
        nonce_seed,
    )?;
    temporary.as_file_mut().flush()?;
    temporary.as_file().sync_all()?;
    persist(temporary, output_path)
}

pub(crate) fn decrypt_file(
    suite: Suite,
    input_path: &Path,
    output_path: &Path,
    password: &[u8],
) -> Result<()> {
    ensure_output_absent(output_path)?;
    let mut input = File::open(input_path)?;
    let metadata = input.metadata()?;
    if !metadata.is_file() {
        return Err(invalid_input("input is not a regular file"));
    }

    let (header, header_bytes) = read_header(&mut input)?;
    ensure_suite(suite, header.suite)?;
    if header.expected_encrypted_len()? != metadata.len() {
        return Err(Error::InvalidFormat);
    }
    let master = password_master(password, &header.salt)?;

    let mut temporary = temporary_output(output_path)?;
    decrypt_records(
        &mut input,
        temporary.as_file_mut(),
        &header,
        &header_bytes,
        &master,
    )?;
    temporary.as_file_mut().flush()?;
    temporary.as_file().sync_all()?;
    persist(temporary, output_path)
}

fn encrypt_stream<R: Read, W: Write>(
    suite: Suite,
    reader: &mut R,
    writer: &mut W,
    plaintext_len: u64,
    master: &[u8; 32],
    salt: [u8; 16],
    nonce_seed: [u8; 24],
) -> Result<()> {
    let header = Header::new(suite, plaintext_len, salt, nonce_seed);
    header.expected_encrypted_len()?;
    let header_bytes = header.encode();
    writer.write_all(&header_bytes)?;

    let mac_key = if suite.is_native_aead() {
        None
    } else {
        Some(file_mac_key(master, suite)?)
    };

    let mut remaining = plaintext_len;
    let mut index = 0_u64;
    while remaining > 0 {
        let length = remaining.min(u64::from(CHUNK_SIZE));
        let length_usize = usize::try_from(length).map_err(|_| Error::FileTooLarge)?;
        let mut buffer = vec![0_u8; length_usize];
        read_plaintext_exact(reader, &mut buffer)?;

        let record = RecordHeader::data(
            index,
            u32::try_from(length).map_err(|_| Error::FileTooLarge)?,
        );
        write_sealed_record(
            writer,
            &header,
            &header_bytes,
            record,
            master,
            mac_key.as_deref(),
            &mut buffer,
        )?;
        remaining -= length;
        index = index.checked_add(1).ok_or(Error::FileTooLarge)?;
    }

    if index != header.data_record_count() {
        return Err(Error::InputChanged);
    }
    let mut empty = [];
    write_sealed_record(
        writer,
        &header,
        &header_bytes,
        RecordHeader::final_record(index),
        master,
        mac_key.as_deref(),
        &mut empty,
    )?;

    let mut extra = [0_u8; 1];
    if reader.read(&mut extra)? != 0 {
        return Err(Error::InputChanged);
    }
    Ok(())
}

fn write_sealed_record<W: Write>(
    writer: &mut W,
    header: &Header,
    header_bytes: &[u8; HEADER_LEN],
    record: RecordHeader,
    master: &[u8; 32],
    mac_key: Option<&[u8; 32]>,
    data: &mut [u8],
) -> Result<()> {
    let record_bytes = record.encode();
    let aad = record_aad(header_bytes, &record_bytes);
    let nonce = record_nonce(&header.nonce_seed, header.suite.nonce_len(), record.index)?;
    let key = record_key(master, header.suite, record.index)?;
    let tag = crypto::seal(header.suite, key.as_slice(), mac_key, &nonce, &aad, data)?;
    if tag.len() != header.suite.tag_len() {
        return Err(Error::Crypto);
    }
    writer.write_all(&record_bytes)?;
    writer.write_all(data)?;
    writer.write_all(&tag)?;
    Ok(())
}

fn read_header<R: Read>(reader: &mut R) -> Result<(Header, [u8; HEADER_LEN])> {
    let mut bytes = [0_u8; HEADER_LEN];
    reader
        .read_exact(&mut bytes)
        .map_err(|_| Error::InvalidFormat)?;
    let header = Header::decode(&bytes)?;
    Ok((header, bytes))
}

fn decrypt_records<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    header: &Header,
    header_bytes: &[u8; HEADER_LEN],
    master: &[u8; 32],
) -> Result<()> {
    let mac_key = if header.suite.is_native_aead() {
        None
    } else {
        Some(file_mac_key(master, header.suite)?)
    };
    let mut remaining = header.plaintext_len;

    for index in 0..header.data_record_count() {
        let expected_len = remaining.min(u64::from(CHUNK_SIZE));
        let (record, record_bytes) = read_record_header_authenticated(reader)?;
        if record.index != index
            || record.is_final()
            || u64::from(record.plaintext_len) != expected_len
        {
            return Err(Error::Authentication);
        }
        let mut ciphertext =
            vec![0_u8; usize::try_from(expected_len).map_err(|_| Error::FileTooLarge)?];
        read_authenticated_exact(reader, &mut ciphertext)?;
        let mut tag = vec![0_u8; header.suite.tag_len()];
        read_authenticated_exact(reader, &mut tag)?;
        open_record(
            header,
            header_bytes,
            &record_bytes,
            record,
            master,
            mac_key.as_deref(),
            &mut ciphertext,
            &tag,
        )?;
        writer.write_all(&ciphertext)?;
        remaining -= expected_len;
    }

    let (final_record, final_bytes) = read_record_header_authenticated(reader)?;
    if final_record != RecordHeader::final_record(header.data_record_count()) || remaining != 0 {
        return Err(Error::Authentication);
    }
    let mut tag = vec![0_u8; header.suite.tag_len()];
    read_authenticated_exact(reader, &mut tag)?;
    open_record(
        header,
        header_bytes,
        &final_bytes,
        final_record,
        master,
        mac_key.as_deref(),
        &mut [],
        &tag,
    )?;

    let mut extra = [0_u8; 1];
    if reader.read(&mut extra)? != 0 {
        return Err(Error::Authentication);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn open_record(
    header: &Header,
    header_bytes: &[u8; HEADER_LEN],
    record_bytes: &[u8; RECORD_HEADER_LEN],
    record: RecordHeader,
    master: &[u8; 32],
    mac_key: Option<&[u8; 32]>,
    ciphertext: &mut [u8],
    tag: &[u8],
) -> Result<()> {
    let aad = record_aad(header_bytes, record_bytes);
    let nonce = record_nonce(&header.nonce_seed, header.suite.nonce_len(), record.index)?;
    let key = record_key(master, header.suite, record.index)?;
    crypto::open(
        header.suite,
        key.as_slice(),
        mac_key,
        &nonce,
        &aad,
        ciphertext,
        tag,
    )
}

fn record_aad(header: &[u8; HEADER_LEN], record: &[u8; RECORD_HEADER_LEN]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_DOMAIN.len() + HEADER_LEN + RECORD_HEADER_LEN);
    aad.extend_from_slice(AAD_DOMAIN);
    aad.extend_from_slice(header);
    aad.extend_from_slice(record);
    aad
}

fn read_record_header_authenticated<R: Read>(
    reader: &mut R,
) -> Result<(RecordHeader, [u8; RECORD_HEADER_LEN])> {
    let mut bytes = [0_u8; RECORD_HEADER_LEN];
    read_authenticated_exact(reader, &mut bytes)?;
    let record = RecordHeader::decode(&bytes).map_err(|_| Error::Authentication)?;
    Ok((record, bytes))
}

fn read_authenticated_exact<R: Read>(reader: &mut R, buffer: &mut [u8]) -> Result<()> {
    reader.read_exact(buffer).map_err(|_| Error::Authentication)
}

fn read_plaintext_exact<R: Read>(reader: &mut R, buffer: &mut [u8]) -> Result<()> {
    reader.read_exact(buffer).map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            Error::InputChanged
        } else {
            Error::Io(error)
        }
    })
}

fn ensure_suite(expected: Suite, found: Suite) -> Result<()> {
    if expected == found {
        Ok(())
    } else {
        Err(Error::SuiteMismatch {
            expected: expected.name(),
            found: found.name(),
        })
    }
}

fn ensure_output_absent(output: &Path) -> Result<()> {
    if output.symlink_metadata().is_ok() {
        return Err(Error::OutputExists(display_path(output)));
    }
    Ok(())
}

fn temporary_output(output: &Path) -> Result<NamedTempFile> {
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    Ok(NamedTempFile::new_in(parent)?)
}

fn persist(temporary: NamedTempFile, output: &Path) -> Result<()> {
    match temporary.persist_noclobber(output) {
        Ok(_) => Ok(()),
        Err(error) => {
            let kind = error.error.kind();
            drop(error.file);
            if kind == io::ErrorKind::AlreadyExists {
                Err(Error::OutputExists(display_path(output)))
            } else {
                Err(Error::Io(error.error))
            }
        }
    }
}

fn display_path(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn invalid_input(message: &'static str) -> Error {
    Error::Io(io::Error::new(io::ErrorKind::InvalidInput, message))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::ALL_SUITES;

    const MASTER: [u8; 32] = [0x42; 32];
    const SALT: [u8; 16] = [0x17; 16];
    const SEED: [u8; 24] = [0xA9; 24];

    fn seal_bytes(suite: Suite, plaintext: &[u8]) -> Vec<u8> {
        let mut reader = Cursor::new(plaintext);
        let mut encrypted = Vec::new();
        encrypt_stream(
            suite,
            &mut reader,
            &mut encrypted,
            plaintext.len() as u64,
            &MASTER,
            SALT,
            SEED,
        )
        .unwrap();
        encrypted
    }

    fn open_bytes_with_master(
        expected: Suite,
        encrypted: &[u8],
        master: &[u8; 32],
    ) -> Result<Vec<u8>> {
        let mut reader = Cursor::new(encrypted);
        let (header, header_bytes) = read_header(&mut reader)?;
        ensure_suite(expected, header.suite)?;
        if header.expected_encrypted_len()? != encrypted.len() as u64 {
            return Err(Error::InvalidFormat);
        }
        let mut plaintext = Vec::new();
        decrypt_records(&mut reader, &mut plaintext, &header, &header_bytes, master)?;
        Ok(plaintext)
    }

    fn patterned(length: usize) -> Vec<u8> {
        (0..length)
            .map(|index| u8::try_from(index % 251).expect("modulo 251 fits in u8"))
            .collect()
    }

    #[test]
    fn every_suite_round_trips_all_boundaries() {
        let chunk = CHUNK_SIZE as usize;
        let lengths = [
            0,
            1,
            15,
            16,
            17,
            255,
            chunk - 1,
            chunk,
            chunk + 1,
            2 * chunk - 1,
            2 * chunk,
            2 * chunk + 1,
        ];
        for suite in ALL_SUITES {
            for length in lengths {
                let plaintext = patterned(length);
                let encrypted = seal_bytes(suite, &plaintext);
                let opened = open_bytes_with_master(suite, &encrypted, &MASTER)
                    .unwrap_or_else(|error| panic!("{} at {length}: {error}", suite.name()));
                assert_eq!(opened, plaintext, "{} at {length}", suite.name());
            }
        }
    }

    #[test]
    fn every_suite_rejects_wrong_master_and_corruption() {
        for suite in ALL_SUITES {
            let encrypted = seal_bytes(suite, b"integrity matters");
            assert!(open_bytes_with_master(suite, &encrypted, &[0x99; 32]).is_err());

            let mut changed = encrypted.clone();
            let offset = changed.len() - suite.tag_len();
            changed[offset] ^= 1;
            assert!(open_bytes_with_master(suite, &changed, &MASTER).is_err());
        }
    }

    #[test]
    fn every_suite_rejects_a_flip_in_every_container_byte() {
        for suite in ALL_SUITES {
            let encrypted = seal_bytes(suite, b"bytewise integrity");
            for offset in 0..encrypted.len() {
                let mut changed = encrypted.clone();
                changed[offset] ^= 1;
                assert!(
                    open_bytes_with_master(suite, &changed, &MASTER).is_err(),
                    "{} accepted corruption at offset {offset}",
                    suite.name()
                );
            }
        }
    }

    #[test]
    fn every_header_byte_is_either_rejected_or_authenticated() {
        let encrypted = seal_bytes(Suite::Aes256Gcm, b"header coverage");
        for offset in 0..HEADER_LEN {
            let mut changed = encrypted.clone();
            changed[offset] ^= 1;
            assert!(
                open_bytes_with_master(Suite::Aes256Gcm, &changed, &MASTER).is_err(),
                "header offset {offset}"
            );
        }
    }

    #[test]
    fn truncation_and_appended_data_are_always_rejected() {
        for suite in [Suite::Aes256Gcm, Suite::Serpent256CtrHmac] {
            let encrypted = seal_bytes(suite, b"small truncation fixture");
            for length in 0..encrypted.len() {
                assert!(open_bytes_with_master(suite, &encrypted[..length], &MASTER).is_err());
            }
            let mut appended = encrypted.clone();
            appended.push(0);
            assert!(open_bytes_with_master(suite, &appended, &MASTER).is_err());
        }
    }

    #[test]
    fn record_reordering_and_splicing_are_rejected() {
        let suite = Suite::XChaCha20Poly1305;
        let plaintext = patterned(CHUNK_SIZE as usize + 23);
        let first = seal_bytes(suite, &plaintext);
        let mut other_plaintext = plaintext.clone();
        other_plaintext[0] ^= 1;
        let mut other_reader = Cursor::new(&other_plaintext);
        let mut second = Vec::new();
        encrypt_stream(
            suite,
            &mut other_reader,
            &mut second,
            other_plaintext.len() as u64,
            &MASTER,
            [0x33; 16],
            [0x55; 24],
        )
        .unwrap();

        let first_record_len = RECORD_HEADER_LEN + CHUNK_SIZE as usize + suite.tag_len();
        let second_record_start = HEADER_LEN + first_record_len;

        let mut reordered = first.clone();
        let left = reordered[HEADER_LEN..second_record_start].to_vec();
        let second_len = RECORD_HEADER_LEN + 23 + suite.tag_len();
        let right = reordered[second_record_start..second_record_start + second_len].to_vec();
        reordered[HEADER_LEN..HEADER_LEN + second_len].copy_from_slice(&right);
        reordered[HEADER_LEN + second_len..HEADER_LEN + second_len + first_record_len]
            .copy_from_slice(&left);
        assert!(open_bytes_with_master(suite, &reordered, &MASTER).is_err());

        let mut spliced = first;
        spliced[HEADER_LEN..second_record_start]
            .copy_from_slice(&second[HEADER_LEN..second_record_start]);
        assert!(open_bytes_with_master(suite, &spliced, &MASTER).is_err());
    }

    #[test]
    fn identical_inputs_with_fresh_header_material_differ() {
        let suite = Suite::Aes256GcmSiv;
        let plaintext = b"same input";
        let first = seal_bytes(suite, plaintext);
        let mut reader = Cursor::new(plaintext);
        let mut second = Vec::new();
        encrypt_stream(
            suite,
            &mut reader,
            &mut second,
            plaintext.len() as u64,
            &MASTER,
            [8; 16],
            [7; 24],
        )
        .unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn encryption_detects_input_growth_and_shrinkage() {
        let suite = Suite::Aes128Gcm;
        let mut short_reader = Cursor::new(b"short");
        let mut output = Vec::new();
        assert!(matches!(
            encrypt_stream(
                suite,
                &mut short_reader,
                &mut output,
                6,
                &MASTER,
                SALT,
                SEED,
            ),
            Err(Error::InputChanged)
        ));

        let mut long_reader = Cursor::new(b"longer");
        let mut output = Vec::new();
        assert!(matches!(
            encrypt_stream(suite, &mut long_reader, &mut output, 5, &MASTER, SALT, SEED,),
            Err(Error::InputChanged)
        ));
    }

    #[test]
    fn each_binary_rejects_another_suite() {
        for (index, suite) in ALL_SUITES.iter().copied().enumerate() {
            let encrypted = seal_bytes(suite, b"suite binding");
            let other = ALL_SUITES[(index + 1) % ALL_SUITES.len()];
            assert!(matches!(
                open_bytes_with_master(other, &encrypted, &MASTER),
                Err(Error::SuiteMismatch { .. })
            ));
        }
    }

    proptest::proptest! {
        #![proptest_config(proptest::test_runner::Config::with_cases(64))]

        #[test]
        fn arbitrary_binary_payloads_round_trip(
            suite_id in 1_u16..=30,
            plaintext in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..150_000),
        ) {
            let suite = Suite::from_id(suite_id).unwrap();
            let encrypted = seal_bytes(suite, &plaintext);
            let opened = open_bytes_with_master(suite, &encrypted, &MASTER).unwrap();
            proptest::prop_assert_eq!(opened, plaintext);
        }
    }
}
