use crate::error::{EzError, FormatError};
use crate::format::{CHUNK_SIZE, HEADER_LEN, Header, KdfParams, chunk_aad, final_aad, header_aad};
use argon2::{Algorithm, Argon2, Block, Params, Version};
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{Key, Tag, XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};
use std::io::{self, Read, Write};
use std::path::Path;
use zeroize::Zeroizing;

pub(crate) const MAX_PASSWORD_BYTES: usize = 1024 * 1024;

pub(crate) fn validate_password(password: &[u8]) -> Result<(), EzError> {
    if password.is_empty() {
        return Err(EzError::InvalidPassword("password must not be empty"));
    }
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(EzError::InvalidPassword("password is too long"));
    }
    Ok(())
}

pub(crate) fn random_material() -> Result<([u8; 16], [u8; 16]), EzError> {
    let mut salt = [0u8; 16];
    let mut nonce_prefix = [0u8; 16];
    OsRng
        .try_fill_bytes(&mut salt)
        .map_err(|_| EzError::Randomness)?;
    OsRng
        .try_fill_bytes(&mut nonce_prefix)
        .map_err(|_| EzError::Randomness)?;
    if salt.iter().all(|byte| *byte == 0) || nonce_prefix.iter().all(|byte| *byte == 0) {
        return Err(EzError::Randomness);
    }
    Ok((salt, nonce_prefix))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn encrypt_stream<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    plaintext_len: u64,
    password: &[u8],
    kdf: KdfParams,
    salt: [u8; 16],
    nonce_prefix: [u8; 16],
    input_path: &Path,
    output_path: &Path,
) -> Result<u64, EzError> {
    validate_password(password)?;
    let header = Header::new(plaintext_len, kdf, salt, nonce_prefix)?;
    let header_bytes = header.encode();
    let cipher = derive_cipher(password, &header)?;

    write_all(writer, &header_bytes, output_path)?;
    let header_tag =
        authenticate_empty(&cipher, &header.nonce(u64::MAX), &header_aad(&header_bytes))?;
    write_all(writer, header_tag.as_slice(), output_path)?;

    let chunks = header.chunk_count()?;
    let mut buffer = Zeroizing::new(vec![0u8; CHUNK_SIZE as usize]);
    for index in 0..chunks {
        let plaintext_chunk_len = header.chunk_plaintext_len(index)?;
        read_exact_source(reader, &mut buffer[..plaintext_chunk_len], input_path)?;
        let nonce_bytes = header.nonce(index);
        let aad = chunk_aad(&header_bytes, index, plaintext_chunk_len);
        let tag = cipher
            .encrypt_in_place_detached(
                XNonce::from_slice(&nonce_bytes),
                &aad,
                &mut buffer[..plaintext_chunk_len],
            )
            .map_err(|_| EzError::AuthenticationFailed)?;
        write_all(writer, &buffer[..plaintext_chunk_len], output_path)?;
        write_all(writer, tag.as_slice(), output_path)?;
    }

    let mut probe = [0u8; 1];
    match read_retry(reader, &mut probe) {
        Ok(0) => {}
        Ok(_) => return Err(EzError::InputChanged(input_path.to_path_buf())),
        Err(source) => return Err(EzError::io("finish reading", input_path, source)),
    }

    let final_tag = authenticate_empty(
        &cipher,
        &header.nonce(chunks),
        &final_aad(&header_bytes, chunks),
    )?;
    write_all(writer, final_tag.as_slice(), output_path)?;
    Ok(header.encoded_len()?)
}

pub(crate) fn decrypt_stream<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    encrypted_len: u64,
    password: &[u8],
    input_path: &Path,
    output_path: &Path,
) -> Result<u64, EzError> {
    validate_password(password)?;
    let mut header_bytes = [0u8; HEADER_LEN];
    read_exact_format(reader, &mut header_bytes, input_path, true)?;
    let header = Header::decode(&header_bytes)?;
    if header.encoded_len()? != encrypted_len {
        return Err(FormatError::LengthMismatch.into());
    }

    let cipher = derive_cipher(password, &header)?;
    let mut header_tag = [0u8; 16];
    read_exact_format(reader, &mut header_tag, input_path, false)?;
    verify_empty(
        &cipher,
        &header.nonce(u64::MAX),
        &header_aad(&header_bytes),
        &header_tag,
    )?;

    let chunks = header.chunk_count()?;
    let mut buffer = Zeroizing::new(vec![0u8; CHUNK_SIZE as usize]);
    for index in 0..chunks {
        let plaintext_chunk_len = header.chunk_plaintext_len(index)?;
        read_exact_format(
            reader,
            &mut buffer[..plaintext_chunk_len],
            input_path,
            false,
        )?;
        let mut tag_bytes = [0u8; 16];
        read_exact_format(reader, &mut tag_bytes, input_path, false)?;
        let nonce_bytes = header.nonce(index);
        let aad = chunk_aad(&header_bytes, index, plaintext_chunk_len);
        cipher
            .decrypt_in_place_detached(
                XNonce::from_slice(&nonce_bytes),
                &aad,
                &mut buffer[..plaintext_chunk_len],
                Tag::from_slice(&tag_bytes),
            )
            .map_err(|_| EzError::AuthenticationFailed)?;
        write_all(writer, &buffer[..plaintext_chunk_len], output_path)?;
    }

    let mut final_tag = [0u8; 16];
    read_exact_format(reader, &mut final_tag, input_path, false)?;
    verify_empty(
        &cipher,
        &header.nonce(chunks),
        &final_aad(&header_bytes, chunks),
        &final_tag,
    )?;

    let mut probe = [0u8; 1];
    match read_retry(reader, &mut probe) {
        Ok(0) => {}
        Ok(_) => return Err(FormatError::LengthMismatch.into()),
        Err(source) => return Err(EzError::io("finish reading", input_path, source)),
    }
    Ok(header.plaintext_len)
}

fn derive_cipher(password: &[u8], header: &Header) -> Result<XChaCha20Poly1305, EzError> {
    let params = Params::new(
        header.kdf.memory_kib,
        header.kdf.time_cost,
        header.kdf.lanes,
        Some(32),
    )
    .map_err(|_| EzError::Kdf)?;
    let block_count = params.block_count();
    let mut memory = Zeroizing::new(Vec::<Block>::new());
    memory
        .try_reserve_exact(block_count)
        .map_err(|_| EzError::Kdf)?;
    memory.resize(block_count, Block::default());

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into_with_memory(password, &header.salt, &mut *key, &mut memory)
        .map_err(|_| EzError::Kdf)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&*key));
    // Both the derived key and Argon2's password-derived working memory are
    // zeroized on every return path by their guards.
    Ok(cipher)
}

fn authenticate_empty(
    cipher: &XChaCha20Poly1305,
    nonce: &[u8; 24],
    aad: &[u8],
) -> Result<Tag, EzError> {
    cipher
        .encrypt_in_place_detached(XNonce::from_slice(nonce), aad, &mut [])
        .map_err(|_| EzError::AuthenticationFailed)
}

fn verify_empty(
    cipher: &XChaCha20Poly1305,
    nonce: &[u8; 24],
    aad: &[u8],
    tag: &[u8; 16],
) -> Result<(), EzError> {
    cipher
        .decrypt_in_place_detached(
            XNonce::from_slice(nonce),
            aad,
            &mut [],
            Tag::from_slice(tag),
        )
        .map_err(|_| EzError::AuthenticationFailed)
}

fn read_exact_source<R: Read>(
    reader: &mut R,
    bytes: &mut [u8],
    path: &Path,
) -> Result<(), EzError> {
    match reader.read_exact(bytes) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
            Err(EzError::InputChanged(path.to_path_buf()))
        }
        Err(source) => Err(EzError::io("read", path, source)),
    }
}

fn read_exact_format<R: Read>(
    reader: &mut R,
    bytes: &mut [u8],
    path: &Path,
    is_header: bool,
) -> Result<(), EzError> {
    match reader.read_exact(bytes) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
            if is_header {
                Err(FormatError::TruncatedHeader.into())
            } else {
                Err(FormatError::LengthMismatch.into())
            }
        }
        Err(source) => Err(EzError::io("read", path, source)),
    }
}

fn write_all<W: Write>(writer: &mut W, bytes: &[u8], path: &Path) -> Result<(), EzError> {
    writer
        .write_all(bytes)
        .map_err(|source| EzError::io("write temporary output", path, source))
}

fn read_retry<R: Read>(reader: &mut R, bytes: &mut [u8]) -> io::Result<usize> {
    loop {
        match reader.read(bytes) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => return result,
        }
    }
}
