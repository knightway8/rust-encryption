//! XChaCha20-Poly1305 file encryption.
//!
//! This module deliberately contains the complete suite adapter: per-file key
//! derivation, input validation, detached-tag encryption, and authenticated
//! decryption. Keeping that boundary small makes the construction easier to
//! review independently from the container format and CLI.

use chacha20poly1305::{
    Tag, XChaCha20Poly1305, XNonce,
    aead::{AeadInOut, KeyInit},
};
use hkdf::Hkdf;
use sha2::Sha512;
use zeroize::Zeroizing;

use super::SALT_LEN;
use crate::error::AppError;

/// XChaCha20-Poly1305's 192-bit nonce size.
pub(crate) const NONCE_LEN: usize = 24;
/// Poly1305's 128-bit authentication tag size.
pub(crate) const TAG_LEN: usize = 16;

const MASTER_KEY_LEN: usize = 32;
const FILE_KEY_LEN: usize = 32;

// Versioned and suite-specific so the same master key and salt cannot derive
// the same working key for another construction or format version.
const HKDF_INFO: &[u8] = b"cascade:file:v1:xchacha20-poly1305:encryption-key";

/// Encrypt `plaintext`, authenticating the complete serialized `header`.
pub(crate) fn seal(
    master_key: &[u8],
    salt: &[u8; SALT_LEN],
    nonce: &[u8],
    header: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), AppError> {
    if master_key.len() != MASTER_KEY_LEN || nonce.len() != NONCE_LEN {
        return Err(AppError::EncryptionFailed);
    }

    let nonce = XNonce::try_from(nonce).map_err(|_| AppError::EncryptionFailed)?;
    let file_key = derive_file_key(master_key, salt).map_err(|_| AppError::EncryptionFailed)?;
    let cipher = XChaCha20Poly1305::new_from_slice(file_key.as_ref())
        .map_err(|_| AppError::EncryptionFailed)?;

    // Keep the plaintext working copy zeroizing until authenticated
    // encryption succeeds. This protects error and unwind paths where an AEAD
    // implementation might have only partially modified the buffer.
    let mut ciphertext = Zeroizing::new(Vec::new());
    ciphertext
        .try_reserve_exact(plaintext.len())
        .map_err(|_| AppError::EncryptionFailed)?;
    ciphertext.extend_from_slice(plaintext);

    let tag = cipher
        .encrypt_inout_detached(&nonce, header, ciphertext.as_mut_slice().into())
        .map_err(|_| AppError::EncryptionFailed)?;

    let mut detached_tag = Vec::new();
    detached_tag
        .try_reserve_exact(TAG_LEN)
        .map_err(|_| AppError::EncryptionFailed)?;
    detached_tag.extend_from_slice(&tag);

    Ok((std::mem::take(&mut *ciphertext), detached_tag))
}

/// Authenticate and decrypt `ciphertext` using the complete serialized header.
pub(crate) fn open(
    master_key: &[u8],
    salt: &[u8; SALT_LEN],
    nonce: &[u8],
    header: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Zeroizing<Vec<u8>>, AppError> {
    if master_key.len() != MASTER_KEY_LEN || nonce.len() != NONCE_LEN || tag.len() != TAG_LEN {
        return Err(AppError::DecryptionFailed);
    }

    let nonce = XNonce::try_from(nonce).map_err(|_| AppError::DecryptionFailed)?;
    let tag = Tag::try_from(tag).map_err(|_| AppError::DecryptionFailed)?;
    let file_key = derive_file_key(master_key, salt).map_err(|_| AppError::DecryptionFailed)?;
    let cipher = XChaCha20Poly1305::new_from_slice(file_key.as_ref())
        .map_err(|_| AppError::DecryptionFailed)?;

    // The buffer is zeroized on every exit path, including authentication
    // failure after an implementation has partially modified it.
    let mut plaintext = Zeroizing::new(Vec::new());
    plaintext
        .try_reserve_exact(ciphertext.len())
        .map_err(|_| AppError::DecryptionFailed)?;
    plaintext.extend_from_slice(ciphertext);

    cipher
        .decrypt_inout_detached(&nonce, header, plaintext.as_mut_slice().into(), &tag)
        .map_err(|_| AppError::DecryptionFailed)?;

    Ok(plaintext)
}

fn derive_file_key(
    master_key: &[u8],
    salt: &[u8; SALT_LEN],
) -> Result<Zeroizing<[u8; FILE_KEY_LEN]>, ()> {
    if master_key.len() != MASTER_KEY_LEN {
        return Err(());
    }

    let (prk, hkdf) = Hkdf::<Sha512>::extract(Some(salt), master_key);
    let _prk = Zeroizing::new(prk);
    let mut file_key = Zeroizing::new([0_u8; FILE_KEY_LEN]);
    hkdf.expand(HKDF_INFO, file_key.as_mut_slice())
        .map_err(|_| ())?;
    Ok(file_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; MASTER_KEY_LEN] = [0x5a; MASTER_KEY_LEN];
    const WRONG_KEY: [u8; MASTER_KEY_LEN] = [0x5b; MASTER_KEY_LEN];
    const SALT: [u8; SALT_LEN] = [0xa5; SALT_LEN];
    const NONCE: [u8; NONCE_LEN] = [0x19; NONCE_LEN];
    const HEADER: &[u8] = b"full container header\0with binary\xff";

    fn assert_encryption_failed(result: Result<(Vec<u8>, Vec<u8>), AppError>) {
        assert!(matches!(result, Err(AppError::EncryptionFailed)));
    }

    fn assert_decryption_failed(result: Result<Zeroizing<Vec<u8>>, AppError>) {
        assert!(matches!(result, Err(AppError::DecryptionFailed)));
    }

    #[test]
    fn round_trips_boundary_lengths() {
        for len in [0, 1, 15, 16, 17, 23, 24, 25, 31, 32, 33, 255, 256, 1024] {
            let plaintext: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(53)).collect();
            let (ciphertext, tag) = seal(&KEY, &SALT, &NONCE, HEADER, &plaintext).unwrap();

            assert_eq!(ciphertext.len(), plaintext.len(), "length {len}");
            assert_eq!(tag.len(), TAG_LEN, "length {len}");
            assert_eq!(
                open(&KEY, &SALT, &NONCE, HEADER, &ciphertext, &tag)
                    .unwrap()
                    .as_slice(),
                plaintext,
                "length {len}"
            );
        }
    }

    #[test]
    fn empty_and_binary_headers_are_authenticated() {
        let plaintext = b"authenticated payload";
        for header in [&b""[..], &b"\0\xff\x80header\0"[..]] {
            let (ciphertext, tag) = seal(&KEY, &SALT, &NONCE, header, plaintext).unwrap();
            assert_eq!(
                open(&KEY, &SALT, &NONCE, header, &ciphertext, &tag)
                    .unwrap()
                    .as_slice(),
                plaintext
            );
        }
    }

    #[test]
    fn wrong_key_and_salt_fail_authentication() {
        let (ciphertext, tag) = seal(&KEY, &SALT, &NONCE, HEADER, b"secret").unwrap();

        assert_decryption_failed(open(&WRONG_KEY, &SALT, &NONCE, HEADER, &ciphertext, &tag));

        let mut wrong_salt = SALT;
        wrong_salt[0] ^= 1;
        assert_decryption_failed(open(&KEY, &wrong_salt, &NONCE, HEADER, &ciphertext, &tag));
    }

    #[test]
    fn header_ciphertext_and_tag_tampering_fail_authentication() {
        let (ciphertext, tag) = seal(&KEY, &SALT, &NONCE, HEADER, b"nonempty secret").unwrap();

        let mut changed_header = HEADER.to_vec();
        changed_header[0] ^= 0x80;
        assert_decryption_failed(open(
            &KEY,
            &SALT,
            &NONCE,
            &changed_header,
            &ciphertext,
            &tag,
        ));

        let mut changed_ciphertext = ciphertext.clone();
        changed_ciphertext[0] ^= 0x80;
        assert_decryption_failed(open(&KEY, &SALT, &NONCE, HEADER, &changed_ciphertext, &tag));

        let mut changed_tag = tag.clone();
        changed_tag[TAG_LEN - 1] ^= 0x80;
        assert_decryption_failed(open(&KEY, &SALT, &NONCE, HEADER, &ciphertext, &changed_tag));
    }

    #[test]
    fn fixed_material_is_deterministic_and_domain_separated() {
        let plaintext = b"fixed XChaCha20-Poly1305 material";
        let first = seal(&KEY, &SALT, &NONCE, HEADER, plaintext).unwrap();
        let second = seal(&KEY, &SALT, &NONCE, HEADER, plaintext).unwrap();
        assert_eq!(first, second);
        assert_eq!(
            first.0,
            [
                0xea, 0x4d, 0x9b, 0xb4, 0x04, 0x8a, 0xd1, 0x9c, 0xf4, 0xaf, 0xfc, 0x4d, 0x46, 0xf9,
                0x77, 0xdf, 0xb3, 0x35, 0x15, 0xf7, 0x84, 0x36, 0x93, 0x8b, 0xd0, 0x15, 0x9d, 0x95,
                0x8b, 0x24, 0xd5, 0xfe, 0xa3,
            ]
        );
        assert_eq!(
            first.1,
            [
                0x8a, 0xfd, 0x6d, 0x3f, 0x50, 0x8b, 0x83, 0x8b, 0x61, 0x02, 0x52, 0xa8, 0x67, 0x5d,
                0x0b, 0x37,
            ]
        );

        let mut other_salt = SALT;
        other_salt[31] ^= 1;
        let other = seal(&KEY, &other_salt, &NONCE, HEADER, plaintext).unwrap();
        assert_ne!(first, other);

        let derived = derive_file_key(&KEY, &SALT).unwrap();
        assert_ne!(derived.as_slice(), KEY);
    }

    #[test]
    fn invalid_key_and_nonce_lengths_are_rejected_without_panics() {
        for key in [&KEY[..0], &KEY[..31], &[0_u8; MASTER_KEY_LEN + 1]] {
            assert_encryption_failed(seal(key, &SALT, &NONCE, HEADER, b"data"));
            assert_decryption_failed(open(
                key,
                &SALT,
                &NONCE,
                HEADER,
                b"ciphertext",
                &[0_u8; TAG_LEN],
            ));
        }

        for nonce in [&NONCE[..0], &NONCE[..NONCE_LEN - 1], &[0_u8; NONCE_LEN + 1]] {
            assert_encryption_failed(seal(&KEY, &SALT, nonce, HEADER, b"data"));
            assert_decryption_failed(open(
                &KEY,
                &SALT,
                nonce,
                HEADER,
                b"ciphertext",
                &[0_u8; TAG_LEN],
            ));
        }
    }

    #[test]
    fn invalid_tag_lengths_are_rejected_without_panics() {
        for tag in [&[][..], &[0_u8; TAG_LEN - 1], &[0_u8; TAG_LEN + 1]] {
            assert_decryption_failed(open(&KEY, &SALT, &NONCE, HEADER, b"ciphertext", tag));
        }
    }
}
