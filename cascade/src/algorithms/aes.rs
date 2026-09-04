//! AES-256-GCM-SIV file encryption.
//!
//! This module deliberately contains the complete suite adapter: per-file key
//! derivation, input validation, detached-tag encryption, and authenticated
//! decryption. Keeping that boundary small makes the construction easier to
//! review independently from the container format and CLI.

use aes_gcm_siv::{
    Aes256GcmSiv, Nonce, Tag,
    aead::{AeadInOut, KeyInit},
};
use hkdf::Hkdf;
use sha2::Sha512;
use zeroize::Zeroizing;

use super::SALT_LEN;
use crate::error::AppError;

/// AES-GCM-SIV's 96-bit nonce size.
pub(crate) const NONCE_LEN: usize = 12;
/// AES-GCM-SIV's 128-bit authentication tag size.
pub(crate) const TAG_LEN: usize = 16;

const MASTER_KEY_LEN: usize = 32;
const FILE_KEY_LEN: usize = 32;

// Versioned and suite-specific so the same master key and salt cannot derive
// the same working key for another construction or format version.
const HKDF_INFO: &[u8] = b"cascade:file:v1:aes-256-gcm-siv:encryption-key";

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

    let nonce = Nonce::try_from(nonce).map_err(|_| AppError::EncryptionFailed)?;
    let file_key = derive_file_key(master_key, salt).map_err(|_| AppError::EncryptionFailed)?;
    let cipher =
        Aes256GcmSiv::new_from_slice(file_key.as_ref()).map_err(|_| AppError::EncryptionFailed)?;

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

    let nonce = Nonce::try_from(nonce).map_err(|_| AppError::DecryptionFailed)?;
    let tag = Tag::try_from(tag).map_err(|_| AppError::DecryptionFailed)?;
    let file_key = derive_file_key(master_key, salt).map_err(|_| AppError::DecryptionFailed)?;
    let cipher =
        Aes256GcmSiv::new_from_slice(file_key.as_ref()).map_err(|_| AppError::DecryptionFailed)?;

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

    const KEY: [u8; MASTER_KEY_LEN] = [0x42; MASTER_KEY_LEN];
    const WRONG_KEY: [u8; MASTER_KEY_LEN] = [0x43; MASTER_KEY_LEN];
    const SALT: [u8; SALT_LEN] = [0x24; SALT_LEN];
    const NONCE: [u8; NONCE_LEN] = [0x81; NONCE_LEN];
    const HEADER: &[u8] = b"full container header\0with binary\xff";

    fn assert_encryption_failed(result: Result<(Vec<u8>, Vec<u8>), AppError>) {
        assert!(matches!(result, Err(AppError::EncryptionFailed)));
    }

    fn assert_decryption_failed(result: Result<Zeroizing<Vec<u8>>, AppError>) {
        assert!(matches!(result, Err(AppError::DecryptionFailed)));
    }

    #[test]
    fn round_trips_boundary_lengths() {
        for len in [0, 1, 11, 12, 15, 16, 17, 31, 32, 33, 255, 256, 1024] {
            let plaintext: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(37)).collect();
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
        let plaintext = b"fixed AES-256-GCM-SIV material";
        let first = seal(&KEY, &SALT, &NONCE, HEADER, plaintext).unwrap();
        let second = seal(&KEY, &SALT, &NONCE, HEADER, plaintext).unwrap();
        assert_eq!(first, second);
        assert_eq!(
            first.0,
            [
                0xd7, 0xdc, 0xa0, 0x83, 0x09, 0xba, 0xcb, 0xd9, 0x13, 0x0d, 0xee, 0x1d, 0x07, 0xe5,
                0x96, 0x6d, 0x7a, 0x7b, 0x22, 0xa0, 0x54, 0x2d, 0x08, 0xe4, 0x80, 0x5e, 0x97, 0x4e,
                0x5a, 0x2d,
            ]
        );
        assert_eq!(
            first.1,
            [
                0x97, 0xd0, 0xb9, 0x8e, 0x56, 0xe7, 0xf6, 0x49, 0xde, 0x2e, 0x4e, 0x91, 0xba, 0x4e,
                0xae, 0x89,
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
