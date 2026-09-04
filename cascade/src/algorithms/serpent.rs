//! Serpent-256-CBC with PKCS#7 padding and encrypt-then-MAC authentication.
//!
//! CBC is only used behind a full HMAC-SHA-512 tag. Decryption authenticates
//! the suite domain, IV, serialized container header, and ciphertext before it
//! invokes the block cipher or examines padding.

use cbc::cipher::{BlockModeDecrypt, BlockModeEncrypt, InnerIvInit, KeyInit, block_padding::Pkcs7};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serpent::Serpent;
use sha2::Sha512;
use zeroize::Zeroizing;

use crate::error::AppError;

use super::SALT_LEN;

/// Serpent's block and CBC initialization-vector size, in bytes.
pub const IV_LEN: usize = 16;
/// Serpent's block size, in bytes.
pub const BLOCK_LEN: usize = 16;

const MASTER_KEY_LEN: usize = 32;
const ENCRYPTION_KEY_LEN: usize = 32;
const AUTHENTICATION_KEY_LEN: usize = 64;
const TAG_LEN: usize = 64;

// These byte strings are protocol constants. Keeping the encryption and MAC
// labels independent prevents a derived key from being reused for both roles.
const KDF_ENCRYPTION_INFO: &[u8] = b"cascade:file:v1:serpent-256-cbc:encryption-key";
const KDF_AUTHENTICATION_INFO: &[u8] = b"cascade:file:v1:serpent-256-cbc:hmac-sha512-key";
const MAC_DOMAIN: &[u8] = b"cascade:file:v1:serpent-256-cbc:hmac-sha512\0";

type CbcEncryptor = cbc::Encryptor<Serpent>;
type CbcDecryptor = cbc::Decryptor<Serpent>;
type HmacSha512 = Hmac<Sha512>;

struct DerivedKeys {
    encryption: Zeroizing<[u8; ENCRYPTION_KEY_LEN]>,
    authentication: Zeroizing<[u8; AUTHENTICATION_KEY_LEN]>,
}

/// Encrypt and authenticate one in-memory plaintext.
pub(super) fn seal(
    master_key: &[u8],
    salt: &[u8; SALT_LEN],
    iv: &[u8],
    header: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), AppError> {
    if master_key.len() != MASTER_KEY_LEN || iv.len() != IV_LEN {
        return Err(AppError::EncryptionFailed);
    }

    let ciphertext_len = padded_len(plaintext.len()).ok_or(AppError::EncryptionFailed)?;
    let keys = derive_keys(master_key, salt).map_err(|()| AppError::EncryptionFailed)?;

    // Serpent supports 128- through 256-bit keys, while its RustCrypto
    // KeySize type names the minimum size. Constructing it explicitly through
    // its variable-length initializer is therefore required for Serpent-256.
    let cipher = <Serpent as KeyInit>::new_from_slice(keys.encryption.as_ref())
        .map_err(|_| AppError::EncryptionFailed)?;
    let encryptor =
        CbcEncryptor::inner_iv_slice_init(cipher, iv).map_err(|_| AppError::EncryptionFailed)?;

    let mut ciphertext = Vec::new();
    ciphertext
        .try_reserve_exact(ciphertext_len)
        .map_err(|_| AppError::EncryptionFailed)?;
    ciphertext.resize(ciphertext_len, 0);
    let written_len = encryptor
        .encrypt_padded_b2b::<Pkcs7>(plaintext, &mut ciphertext)
        .map_err(|_| AppError::EncryptionFailed)?
        .len();
    if written_len != ciphertext_len {
        return Err(AppError::EncryptionFailed);
    }

    let tag = make_tag(keys.authentication.as_ref(), iv, header, &ciphertext)
        .map_err(|()| AppError::EncryptionFailed)?;
    Ok((ciphertext, tag))
}

/// Authenticate and decrypt one in-memory ciphertext.
pub(super) fn open(
    master_key: &[u8],
    salt: &[u8; SALT_LEN],
    iv: &[u8],
    header: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Zeroizing<Vec<u8>>, AppError> {
    if master_key.len() != MASTER_KEY_LEN
        || iv.len() != IV_LEN
        || tag.len() != TAG_LEN
        || ciphertext.is_empty()
        || ciphertext.len() % BLOCK_LEN != 0
    {
        return Err(AppError::DecryptionFailed);
    }

    let keys = derive_keys(master_key, salt).map_err(|()| AppError::DecryptionFailed)?;

    // HMAC's verify_slice performs a constant-time comparison. This must stay
    // before construction or invocation of the CBC decryptor so padding is
    // never an authentication oracle.
    verify_tag(keys.authentication.as_ref(), iv, header, ciphertext, tag)
        .map_err(|()| AppError::DecryptionFailed)?;

    let cipher = <Serpent as KeyInit>::new_from_slice(keys.encryption.as_ref())
        .map_err(|_| AppError::DecryptionFailed)?;
    let decryptor =
        CbcDecryptor::inner_iv_slice_init(cipher, iv).map_err(|_| AppError::DecryptionFailed)?;

    let mut plaintext = Zeroizing::new(Vec::new());
    plaintext
        .try_reserve_exact(ciphertext.len())
        .map_err(|_| AppError::DecryptionFailed)?;
    plaintext.resize(ciphertext.len(), 0);
    let plaintext_len = decryptor
        .decrypt_padded_b2b::<Pkcs7>(ciphertext, plaintext.as_mut_slice())
        .map_err(|_| AppError::DecryptionFailed)?
        .len();
    plaintext.truncate(plaintext_len);
    Ok(plaintext)
}

fn derive_keys(master_key: &[u8], salt: &[u8; SALT_LEN]) -> Result<DerivedKeys, ()> {
    let (prk, hkdf) = Hkdf::<Sha512>::extract(Some(salt), master_key);
    let _prk = Zeroizing::new(prk);
    let mut encryption = Zeroizing::new([0_u8; ENCRYPTION_KEY_LEN]);
    let mut authentication = Zeroizing::new([0_u8; AUTHENTICATION_KEY_LEN]);
    hkdf.expand(KDF_ENCRYPTION_INFO, encryption.as_mut())
        .map_err(|_| ())?;
    hkdf.expand(KDF_AUTHENTICATION_INFO, authentication.as_mut())
        .map_err(|_| ())?;
    Ok(DerivedKeys {
        encryption,
        authentication,
    })
}

fn mac_for(
    authentication_key: &[u8],
    iv: &[u8],
    header: &[u8],
    ciphertext: &[u8],
) -> Result<HmacSha512, ()> {
    let mut mac =
        <HmacSha512 as hmac::KeyInit>::new_from_slice(authentication_key).map_err(|_| ())?;
    mac.update(MAC_DOMAIN);
    mac.update(iv);
    mac.update(header);
    mac.update(ciphertext);
    Ok(mac)
}

fn make_tag(
    authentication_key: &[u8],
    iv: &[u8],
    header: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, ()> {
    let tag_bytes = mac_for(authentication_key, iv, header, ciphertext)?
        .finalize()
        .into_bytes();
    let mut tag = Vec::new();
    tag.try_reserve_exact(TAG_LEN).map_err(|_| ())?;
    tag.extend_from_slice(&tag_bytes);
    Ok(tag)
}

fn verify_tag(
    authentication_key: &[u8],
    iv: &[u8],
    header: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<(), ()> {
    mac_for(authentication_key, iv, header, ciphertext)?
        .verify_slice(tag)
        .map_err(|_| ())
}

fn padded_len(plaintext_len: usize) -> Option<usize> {
    plaintext_len
        .checked_div(BLOCK_LEN)?
        .checked_add(1)?
        .checked_mul(BLOCK_LEN)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cbc::cipher::{Block, BlockCipherDecrypt, BlockCipherEncrypt};

    const KEY: [u8; MASTER_KEY_LEN] = [0x42; MASTER_KEY_LEN];
    const WRONG_KEY: [u8; MASTER_KEY_LEN] = [0x43; MASTER_KEY_LEN];
    const SALT: [u8; SALT_LEN] = [0x24; SALT_LEN];
    const IV: [u8; IV_LEN] = [0x81; IV_LEN];
    const HEADER: &[u8] = b"exact serialized test header";

    fn plaintext(len: usize) -> Vec<u8> {
        (0..len)
            .map(|index| (index as u8).wrapping_mul(29).wrapping_add(7))
            .collect()
    }

    fn assert_decryption_failed(result: Result<Zeroizing<Vec<u8>>, AppError>) {
        assert!(matches!(result, Err(AppError::DecryptionFailed)));
    }

    #[test]
    fn serpent_256_matches_nessie_known_answer() {
        // NESSIE: 256-bit all-zero key and all-zero plaintext block.
        let cipher = <Serpent as KeyInit>::new_from_slice(&[0_u8; MASTER_KEY_LEN]).unwrap();
        let mut block = Block::<Serpent>::default();
        cipher.encrypt_block(&mut block);
        assert_eq!(
            block.as_slice(),
            &[
                0x49, 0x67, 0x2b, 0xa8, 0x98, 0xd9, 0x8d, 0xf9, 0x50, 0x19, 0x18, 0x04, 0x45, 0x49,
                0x10, 0x89,
            ]
        );
        cipher.decrypt_block(&mut block);
        assert_eq!(block.as_slice(), &[0_u8; BLOCK_LEN]);
    }

    #[test]
    fn boundary_lengths_round_trip() {
        for len in [0, 1, 15, 16, 17, 127, 128, 129, 255, 256, 257] {
            let input = plaintext(len);
            let (ciphertext, tag) = seal(&KEY, &SALT, &IV, HEADER, &input).unwrap();
            assert_eq!(ciphertext.len(), padded_len(len).unwrap());
            assert_eq!(tag.len(), TAG_LEN);
            let output = open(&KEY, &SALT, &IV, HEADER, &ciphertext, &tag).unwrap();
            assert_eq!(output.as_slice(), input.as_slice(), "length {len}");
        }
    }

    #[test]
    fn construction_is_deterministic_for_fixed_public_material() {
        let input = plaintext(129);
        let first = seal(&KEY, &SALT, &IV, HEADER, &input).unwrap();
        let second = seal(&KEY, &SALT, &IV, HEADER, &input).unwrap();
        assert_eq!(first, second);

        let different_salt = [0x25; SALT_LEN];
        assert_ne!(
            first,
            seal(&KEY, &different_salt, &IV, HEADER, &input).unwrap()
        );
        let different_iv = [0x82; IV_LEN];
        assert_ne!(
            first,
            seal(&KEY, &SALT, &different_iv, HEADER, &input).unwrap()
        );

        let changed_header = seal(&KEY, &SALT, &IV, b"changed header", &input).unwrap();
        assert_eq!(first.0, changed_header.0);
        assert_ne!(first.1, changed_header.1);
    }

    #[test]
    fn wrong_key_is_rejected() {
        let (ciphertext, tag) = seal(&KEY, &SALT, &IV, HEADER, b"secret").unwrap();
        assert_decryption_failed(open(&WRONG_KEY, &SALT, &IV, HEADER, &ciphertext, &tag));
    }

    #[test]
    fn header_ciphertext_tag_and_salt_tampering_are_rejected() {
        let (ciphertext, tag) = seal(&KEY, &SALT, &IV, HEADER, &plaintext(64)).unwrap();

        let mut header = HEADER.to_vec();
        header[0] ^= 1;
        assert_decryption_failed(open(&KEY, &SALT, &IV, &header, &ciphertext, &tag));

        let mut changed_ciphertext = ciphertext.clone();
        changed_ciphertext[0] ^= 1;
        assert_decryption_failed(open(&KEY, &SALT, &IV, HEADER, &changed_ciphertext, &tag));

        let mut changed_tag = tag.clone();
        changed_tag[TAG_LEN - 1] ^= 1;
        assert_decryption_failed(open(&KEY, &SALT, &IV, HEADER, &ciphertext, &changed_tag));

        let mut changed_salt = SALT;
        changed_salt[0] ^= 1;
        assert_decryption_failed(open(&KEY, &changed_salt, &IV, HEADER, &ciphertext, &tag));

        let mut changed_iv = IV;
        changed_iv[0] ^= 1;
        assert_decryption_failed(open(&KEY, &SALT, &changed_iv, HEADER, &ciphertext, &tag));
    }

    #[test]
    fn invalid_key_iv_tag_and_ciphertext_lengths_are_errors() {
        assert!(matches!(
            seal(&KEY[..MASTER_KEY_LEN - 1], &SALT, &IV, HEADER, b"data"),
            Err(AppError::EncryptionFailed)
        ));
        assert!(matches!(
            seal(&KEY, &SALT, &IV[..IV_LEN - 1], HEADER, b"data"),
            Err(AppError::EncryptionFailed)
        ));
        let long_iv = [0_u8; IV_LEN + 1];
        assert!(matches!(
            seal(&KEY, &SALT, &long_iv, HEADER, b"data"),
            Err(AppError::EncryptionFailed)
        ));

        let (ciphertext, tag) = seal(&KEY, &SALT, &IV, HEADER, b"data").unwrap();
        assert_decryption_failed(open(
            &KEY[..MASTER_KEY_LEN - 1],
            &SALT,
            &IV,
            HEADER,
            &ciphertext,
            &tag,
        ));
        assert_decryption_failed(open(
            &KEY,
            &SALT,
            &IV[..IV_LEN - 1],
            HEADER,
            &ciphertext,
            &tag,
        ));
        assert_decryption_failed(open(&KEY, &SALT, &long_iv, HEADER, &ciphertext, &tag));
        assert_decryption_failed(open(
            &KEY,
            &SALT,
            &IV,
            HEADER,
            &ciphertext,
            &tag[..TAG_LEN - 1],
        ));
        let mut long_tag = tag.clone();
        long_tag.push(0);
        assert_decryption_failed(open(&KEY, &SALT, &IV, HEADER, &ciphertext, &long_tag));
        assert_decryption_failed(open(&KEY, &SALT, &IV, HEADER, &[], &tag));
        assert_decryption_failed(open(
            &KEY,
            &SALT,
            &IV,
            HEADER,
            &ciphertext[..BLOCK_LEN - 1],
            &tag,
        ));
        let mut non_block_aligned = ciphertext.clone();
        non_block_aligned.push(0);
        assert_decryption_failed(open(&KEY, &SALT, &IV, HEADER, &non_block_aligned, &tag));
    }

    #[test]
    fn authenticated_malformed_padding_is_rejected() {
        // A full padding block follows this 16-byte plaintext. Flipping the
        // preceding CBC block's final byte deterministically corrupts the last
        // padding byte; a recomputed tag lets this test reach unpadding.
        let (mut ciphertext, _) = seal(&KEY, &SALT, &IV, HEADER, &plaintext(BLOCK_LEN)).unwrap();
        ciphertext[BLOCK_LEN - 1] ^= 1;
        let keys = derive_keys(&KEY, &SALT).unwrap();
        let tag = make_tag(keys.authentication.as_ref(), &IV, HEADER, &ciphertext).unwrap();
        assert_decryption_failed(open(&KEY, &SALT, &IV, HEADER, &ciphertext, &tag));
    }

    #[test]
    fn derived_key_roles_are_domain_separated() {
        let keys = derive_keys(&KEY, &SALT).unwrap();
        assert_ne!(
            keys.encryption.as_slice(),
            &keys.authentication[..ENCRYPTION_KEY_LEN]
        );
        let again = derive_keys(&KEY, &SALT).unwrap();
        assert_eq!(keys.encryption.as_slice(), again.encryption.as_slice());
        assert_eq!(
            keys.authentication.as_slice(),
            again.authentication.as_slice()
        );
    }
}
