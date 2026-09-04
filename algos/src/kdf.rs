use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::format::{ARGON_LANES, ARGON_MEMORY_KIB, ARGON_TIME_COST};
use crate::{Error, Result, Suite};

const HKDF_SALT: &[u8] = b"algos/envelope/v1/hkdf";

pub(crate) fn password_master(password: &[u8], salt: &[u8; 16]) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(
        ARGON_MEMORY_KIB,
        ARGON_TIME_COST,
        u32::from(ARGON_LANES),
        Some(32),
    )
    .map_err(|_| Error::Crypto)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut master = Zeroizing::new([0_u8; 32]);
    argon2
        .hash_password_into(password, salt, master.as_mut())
        .map_err(|_| Error::Crypto)?;
    Ok(master)
}

pub(crate) fn record_key(
    master: &[u8; 32],
    suite: Suite,
    index: u64,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut info = [0_u8; 13];
    info[0..3].copy_from_slice(b"enc");
    info[3..5].copy_from_slice(&suite.id().to_le_bytes());
    info[5..13].copy_from_slice(&index.to_le_bytes());
    expand(master, &info, suite.key_len())
}

pub(crate) fn file_mac_key(master: &[u8; 32], suite: Suite) -> Result<Zeroizing<[u8; 32]>> {
    let mut info = [0_u8; 5];
    info[0..3].copy_from_slice(b"mac");
    info[3..5].copy_from_slice(&suite.id().to_le_bytes());
    let bytes = expand(master, &info, 32)?;
    let mut key = Zeroizing::new([0_u8; 32]);
    key.copy_from_slice(bytes.as_slice());
    Ok(key)
}

fn expand(master: &[u8; 32], info: &[u8], len: usize) -> Result<Zeroizing<Vec<u8>>> {
    let hkdf = Hkdf::<Sha256>::new(Some(HKDF_SALT), master);
    let mut output = Zeroizing::new(vec![0_u8; len]);
    hkdf.expand(info, output.as_mut_slice())
        .map_err(|_| Error::Crypto)?;
    Ok(output)
}

/// Derive an injective per-file record nonce for every nonce size in the registry.
pub(crate) fn record_nonce(seed: &[u8; 24], nonce_len: usize, index: u64) -> Result<Vec<u8>> {
    let index_bytes = index.to_le_bytes();
    match nonce_len {
        8..=24 => {
            let mut nonce = seed[..nonce_len].to_vec();
            for (dst, src) in nonce[nonce_len - 8..].iter_mut().zip(index_bytes) {
                *dst ^= src;
            }
            Ok(nonce)
        }
        32 => {
            let mut nonce = Vec::with_capacity(32);
            nonce.extend_from_slice(seed);
            nonce.extend_from_slice(&index_bytes);
            Ok(nonce)
        }
        _ => Err(Error::Crypto),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::ALL_SUITES;

    #[test]
    fn keys_are_domain_separated_by_suite_record_and_purpose() {
        let master = [42_u8; 32];
        let first = record_key(&master, Suite::Aes256Gcm, 0).unwrap();
        let next = record_key(&master, Suite::Aes256Gcm, 1).unwrap();
        let other = record_key(&master, Suite::Aes128Gcm, 0).unwrap();
        let mac = file_mac_key(&master, Suite::Aes256Gcm).unwrap();
        assert_ne!(first.as_slice(), next.as_slice());
        assert_ne!(first.as_slice(), other.as_slice());
        assert_ne!(first.as_slice(), mac.as_slice());
    }

    #[test]
    fn every_registered_nonce_size_is_supported_and_unique() {
        let seed = [0xA5; 24];
        for suite in ALL_SUITES {
            let nonces: HashSet<_> = (0..100)
                .map(|index| record_nonce(&seed, suite.nonce_len(), index).unwrap())
                .collect();
            assert_eq!(nonces.len(), 100, "{}", suite.name());
            assert!(nonces.iter().all(|nonce| nonce.len() == suite.nonce_len()));
        }
    }

    #[test]
    fn compound_siv_keys_have_the_required_length() {
        let master = [0_u8; 32];
        assert_eq!(
            record_key(&master, Suite::Aes128CmacSiv, 0).unwrap().len(),
            32
        );
        assert_eq!(
            record_key(&master, Suite::Aes256CmacSiv, 0).unwrap().len(),
            64
        );
    }

    #[test]
    fn production_kdf_schedule_has_a_stable_compatibility_vector() {
        let master = password_master(b"test password", &[3_u8; 16]).unwrap();
        assert_eq!(
            *master,
            hex_literal::hex!("8b62605b1747db058f19132358fe90409a43bbec1696bb4f3f527d3271d2cfda")
        );
        assert_eq!(
            record_key(&master, Suite::Aes256CmacSiv, 7)
                .unwrap()
                .as_slice(),
            hex_literal::hex!(
                "ce4806909d43c58f86cfa9483ce5475e"
                "5d470607879137b0e04923d783a01fd9"
                "46179e164882d95a2fe97a7495350c90"
                "5a693770d44ca028fe4440edf915cdeb"
            )
        );
        assert_eq!(
            file_mac_key(&master, Suite::Hc256Hmac).unwrap().as_slice(),
            hex_literal::hex!("6bfedeee695d4f1a519251da9f188d3c193b25b13bf9869bdf09b405093a249d")
        );
    }

    #[test]
    fn argon2id_v19_reference_vector() {
        // Reference implementation vector carried by the upstream argon2 crate:
        // Argon2id v19, m=256 KiB, t=2, p=1.
        let params = Params::new(256, 2, 1, Some(32)).unwrap();
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut output = [0_u8; 32];
        argon2
            .hash_password_into(b"password", b"somesalt", &mut output)
            .unwrap();
        assert_eq!(
            output,
            hex_literal::hex!("9dfeb910e80bad0311fee20f9c0e2b12c17987b4cac90c2ef54d5b3021c68bfe")
        );
    }

    #[test]
    fn hkdf_sha256_rfc5869_case_one() {
        let ikm = [0x0b_u8; 22];
        let salt = hex_literal::hex!("000102030405060708090a0b0c");
        let info = hex_literal::hex!("f0f1f2f3f4f5f6f7f8f9");
        let hkdf = Hkdf::<Sha256>::new(Some(&salt), &ikm);
        let mut output = [0_u8; 42];
        hkdf.expand(&info, &mut output).unwrap();
        assert_eq!(
            output,
            hex_literal::hex!(
                "3cb25f25faacd57a90434f64d0362f2a"
                "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                "34007208d5b887185865"
            )
        );
    }
}
