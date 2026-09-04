use aegis::aegis128l::Aegis128L;
use aegis::aegis256::Aegis256;
use aes_gcm_siv::Aes256GcmSiv;
use aes_gcm_siv::aead::{AeadInOut, Key, KeyInit, Nonce, Tag};
use ascon_aead::AsconAead128;
use ctr::cipher::{InnerIvInit, Iv, KeyIvInit, StreamCipher, StreamCipherCoreWrapper};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit as HmacKeyInit, Mac};
use rabbit::Rabbit;
use serpent::Serpent;
use sha2::{Digest, Sha256, Sha512};
use threefish::Threefish1024;
use zeroize::Zeroizing;

use crate::container::{self, KEY_ID_LEN, SALT_LEN};
use crate::{Algorithm, Error};

const KDF_DOMAIN: &[u8] = b"MCRYPT-FILE-v1\0";
const AUTH_DOMAIN: &[u8] = b"MCRYPT-AUTH-v1\0";
type HmacSha512 = Hmac<Sha512>;
type SerpentCtrCore = ctr::CtrCore<Serpent, ctr::flavors::Ctr128BE>;
type ThreefishCtrCore = ctr::CtrCore<Threefish1024, ctr::flavors::Ctr128BE>;

pub(crate) fn seal(
    algorithm: Algorithm,
    plaintext: &[u8],
    master_key: &[u8; 32],
) -> Result<Vec<u8>, Error> {
    let mut salt = [0_u8; SALT_LEN];
    let mut nonce = Zeroizing::new(vec![0_u8; algorithm.nonce_len()]);
    getrandom::fill(&mut salt).map_err(|error| Error::Random(error.to_string()))?;
    getrandom::fill(&mut nonce).map_err(|error| Error::Random(error.to_string()))?;
    seal_with_material(algorithm, plaintext, master_key, &salt, &nonce)
}

pub(crate) fn seal_with_material(
    algorithm: Algorithm,
    plaintext: &[u8],
    master_key: &[u8; 32],
    salt: &[u8; SALT_LEN],
    nonce: &[u8],
) -> Result<Vec<u8>, Error> {
    if nonce.len() != algorithm.nonce_len() {
        return Err(Error::Crypto("internal nonce length mismatch"));
    }

    let key_id = key_id(algorithm, master_key);
    let header = container::build_header(algorithm, plaintext.len(), &key_id, salt, nonce)?;
    let encryption_key = derive_key(
        algorithm,
        master_key,
        salt,
        b"ENC",
        algorithm.encryption_key_len(),
    )?;
    let mac_key = if algorithm.mac_key_len() == 0 {
        None
    } else {
        Some(derive_key(
            algorithm,
            master_key,
            salt,
            b"MAC",
            algorithm.mac_key_len(),
        )?)
    };
    let (ciphertext, tag) = encrypt_payload(
        algorithm,
        plaintext,
        &encryption_key,
        mac_key.as_ref().map(|key| key.as_slice()),
        nonce,
        &header,
    )?;

    let total_len = header
        .len()
        .checked_add(ciphertext.len())
        .and_then(|length| length.checked_add(tag.len()))
        .ok_or(Error::InputTooLarge)?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(total_len)
        .map_err(|_| Error::OutOfMemory)?;
    output.extend_from_slice(&header);
    output.extend_from_slice(&ciphertext);
    output.extend_from_slice(&tag);
    Ok(output)
}

pub(crate) fn open(
    requested: Algorithm,
    container_bytes: &[u8],
    master_key: &[u8; 32],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let parsed = container::parse(container_bytes, requested)?;
    if parsed.key_id != &key_id(parsed.algorithm, master_key) {
        return Err(Error::AuthenticationFailed);
    }

    let encryption_key = derive_key(
        parsed.algorithm,
        master_key,
        parsed.salt,
        b"ENC",
        parsed.algorithm.encryption_key_len(),
    )?;
    let mac_key = if parsed.algorithm.mac_key_len() == 0 {
        None
    } else {
        Some(derive_key(
            parsed.algorithm,
            master_key,
            parsed.salt,
            b"MAC",
            parsed.algorithm.mac_key_len(),
        )?)
    };
    decrypt_payload(
        parsed.algorithm,
        parsed.ciphertext,
        parsed.tag,
        &encryption_key,
        mac_key.as_ref().map(|key| key.as_slice()),
        parsed.nonce,
        parsed.header,
    )
}

fn key_id(algorithm: Algorithm, master_key: &[u8; 32]) -> [u8; KEY_ID_LEN] {
    let mut hash = Sha256::new();
    hash.update(b"MCRYPT key-id v1\0");
    hash.update(algorithm.id().to_be_bytes());
    hash.update(master_key);
    let digest = hash.finalize();
    let mut result = [0_u8; KEY_ID_LEN];
    result.copy_from_slice(&digest[..KEY_ID_LEN]);
    result
}

fn derive_key(
    algorithm: Algorithm,
    master_key: &[u8; 32],
    salt: &[u8; SALT_LEN],
    purpose: &[u8],
    length: usize,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let hkdf = Hkdf::<Sha512>::new(Some(salt), master_key);
    let mut info = Vec::with_capacity(KDF_DOMAIN.len() + 3 + purpose.len());
    info.extend_from_slice(KDF_DOMAIN);
    info.extend_from_slice(&algorithm.id().to_be_bytes());
    info.push(0);
    info.extend_from_slice(purpose);

    let mut result = Zeroizing::new(vec![0_u8; length]);
    hkdf.expand(&info, &mut result)
        .map_err(|_| Error::Crypto("HKDF output length is invalid"))?;
    Ok(result)
}

fn encrypt_payload(
    algorithm: Algorithm,
    plaintext: &[u8],
    encryption_key: &[u8],
    mac_key: Option<&[u8]>,
    nonce: &[u8],
    header: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    match algorithm {
        Algorithm::Aes256GcmSiv => {
            aead_encrypt::<Aes256GcmSiv>(encryption_key, nonce, header, plaintext)
        }
        Algorithm::AsconAead128 => {
            aead_encrypt::<AsconAead128>(encryption_key, nonce, header, plaintext)
        }
        Algorithm::Aegis256 => {
            let key: &[u8; 32] = encryption_key
                .try_into()
                .map_err(|_| Error::Crypto("invalid AEGIS-256 key length"))?;
            let nonce: &[u8; 32] = nonce
                .try_into()
                .map_err(|_| Error::Crypto("invalid AEGIS-256 nonce length"))?;
            let (ciphertext, tag) = Aegis256::<32>::new(key, nonce).encrypt(plaintext, header);
            Ok((ciphertext, tag.to_vec()))
        }
        Algorithm::Aegis128L => {
            let key: &[u8; 16] = encryption_key
                .try_into()
                .map_err(|_| Error::Crypto("invalid AEGIS-128L key length"))?;
            let nonce: &[u8; 16] = nonce
                .try_into()
                .map_err(|_| Error::Crypto("invalid AEGIS-128L nonce length"))?;
            let (ciphertext, tag) = Aegis128L::<32>::new(key, nonce).encrypt(plaintext, header);
            Ok((ciphertext, tag.to_vec()))
        }
        Algorithm::Serpent256CtrHmacSha512
        | Algorithm::Threefish1024CtrHmacSha512
        | Algorithm::RabbitHmacSha512 => {
            let mut ciphertext = Zeroizing::new(copy_bytes(plaintext)?);
            apply_stream(algorithm, encryption_key, nonce, &mut ciphertext)?;
            let tag = compute_hmac(
                mac_key.ok_or(Error::Crypto("missing MAC key"))?,
                header,
                &ciphertext,
            )?;
            Ok((std::mem::take(&mut *ciphertext), tag))
        }
    }
}

fn decrypt_payload(
    algorithm: Algorithm,
    ciphertext: &[u8],
    tag: &[u8],
    encryption_key: &[u8],
    mac_key: Option<&[u8]>,
    nonce: &[u8],
    header: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    match algorithm {
        Algorithm::Aes256GcmSiv => {
            aead_decrypt::<Aes256GcmSiv>(encryption_key, nonce, header, ciphertext, tag)
        }
        Algorithm::AsconAead128 => {
            aead_decrypt::<AsconAead128>(encryption_key, nonce, header, ciphertext, tag)
        }
        Algorithm::Aegis256 => {
            let key: &[u8; 32] = encryption_key
                .try_into()
                .map_err(|_| Error::Crypto("invalid AEGIS-256 key length"))?;
            let nonce: &[u8; 32] = nonce
                .try_into()
                .map_err(|_| Error::Crypto("invalid AEGIS-256 nonce length"))?;
            let tag: &[u8; 32] = tag.try_into().map_err(|_| Error::AuthenticationFailed)?;
            let mut plaintext = Zeroizing::new(copy_bytes(ciphertext)?);
            Aegis256::<32>::new(key, nonce)
                .decrypt_in_place(&mut plaintext, tag, header)
                .map_err(|_| Error::AuthenticationFailed)?;
            Ok(plaintext)
        }
        Algorithm::Aegis128L => {
            let key: &[u8; 16] = encryption_key
                .try_into()
                .map_err(|_| Error::Crypto("invalid AEGIS-128L key length"))?;
            let nonce: &[u8; 16] = nonce
                .try_into()
                .map_err(|_| Error::Crypto("invalid AEGIS-128L nonce length"))?;
            let tag: &[u8; 32] = tag.try_into().map_err(|_| Error::AuthenticationFailed)?;
            let mut plaintext = Zeroizing::new(copy_bytes(ciphertext)?);
            Aegis128L::<32>::new(key, nonce)
                .decrypt_in_place(&mut plaintext, tag, header)
                .map_err(|_| Error::AuthenticationFailed)?;
            Ok(plaintext)
        }
        Algorithm::Serpent256CtrHmacSha512
        | Algorithm::Threefish1024CtrHmacSha512
        | Algorithm::RabbitHmacSha512 => {
            verify_hmac(
                mac_key.ok_or(Error::Crypto("missing MAC key"))?,
                header,
                ciphertext,
                tag,
            )?;
            let mut plaintext = Zeroizing::new(copy_bytes(ciphertext)?);
            apply_stream(algorithm, encryption_key, nonce, &mut plaintext)?;
            Ok(plaintext)
        }
    }
}

fn aead_encrypt<A>(
    key: &[u8],
    nonce: &[u8],
    associated_data: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), Error>
where
    A: KeyInit + AeadInOut,
{
    let key = Key::<A>::try_from(key).map_err(|_| Error::Crypto("invalid AEAD key length"))?;
    let nonce =
        Nonce::<A>::try_from(nonce).map_err(|_| Error::Crypto("invalid AEAD nonce length"))?;
    let cipher = A::new(&key);
    let mut ciphertext = Zeroizing::new(copy_bytes(plaintext)?);
    let tag = cipher
        .encrypt_inout_detached(&nonce, associated_data, ciphertext.as_mut_slice().into())
        .map_err(|_| Error::Crypto("AEAD encryption failed"))?;
    Ok((std::mem::take(&mut *ciphertext), tag.to_vec()))
}

fn aead_decrypt<A>(
    key: &[u8],
    nonce: &[u8],
    associated_data: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error>
where
    A: KeyInit + AeadInOut,
{
    let key = Key::<A>::try_from(key).map_err(|_| Error::Crypto("invalid AEAD key length"))?;
    let nonce =
        Nonce::<A>::try_from(nonce).map_err(|_| Error::Crypto("invalid AEAD nonce length"))?;
    let tag = Tag::<A>::try_from(tag).map_err(|_| Error::AuthenticationFailed)?;
    let cipher = A::new(&key);
    let mut plaintext = Zeroizing::new(copy_bytes(ciphertext)?);
    cipher
        .decrypt_inout_detached(
            &nonce,
            associated_data,
            plaintext.as_mut_slice().into(),
            &tag,
        )
        .map_err(|_| Error::AuthenticationFailed)?;
    Ok(plaintext)
}

fn apply_stream(
    algorithm: Algorithm,
    key: &[u8],
    nonce: &[u8],
    buffer: &mut [u8],
) -> Result<(), Error> {
    match algorithm {
        Algorithm::Serpent256CtrHmacSha512 => apply_serpent_ctr(key, nonce, buffer),
        Algorithm::Threefish1024CtrHmacSha512 => apply_threefish_ctr(key, nonce, buffer),
        Algorithm::RabbitHmacSha512 => apply_rabbit(key, nonce, buffer),
        _ => Err(Error::Crypto("algorithm is not a stream-cipher suite")),
    }
}

fn apply_serpent_ctr(key: &[u8], iv: &[u8], buffer: &mut [u8]) -> Result<(), Error> {
    ensure_ctr_capacity(iv, buffer.len(), 16)?;
    let block_cipher = Serpent::new_from_slice(key)
        .map_err(|_| Error::Crypto("invalid Serpent-256 key length"))?;
    let iv = Iv::<SerpentCtrCore>::try_from(iv)
        .map_err(|_| Error::Crypto("invalid Serpent CTR IV length"))?;
    let core = SerpentCtrCore::inner_iv_init(block_cipher, &iv);
    let mut cipher = StreamCipherCoreWrapper::from_core(core);
    cipher
        .try_apply_keystream(buffer)
        .map_err(|_| Error::Crypto("Serpent CTR counter exhausted"))
}

fn apply_threefish_ctr(key: &[u8], iv: &[u8], buffer: &mut [u8]) -> Result<(), Error> {
    ensure_ctr_capacity(iv, buffer.len(), 128)?;
    let key: &[u8; 128] = key
        .try_into()
        .map_err(|_| Error::Crypto("invalid Threefish-1024 key length"))?;
    let block_cipher = Threefish1024::new_with_tweak(key, &[0_u8; 16]);
    let iv = Iv::<ThreefishCtrCore>::try_from(iv)
        .map_err(|_| Error::Crypto("invalid Threefish CTR IV length"))?;
    let core = ThreefishCtrCore::inner_iv_init(block_cipher, &iv);
    let mut cipher = StreamCipherCoreWrapper::from_core(core);
    cipher
        .try_apply_keystream(buffer)
        .map_err(|_| Error::Crypto("Threefish CTR counter exhausted"))
}

fn ensure_ctr_capacity(iv: &[u8], data_len: usize, block_len: usize) -> Result<(), Error> {
    if data_len == 0 {
        return Ok(());
    }
    let counter_bytes: &[u8; 16] = iv
        .get(iv.len().saturating_sub(16)..)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(Error::Crypto("invalid CTR IV length"))?;
    let initial_counter = u128::from_be_bytes(*counter_bytes);
    let blocks = data_len.div_ceil(block_len);
    let final_offset = u128::try_from(blocks - 1).map_err(|_| Error::InputTooLarge)?;
    initial_counter
        .checked_add(final_offset)
        .ok_or(Error::Crypto("CTR counter would wrap"))?;
    Ok(())
}

fn apply_rabbit(key: &[u8], iv: &[u8], buffer: &mut [u8]) -> Result<(), Error> {
    let mut cipher = Rabbit::new_from_slices(key, iv)
        .map_err(|_| Error::Crypto("invalid Rabbit key or IV length"))?;
    cipher
        .try_apply_keystream(buffer)
        .map_err(|_| Error::Crypto("Rabbit keystream exhausted"))
}

fn compute_hmac(key: &[u8], header: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
    let mut mac = <HmacSha512 as HmacKeyInit>::new_from_slice(key)
        .map_err(|_| Error::Crypto("invalid HMAC-SHA-512 key length"))?;
    mac.update(AUTH_DOMAIN);
    mac.update(header);
    mac.update(ciphertext);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn verify_hmac(key: &[u8], header: &[u8], ciphertext: &[u8], tag: &[u8]) -> Result<(), Error> {
    let mut mac = <HmacSha512 as HmacKeyInit>::new_from_slice(key)
        .map_err(|_| Error::Crypto("invalid HMAC-SHA-512 key length"))?;
    mac.update(AUTH_DOMAIN);
    mac.update(header);
    mac.update(ciphertext);
    mac.verify_slice(tag)
        .map_err(|_| Error::AuthenticationFailed)
}

fn copy_bytes(input: &[u8]) -> Result<Vec<u8>, Error> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(input.len())
        .map_err(|_| Error::OutOfMemory)?;
    copy.extend_from_slice(input);
    Ok(copy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ctr::cipher::BlockCipherEncrypt;

    fn test_master(algorithm: Algorithm) -> [u8; 32] {
        let mut key = [0_u8; 32];
        for (index, byte) in key.iter_mut().enumerate() {
            *byte = (index as u8)
                .wrapping_mul(17)
                .wrapping_add(algorithm.id() as u8);
        }
        key
    }

    fn deterministic_nonce(algorithm: Algorithm) -> Vec<u8> {
        (0..algorithm.nonce_len())
            .map(|index| (index as u8).wrapping_mul(29).wrapping_add(3))
            .collect()
    }

    #[test]
    fn every_suite_round_trips_boundary_lengths() {
        let lengths = [
            0_usize, 1, 7, 8, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257,
            4096,
        ];
        for algorithm in Algorithm::ALL {
            let master = test_master(algorithm);
            let salt = [algorithm.id() as u8; SALT_LEN];
            let nonce = deterministic_nonce(algorithm);
            for length in lengths {
                let plaintext: Vec<u8> = (0..length)
                    .map(|index| (index as u8).wrapping_mul(131).wrapping_add(length as u8))
                    .collect();
                let encrypted =
                    seal_with_material(algorithm, &plaintext, &master, &salt, &nonce).unwrap();
                if length != 0 {
                    assert_ne!(
                        &encrypted[container::BASE_HEADER_LEN + algorithm.nonce_len()
                            ..container::BASE_HEADER_LEN + algorithm.nonce_len() + length],
                        plaintext,
                        "algorithm={algorithm}, length={length}"
                    );
                }
                let decrypted = open(algorithm, &encrypted, &master).unwrap();
                assert_eq!(
                    decrypted.as_slice(),
                    plaintext,
                    "algorithm={algorithm}, length={length}"
                );
            }
        }
    }

    #[test]
    fn every_suite_round_trips_a_large_binary_value() {
        let plaintext: Vec<u8> = (0..256 * 1024)
            .map(|index| (index as u8).wrapping_mul(197).wrapping_add(91))
            .collect();
        for algorithm in Algorithm::ALL {
            let master = test_master(algorithm);
            let encrypted = seal(algorithm, &plaintext, &master).unwrap();
            assert_eq!(
                open(algorithm, &encrypted, &master).unwrap().as_slice(),
                plaintext
            );
        }
    }

    #[test]
    fn randomized_encryptions_of_the_same_message_differ() {
        for algorithm in Algorithm::ALL {
            let master = test_master(algorithm);
            let first = seal(algorithm, b"same message", &master).unwrap();
            let second = seal(algorithm, b"same message", &master).unwrap();
            assert_ne!(first, second, "algorithm={algorithm}");
            assert_eq!(
                open(algorithm, &first, &master).unwrap().as_slice(),
                b"same message"
            );
            assert_eq!(
                open(algorithm, &second, &master).unwrap().as_slice(),
                b"same message"
            );
        }
    }

    #[test]
    fn every_suite_rejects_wrong_keys_and_tampering_in_every_region() {
        for algorithm in Algorithm::ALL {
            let master = test_master(algorithm);
            let salt = [0x5a; SALT_LEN];
            let nonce = deterministic_nonce(algorithm);
            let encrypted =
                seal_with_material(algorithm, b"authenticated payload", &master, &salt, &nonce)
                    .unwrap();
            let header_len = container::BASE_HEADER_LEN + algorithm.nonce_len();
            let offsets = [
                40,
                56,
                container::BASE_HEADER_LEN,
                header_len,
                encrypted.len() - 1,
            ];
            for offset in offsets {
                let mut changed = encrypted.clone();
                changed[offset] ^= 0x80;
                assert!(
                    matches!(
                        open(algorithm, &changed, &master),
                        Err(Error::AuthenticationFailed)
                    ),
                    "algorithm={algorithm}, offset={offset}"
                );
            }

            let mut wrong_key = master;
            wrong_key[0] ^= 1;
            assert!(matches!(
                open(algorithm, &encrypted, &wrong_key),
                Err(Error::AuthenticationFailed)
            ));

            for offset in 0..encrypted.len() {
                let mut changed = encrypted.clone();
                changed[offset] ^= 1;
                assert!(
                    open(algorithm, &changed, &master).is_err(),
                    "single-byte change accepted: algorithm={algorithm}, offset={offset}"
                );
            }
        }
    }

    #[test]
    fn deterministic_container_hashes() {
        for algorithm in Algorithm::ALL {
            let master = test_master(algorithm);
            let salt = [0x42; SALT_LEN];
            let nonce = deterministic_nonce(algorithm);
            let encrypted = seal_with_material(
                algorithm,
                b"multicrypt v1 compatibility fixture",
                &master,
                &salt,
                &nonce,
            )
            .unwrap();
            let expected = match algorithm {
                Algorithm::Aes256GcmSiv => {
                    "a5631ac585562f127c59ea022e95ae03eee6efcfd721157496200cecdcbb66c6"
                }
                Algorithm::Serpent256CtrHmacSha512 => {
                    "19694cf2e979f2a3c915c6b30622252d0075bfcde4e07410806ba0a1f6f71f96"
                }
                Algorithm::Threefish1024CtrHmacSha512 => {
                    "946ad60f7257d25dcc7adac258b3b2269e64683b5069ee33ec18667cc4bc9679"
                }
                Algorithm::AsconAead128 => {
                    "6d3ad3ce3f3050ff516fb27199cc106d948e59ce619c7b4682979cd42173826f"
                }
                Algorithm::RabbitHmacSha512 => {
                    "2ea89684ffd678576dd716acd479ad6526925c7daa095c385c490e3c02c9b0ac"
                }
                Algorithm::Aegis256 => {
                    "1295e01c896423da1649a8ced4b828c81c89d6e743e40d2b212d6e1820763ef5"
                }
                Algorithm::Aegis128L => {
                    "cc9c63b691533c3e4712caf825e80120369e91e11c49421723aee98fb4558435"
                }
            };
            assert_eq!(
                hex::encode(Sha256::digest(&encrypted)),
                expected,
                "algorithm={algorithm}"
            );
        }
    }

    #[test]
    fn derived_keys_are_domain_and_algorithm_separated() {
        let master = [0x11; 32];
        let salt = [0x22; SALT_LEN];
        let enc = derive_key(Algorithm::Aes256GcmSiv, &master, &salt, b"ENC", 32).unwrap();
        let mac = derive_key(Algorithm::Aes256GcmSiv, &master, &salt, b"MAC", 32).unwrap();
        let other = derive_key(Algorithm::Aegis256, &master, &salt, b"ENC", 32).unwrap();
        assert_ne!(enc.as_slice(), mac.as_slice());
        assert_ne!(enc.as_slice(), other.as_slice());
    }

    #[test]
    fn aes_256_gcm_siv_matches_rfc_8452() {
        let key = hex::decode("0100000000000000000000000000000000000000000000000000000000000000")
            .unwrap();
        let nonce = hex::decode("030000000000000000000000").unwrap();
        let (ciphertext, tag) =
            aead_encrypt::<Aes256GcmSiv>(&key, &nonce, &[0x01], &[0x02, 0, 0, 0, 0, 0, 0, 0])
                .unwrap();
        assert_eq!(hex::encode(ciphertext), "1de22967237a8132");
        assert_eq!(hex::encode(tag), "91213f267e3b452f02d01ae33e4ec854");
    }

    #[test]
    fn ascon_aead128_matches_final_nist_vector() {
        let key = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let nonce = hex::decode("101112131415161718191a1b1c1d1e1f").unwrap();
        let (ciphertext, tag) =
            aead_encrypt::<AsconAead128>(&key, &nonce, &[0x30], &[0x20]).unwrap();
        assert_eq!(hex::encode(ciphertext), "96");
        assert_eq!(hex::encode(tag), "2b8016836c75a7d86866588ca245d886");
    }

    #[test]
    fn serpent_256_and_big_endian_ctr_match_nessie_vectors() {
        let key = [0_u8; 32];
        let cipher = Serpent::new_from_slice(&key).unwrap();
        let mut block = serpent::cipher::Block::<Serpent>::default();
        cipher.encrypt_block(&mut block);
        assert_eq!(hex::encode(block), "49672ba898d98df95019180445491089");

        let mut stream = [0_u8; 32];
        apply_serpent_ctr(&key, &[0_u8; 16], &mut stream).unwrap();
        assert_eq!(
            hex::encode(stream),
            concat!(
                "49672ba898d98df95019180445491089",
                "ad86de83231c3203a86ae33b721eaa9f"
            )
        );
    }

    #[test]
    fn serpent_ctr_rejects_counter_wrap_before_modifying_data() {
        let key = [0x3c_u8; 32];
        let maximum_iv = [0xff_u8; 16];

        let mut final_block = [0_u8; 16];
        apply_serpent_ctr(&key, &maximum_iv, &mut final_block).unwrap();
        assert_ne!(final_block, [0_u8; 16]);

        let mut too_long = [0_u8; 17];
        assert!(matches!(
            apply_serpent_ctr(&key, &maximum_iv, &mut too_long),
            Err(Error::Crypto("CTR counter would wrap"))
        ));
        assert_eq!(too_long, [0_u8; 17]);
    }

    #[test]
    fn threefish_1024_matches_official_zero_tweak_vector() {
        let key = [0_u8; 128];
        let cipher = Threefish1024::new_with_tweak(&key, &[0_u8; 16]);
        let mut block = threefish::cipher::Block::<Threefish1024>::default();
        cipher.encrypt_block(&mut block);
        assert_eq!(
            hex::encode(block),
            concat!(
                "f05c3d0a3d05b304f785ddc7d1e03601",
                "5c8aa76e2f217b06c6e1544c0bc1a90d",
                "f0accb9473c24e0fd54fea68057f4332",
                "9cb454761d6df5cf7b2e9b3614fbd5a2",
                "0b2e4760b40603540d82eabc5482c171",
                "c832afbe68406bc39500367a592943fa",
                "9a5b4a43286ca3c4cf46104b443143d5",
                "60a4b230488311df4feef7e1dfe8391e"
            )
        );
    }

    #[test]
    fn threefish_ctr_matches_manual_counter_increment_and_rejects_wrap() {
        let key = [0x3c_u8; 128];
        let mut iv = [0_u8; 128];
        for (index, byte) in iv[..112].iter_mut().enumerate() {
            *byte = (index as u8).wrapping_mul(11);
        }
        iv[127] = 0xff;

        let mut actual = [0_u8; 256];
        apply_threefish_ctr(&key, &iv, &mut actual).unwrap();

        let cipher = Threefish1024::new_with_tweak(&key, &[0_u8; 16]);
        let mut first = threefish::cipher::Block::<Threefish1024>::from(iv);
        cipher.encrypt_block(&mut first);
        let mut second_bytes = iv;
        second_bytes[126] = 0x01;
        second_bytes[127] = 0x00;
        let mut second = threefish::cipher::Block::<Threefish1024>::from(second_bytes);
        cipher.encrypt_block(&mut second);
        let mut expected = [0_u8; 256];
        expected[..128].copy_from_slice(&first);
        expected[128..].copy_from_slice(&second);
        assert_eq!(actual, expected);

        let mut maximum_iv = [0_u8; 128];
        maximum_iv[112..].fill(0xff);
        let mut too_long = [0_u8; 129];
        assert!(matches!(
            apply_threefish_ctr(&key, &maximum_iv, &mut too_long),
            Err(Error::Crypto("CTR counter would wrap"))
        ));
        assert_eq!(too_long, [0_u8; 129]);
    }

    #[test]
    fn rabbit_matches_rfc_4503_iv_vector() {
        let mut output = [0_u8; 48];
        apply_rabbit(&[0_u8; 16], &[0_u8; 8], &mut output).unwrap();
        assert_eq!(
            hex::encode(output),
            concat!(
                "edb70567375dcd7cd89554f85e27a7c6",
                "8d4adc7032298f7bd4eff504aca6295f",
                "668fbf478adb2be51e6cde292b82de2a"
            )
        );
    }

    #[test]
    fn hmac_sha512_matches_rfc_4231() {
        let key = [0x0b; 20];
        let mut mac = <HmacSha512 as HmacKeyInit>::new_from_slice(&key).unwrap();
        mac.update(b"Hi There");
        assert_eq!(
            hex::encode(mac.finalize().into_bytes()),
            concat!(
                "87aa7cdea5ef619d4ff0b4241a1d6cb0",
                "2379f4e2ce4ec2787ad0b30545e17cde",
                "daa833b7d6b8a702038b274eaea3f4e4",
                "be9d914eeb61f1702e696c203a126854"
            )
        );
    }

    #[test]
    fn aegis_128l_matches_draft_18_vector() {
        let key = hex::decode("10010000000000000000000000000000").unwrap();
        let nonce = hex::decode("10000200000000000000000000000000").unwrap();
        let aad = hex::decode("0001020304050607").unwrap();
        let plaintext =
            hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
                .unwrap();
        let key: &[u8; 16] = key.as_slice().try_into().unwrap();
        let nonce: &[u8; 16] = nonce.as_slice().try_into().unwrap();
        let (ciphertext, tag) = Aegis128L::<32>::new(key, nonce).encrypt(&plaintext, &aad);
        assert_eq!(
            hex::encode(ciphertext),
            "79d94593d8c2119d7e8fd9b8fc77845c5c077a05b2528b6ac54b563aed8efe84"
        );
        assert_eq!(
            hex::encode(tag),
            "022cb796fe7e0ae1197525ff67e309484cfbab6528ddef89f17d74ef8ecd82b3"
        );
    }

    #[test]
    fn aegis_256_matches_draft_18_vector() {
        let key = hex::decode("1001000000000000000000000000000000000000000000000000000000000000")
            .unwrap();
        let nonce = hex::decode("1000020000000000000000000000000000000000000000000000000000000000")
            .unwrap();
        let aad = hex::decode("0001020304050607").unwrap();
        let plaintext =
            hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
                .unwrap();
        let key: &[u8; 32] = key.as_slice().try_into().unwrap();
        let nonce: &[u8; 32] = nonce.as_slice().try_into().unwrap();
        let (ciphertext, tag) = Aegis256::<32>::new(key, nonce).encrypt(&plaintext, &aad);
        assert_eq!(
            hex::encode(ciphertext),
            "f373079ed84b2709faee373584585d60accd191db310ef5d8b11833df9dec711"
        );
        assert_eq!(
            hex::encode(tag),
            "b7d28d0c3c0ebd409fd22b44160503073a547412da0854bfb9723020dab8da1a"
        );
    }
}
