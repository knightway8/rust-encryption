use aead::{AeadInOut, KeyInit as AeadKeyInit};
use cipher::{
    BlockCipherEncrypt, BlockSizeUser, InnerIvInit, KeyInit, KeyIvInit, StreamCipher,
    StreamCipherCoreWrapper, consts::U16,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::{Error, Result, Suite};

const HMAC_DOMAIN: &[u8] = b"algos/envelope/v1/hmac";
type HmacSha256 = Hmac<Sha256>;

pub(crate) fn seal(
    suite: Suite,
    key: &[u8],
    mac_key: Option<&[u8; 32]>,
    nonce: &[u8],
    aad: &[u8],
    data: &mut [u8],
) -> Result<Vec<u8>> {
    if suite.is_native_aead() {
        return seal_native_aead(suite, key, nonce, aad, data);
    }
    apply_unauthenticated(suite, key, nonce, data)?;
    compute_hmac(mac_key.ok_or(Error::Crypto)?, nonce, aad, data)
}

pub(crate) fn open(
    suite: Suite,
    key: &[u8],
    mac_key: Option<&[u8; 32]>,
    nonce: &[u8],
    aad: &[u8],
    data: &mut [u8],
    tag: &[u8],
) -> Result<()> {
    if suite.is_native_aead() {
        return open_native_aead(suite, key, nonce, aad, data, tag);
    }
    verify_hmac(mac_key.ok_or(Error::Crypto)?, nonce, aad, data, tag)?;
    apply_unauthenticated(suite, key, nonce, data)
}

fn seal_native_aead(
    suite: Suite,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    data: &mut [u8],
) -> Result<Vec<u8>> {
    match suite {
        Suite::Aes128Gcm => aead_seal::<aes_gcm::Aes128Gcm>(key, nonce, aad, data),
        Suite::Aes256Gcm => aead_seal::<aes_gcm::Aes256Gcm>(key, nonce, aad, data),
        Suite::Aes128GcmSiv => aead_seal::<aes_gcm_siv::Aes128GcmSiv>(key, nonce, aad, data),
        Suite::Aes256GcmSiv => aead_seal::<aes_gcm_siv::Aes256GcmSiv>(key, nonce, aad, data),
        Suite::Aes128CmacSiv => aead_seal::<aes_siv::Aes128SivAead>(key, nonce, aad, data),
        Suite::Aes256CmacSiv => aead_seal::<aes_siv::Aes256SivAead>(key, nonce, aad, data),
        Suite::ChaCha20Poly1305 => {
            aead_seal::<chacha20poly1305::ChaCha20Poly1305>(key, nonce, aad, data)
        }
        Suite::XChaCha20Poly1305 => {
            aead_seal::<chacha20poly1305::XChaCha20Poly1305>(key, nonce, aad, data)
        }
        _ => Err(Error::Crypto),
    }
}

fn open_native_aead(
    suite: Suite,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    data: &mut [u8],
    tag: &[u8],
) -> Result<()> {
    match suite {
        Suite::Aes128Gcm => aead_open::<aes_gcm::Aes128Gcm>(key, nonce, aad, data, tag),
        Suite::Aes256Gcm => aead_open::<aes_gcm::Aes256Gcm>(key, nonce, aad, data, tag),
        Suite::Aes128GcmSiv => aead_open::<aes_gcm_siv::Aes128GcmSiv>(key, nonce, aad, data, tag),
        Suite::Aes256GcmSiv => aead_open::<aes_gcm_siv::Aes256GcmSiv>(key, nonce, aad, data, tag),
        Suite::Aes128CmacSiv => aead_open::<aes_siv::Aes128SivAead>(key, nonce, aad, data, tag),
        Suite::Aes256CmacSiv => aead_open::<aes_siv::Aes256SivAead>(key, nonce, aad, data, tag),
        Suite::ChaCha20Poly1305 => {
            aead_open::<chacha20poly1305::ChaCha20Poly1305>(key, nonce, aad, data, tag)
        }
        Suite::XChaCha20Poly1305 => {
            aead_open::<chacha20poly1305::XChaCha20Poly1305>(key, nonce, aad, data, tag)
        }
        _ => Err(Error::Crypto),
    }
}

fn aead_seal<C>(key: &[u8], nonce: &[u8], aad: &[u8], data: &mut [u8]) -> Result<Vec<u8>>
where
    C: AeadInOut + AeadKeyInit,
{
    let cipher = C::new_from_slice(key).map_err(|_| Error::Crypto)?;
    let nonce = aead::Nonce::<C>::try_from(nonce).map_err(|_| Error::Crypto)?;
    cipher
        .encrypt_inout_detached(&nonce, aad, data.into())
        .map(|tag| tag.to_vec())
        .map_err(|_| Error::Crypto)
}

fn aead_open<C>(key: &[u8], nonce: &[u8], aad: &[u8], data: &mut [u8], tag: &[u8]) -> Result<()>
where
    C: AeadInOut + AeadKeyInit,
{
    let cipher = C::new_from_slice(key).map_err(|_| Error::Crypto)?;
    let nonce = aead::Nonce::<C>::try_from(nonce).map_err(|_| Error::Authentication)?;
    let tag = aead::Tag::<C>::try_from(tag).map_err(|_| Error::Authentication)?;
    cipher
        .decrypt_inout_detached(&nonce, aad, data.into(), &tag)
        .map_err(|_| Error::Authentication)
}

fn apply_unauthenticated(suite: Suite, key: &[u8], nonce: &[u8], data: &mut [u8]) -> Result<()> {
    match suite {
        Suite::Aes128CtrHmac => ctr128::<aes::Aes128>(key, nonce, data),
        Suite::Aes192CtrHmac => ctr128::<aes::Aes192>(key, nonce, data),
        Suite::Aes256CtrHmac => ctr128::<aes::Aes256>(key, nonce, data),
        Suite::Camellia128CtrHmac => ctr128::<camellia::Camellia128>(key, nonce, data),
        Suite::Camellia192CtrHmac => ctr128::<camellia::Camellia192>(key, nonce, data),
        Suite::Camellia256CtrHmac => ctr128::<camellia::Camellia256>(key, nonce, data),
        Suite::Aria128CtrHmac => ctr128::<aria::Aria128>(key, nonce, data),
        Suite::Aria192CtrHmac => ctr128::<aria::Aria192>(key, nonce, data),
        Suite::Aria256CtrHmac => ctr128::<aria::Aria256>(key, nonce, data),
        Suite::Twofish128CtrHmac | Suite::Twofish192CtrHmac | Suite::Twofish256CtrHmac => {
            ctr128::<twofish::Twofish>(key, nonce, data)
        }
        Suite::Serpent128CtrHmac | Suite::Serpent192CtrHmac | Suite::Serpent256CtrHmac => {
            ctr128::<serpent::Serpent>(key, nonce, data)
        }
        Suite::Sm4CtrHmac => ctr128::<sm4::Sm4>(key, nonce, data),
        Suite::KuznyechikCtrHmac => ctr128::<kuznyechik::Kuznyechik>(key, nonce, data),
        Suite::Cast6CtrHmac => ctr128::<cast6::Cast6>(key, nonce, data),
        Suite::BeltCtrHmac => stream::<belt_ctr::BeltCtr>(key, nonce, data),
        Suite::Salsa20Hmac => stream::<salsa20::Salsa20>(key, nonce, data),
        Suite::XSalsa20Hmac => stream::<salsa20::XSalsa20>(key, nonce, data),
        Suite::Hc256Hmac => stream::<hc_256::Hc256>(key, nonce, data),
        _ => Err(Error::Crypto),
    }
}

fn ctr128<C>(key: &[u8], iv: &[u8], data: &mut [u8]) -> Result<()>
where
    C: BlockCipherEncrypt + BlockSizeUser<BlockSize = U16> + KeyInit,
{
    type Core<C> = ctr::CtrCore<C, ctr::flavors::Ctr128BE>;
    let inner = C::new_from_slice(key).map_err(|_| Error::Crypto)?;
    let iv = cipher::Iv::<Core<C>>::try_from(iv).map_err(|_| Error::Crypto)?;
    let core = Core::<C>::inner_iv_init(inner, &iv);
    let mut cipher = StreamCipherCoreWrapper::from_core(core);
    cipher
        .try_apply_keystream(data)
        .map_err(|_| Error::FileTooLarge)
}

fn stream<C>(key: &[u8], iv: &[u8], data: &mut [u8]) -> Result<()>
where
    C: KeyIvInit + StreamCipher,
{
    let mut cipher = C::new_from_slices(key, iv).map_err(|_| Error::Crypto)?;
    cipher
        .try_apply_keystream(data)
        .map_err(|_| Error::FileTooLarge)
}

fn compute_hmac(key: &[u8; 32], nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let mut mac = <HmacSha256 as hmac::KeyInit>::new_from_slice(key).map_err(|_| Error::Crypto)?;
    update_hmac(&mut mac, nonce, aad, ciphertext)?;
    Ok(mac.finalize().into_bytes().to_vec())
}

fn verify_hmac(
    key: &[u8; 32],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<()> {
    let mut mac = <HmacSha256 as hmac::KeyInit>::new_from_slice(key).map_err(|_| Error::Crypto)?;
    update_hmac(&mut mac, nonce, aad, ciphertext)?;
    mac.verify_slice(tag).map_err(|_| Error::Authentication)
}

fn update_hmac(mac: &mut HmacSha256, nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<()> {
    let nonce_len = u8::try_from(nonce.len()).map_err(|_| Error::Crypto)?;
    mac.update(HMAC_DOMAIN);
    mac.update(aad);
    mac.update(&[nonce_len]);
    mac.update(nonce);
    mac.update(ciphertext);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ALL_SUITES;
    use hex_literal::hex;

    /// Independently spells out the native AEAD adapter expected for each
    /// stable suite variant. This deliberate duplication catches an adapter
    /// swap even if production encryption and decryption still round-trip.
    fn seal_with_expected_native_adapter(
        suite: Suite,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        data: &mut [u8],
    ) -> Result<Vec<u8>> {
        match suite {
            Suite::Aes128Gcm => aead_seal::<aes_gcm::Aes128Gcm>(key, nonce, aad, data),
            Suite::Aes256Gcm => aead_seal::<aes_gcm::Aes256Gcm>(key, nonce, aad, data),
            Suite::Aes128GcmSiv => aead_seal::<aes_gcm_siv::Aes128GcmSiv>(key, nonce, aad, data),
            Suite::Aes256GcmSiv => aead_seal::<aes_gcm_siv::Aes256GcmSiv>(key, nonce, aad, data),
            Suite::Aes128CmacSiv => aead_seal::<aes_siv::Aes128SivAead>(key, nonce, aad, data),
            Suite::Aes256CmacSiv => aead_seal::<aes_siv::Aes256SivAead>(key, nonce, aad, data),
            Suite::ChaCha20Poly1305 => {
                aead_seal::<chacha20poly1305::ChaCha20Poly1305>(key, nonce, aad, data)
            }
            Suite::XChaCha20Poly1305 => {
                aead_seal::<chacha20poly1305::XChaCha20Poly1305>(key, nonce, aad, data)
            }
            _ => Err(Error::Crypto),
        }
    }

    fn apply_expected_unauthenticated_adapter(
        suite: Suite,
        key: &[u8],
        nonce: &[u8],
        data: &mut [u8],
    ) -> Result<()> {
        match suite {
            Suite::Aes128CtrHmac => ctr128::<aes::Aes128>(key, nonce, data),
            Suite::Aes192CtrHmac => ctr128::<aes::Aes192>(key, nonce, data),
            Suite::Aes256CtrHmac => ctr128::<aes::Aes256>(key, nonce, data),
            Suite::Camellia128CtrHmac => ctr128::<camellia::Camellia128>(key, nonce, data),
            Suite::Camellia192CtrHmac => ctr128::<camellia::Camellia192>(key, nonce, data),
            Suite::Camellia256CtrHmac => ctr128::<camellia::Camellia256>(key, nonce, data),
            Suite::Aria128CtrHmac => ctr128::<aria::Aria128>(key, nonce, data),
            Suite::Aria192CtrHmac => ctr128::<aria::Aria192>(key, nonce, data),
            Suite::Aria256CtrHmac => ctr128::<aria::Aria256>(key, nonce, data),
            Suite::Twofish128CtrHmac | Suite::Twofish192CtrHmac | Suite::Twofish256CtrHmac => {
                ctr128::<twofish::Twofish>(key, nonce, data)
            }
            Suite::Serpent128CtrHmac | Suite::Serpent192CtrHmac | Suite::Serpent256CtrHmac => {
                ctr128::<serpent::Serpent>(key, nonce, data)
            }
            Suite::Sm4CtrHmac => ctr128::<sm4::Sm4>(key, nonce, data),
            Suite::KuznyechikCtrHmac => ctr128::<kuznyechik::Kuznyechik>(key, nonce, data),
            Suite::Cast6CtrHmac => ctr128::<cast6::Cast6>(key, nonce, data),
            Suite::BeltCtrHmac => stream::<belt_ctr::BeltCtr>(key, nonce, data),
            Suite::Salsa20Hmac => stream::<salsa20::Salsa20>(key, nonce, data),
            Suite::XSalsa20Hmac => stream::<salsa20::XSalsa20>(key, nonce, data),
            Suite::Hc256Hmac => stream::<hc_256::Hc256>(key, nonce, data),
            _ => Err(Error::Crypto),
        }
    }

    fn seal_with_expected_adapter(
        suite: Suite,
        key: &[u8],
        mac_key: &[u8; 32],
        nonce: &[u8],
        aad: &[u8],
        data: &mut [u8],
    ) -> Result<Vec<u8>> {
        if suite.is_native_aead() {
            seal_with_expected_native_adapter(suite, key, nonce, aad, data)
        } else {
            apply_expected_unauthenticated_adapter(suite, key, nonce, data)?;
            compute_hmac(mac_key, nonce, aad, data)
        }
    }

    fn assert_production_aes_siv_vector(
        suite: Suite,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        expected_tag: &[u8; 16],
        expected_ciphertext: &[u8],
    ) {
        let mut ciphertext = plaintext.to_vec();
        let tag = seal(suite, key, None, nonce, aad, &mut ciphertext).unwrap();
        assert_eq!(tag, expected_tag);
        assert_eq!(ciphertext, expected_ciphertext);

        open(suite, key, None, nonce, aad, &mut ciphertext, &tag).unwrap();
        assert_eq!(ciphertext, plaintext);
    }

    #[test]
    fn aes128_cmac_siv_production_path_matches_rfc5297_a2() {
        // RFC output is SIV/tag || ciphertext. The production record API
        // returns those two parts separately.
        let key = hex!("7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f");
        let nonce = hex!("09f911029d74e35bd84156c5635688c0");
        let aad = hex!(
            "00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100"
        );
        let plaintext = hex!(
            "7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67205349562d414553"
        );
        let tag = hex!("85825e22e90cf2ddda2c548dc7c1b631");
        let ciphertext = hex!(
            "0dcdaca0cebf9dc6cb90583f5bf1506e02cd48832b00e4e598b2b22a53e6199d4df0c1666a35a0433b250dc134d776"
        );

        assert_production_aes_siv_vector(
            Suite::Aes128CmacSiv,
            &key,
            &nonce,
            &aad,
            &plaintext,
            &tag,
            &ciphertext,
        );
    }

    #[test]
    fn every_suite_id_selects_its_intended_production_adapter() {
        for id in 1_u16..=30 {
            let suite = Suite::from_id(id).expect("stable suite ID must exist");
            let id_byte = u8::try_from(id).expect("stable suite IDs fit in one byte");
            let key = (0..suite.key_len())
                .map(|offset| {
                    u8::try_from(offset)
                        .expect("suite keys are at most 64 bytes")
                        .wrapping_add(id_byte)
                })
                .collect::<Vec<_>>();
            let mac_key = [0x80_u8.wrapping_add(id_byte); 32];
            let nonce = (0..suite.nonce_len())
                .map(|offset| {
                    0xf0_u8
                        .wrapping_sub(
                            u8::try_from(offset).expect("suite nonces are at most 32 bytes"),
                        )
                        .wrapping_add(id_byte)
                })
                .collect::<Vec<_>>();
            let aad = [
                b"production adapter binding: ".as_slice(),
                &id.to_le_bytes(),
            ]
            .concat();
            let plaintext = (0_u8..=47).map(|byte| byte ^ id_byte).collect::<Vec<_>>();

            let mut expected_ciphertext = plaintext.clone();
            let expected_tag = seal_with_expected_adapter(
                suite,
                &key,
                &mac_key,
                &nonce,
                &aad,
                &mut expected_ciphertext,
            )
            .unwrap_or_else(|error| panic!("{} expected adapter: {error}", suite.name()));

            let mut production_ciphertext = plaintext.clone();
            let production_tag = seal(
                suite,
                &key,
                Some(&mac_key),
                &nonce,
                &aad,
                &mut production_ciphertext,
            )
            .unwrap_or_else(|error| panic!("{} production adapter: {error}", suite.name()));

            assert_eq!(
                production_ciphertext,
                expected_ciphertext,
                "{}",
                suite.name()
            );
            assert_eq!(production_tag, expected_tag, "{}", suite.name());
            open(
                suite,
                &key,
                Some(&mac_key),
                &nonce,
                &aad,
                &mut production_ciphertext,
                &production_tag,
            )
            .unwrap_or_else(|error| panic!("{} production open: {error}", suite.name()));
            assert_eq!(production_ciphertext, plaintext, "{}", suite.name());
        }
    }

    #[test]
    fn aes256_cmac_siv_production_path_matches_fixed_aead_vector() {
        let key = hex!(
            "000102030405060708090a0b0c0d0e0f"
            "101112131415161718191a1b1c1d1e1f"
            "202122232425262728292a2b2c2d2e2f"
            "303132333435363738393a3b3c3d3e3f"
        );
        let nonce = hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let aad = b"production adapter aad";
        let plaintext = b"AES-256-CMAC-SIV production adapter";
        let tag = hex!("07ba56b15c626be1f25fbe417315ca23");
        let ciphertext =
            hex!("35b50c5bef26ecc15f54c154dcd24198a2488cb6d3f2280097e6b8a4f795ada9323638");

        assert_production_aes_siv_vector(
            Suite::Aes256CmacSiv,
            &key,
            &nonce,
            aad,
            plaintext,
            &tag,
            &ciphertext,
        );
    }

    #[test]
    fn every_adapter_round_trips_and_rejects_tampering() {
        for suite in ALL_SUITES {
            let key = vec![0x11; suite.key_len()];
            let mac_key = [0x22; 32];
            let nonce = vec![0x33; suite.nonce_len()];
            let aad = b"adapter test aad";
            let plaintext = (0_u8..=255).collect::<Vec<_>>();
            let mut ciphertext = plaintext.clone();
            let tag = seal(suite, &key, Some(&mac_key), &nonce, aad, &mut ciphertext)
                .unwrap_or_else(|error| panic!("{}: {error}", suite.name()));
            assert_ne!(ciphertext, plaintext, "{}", suite.name());
            open(
                suite,
                &key,
                Some(&mac_key),
                &nonce,
                aad,
                &mut ciphertext,
                &tag,
            )
            .unwrap_or_else(|error| panic!("{}: {error}", suite.name()));
            assert_eq!(ciphertext, plaintext, "{}", suite.name());

            let mut damaged_tag = tag;
            damaged_tag[0] ^= 1;
            let mut damaged_data = plaintext.clone();
            assert!(
                open(
                    suite,
                    &key,
                    Some(&mac_key),
                    &nonce,
                    aad,
                    &mut damaged_data,
                    &damaged_tag,
                )
                .is_err(),
                "{}",
                suite.name()
            );
        }
    }
}
