use super::CHUNK_SIZE;
use super::format::{Header, chunk_aad, chunk_count, chunk_nonce, chunk_plaintext_len};
use crate::Algorithm;
use aes_gcm_siv::aead::{Aead as Aead05, KeyInit as KeyInit05, Payload as Payload05};
use anyhow::{Context, Result, anyhow, bail};
use ascon_aead::aead::{Aead as Aead06, KeyInit as KeyInit06, Payload as Payload06};
use std::io::{Read, Write};
use zeroize::Zeroizing;

pub(super) fn encrypt(
    reader: &mut impl Read,
    writer: &mut impl Write,
    algorithm: Algorithm,
    key: &[u8],
    header: &Header,
) -> Result<()> {
    let chunks = chunk_count(header.plaintext_len, CHUNK_SIZE);
    for index in 0..chunks {
        let plaintext_len = chunk_plaintext_len(header.plaintext_len, CHUNK_SIZE, index);
        let mut plaintext = Zeroizing::new(vec![0_u8; plaintext_len]);
        reader
            .read_exact(&mut plaintext)
            .with_context(|| format!("input ended while reading plaintext chunk {index}"))?;

        let is_final = index + 1 == chunks;
        let aad = chunk_aad(header, index, plaintext_len, is_final);
        let nonce = chunk_nonce(&header.nonce_seed, algorithm.nonce_len(), index);
        let ciphertext = encrypt_chunk(algorithm, key, &nonce, &aad, &plaintext)
            .with_context(|| format!("failed to encrypt chunk {index}"))?;
        writer
            .write_all(&ciphertext)
            .with_context(|| format!("failed to write encrypted chunk {index}"))?;
    }
    Ok(())
}

pub(super) fn decrypt(
    reader: &mut impl Read,
    writer: &mut impl Write,
    algorithm: Algorithm,
    key: &[u8],
    header: &Header,
) -> Result<()> {
    let chunks = chunk_count(header.plaintext_len, CHUNK_SIZE);
    for index in 0..chunks {
        let plaintext_len = chunk_plaintext_len(header.plaintext_len, CHUNK_SIZE, index);
        let record_len = plaintext_len
            .checked_add(algorithm.tag_len())
            .context("encrypted chunk length overflows")?;
        let mut ciphertext = vec![0_u8; record_len];
        reader
            .read_exact(&mut ciphertext)
            .with_context(|| format!("encrypted file ended in chunk {index}"))?;

        let is_final = index + 1 == chunks;
        let aad = chunk_aad(header, index, plaintext_len, is_final);
        let nonce = chunk_nonce(&header.nonce_seed, algorithm.nonce_len(), index);
        let plaintext = Zeroizing::new(
            decrypt_chunk(algorithm, key, &nonce, &aad, ciphertext).with_context(|| {
                format!(
                    "authentication failed in chunk {index}: wrong key or damaged encrypted file"
                )
            })?,
        );
        if plaintext.len() != plaintext_len {
            bail!("cipher returned an unexpected plaintext length");
        }
        writer
            .write_all(&plaintext)
            .with_context(|| format!("failed to write decrypted chunk {index}"))?;
    }
    Ok(())
}

fn encrypt_chunk(
    algorithm: Algorithm,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    match algorithm {
        Algorithm::Aes256GcmSiv => {
            let cipher = <aes_gcm_siv::Aes256GcmSiv as KeyInit05>::new_from_slice(key)
                .map_err(|_| anyhow!("invalid AES-256 key length"))?;
            Aead05::encrypt(
                &cipher,
                aes_gcm_siv::Nonce::from_slice(nonce),
                Payload05 {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| anyhow!("AES-256-GCM-SIV encryption failed"))
        }
        Algorithm::XChaCha20Poly1305 => {
            let cipher = <chacha20poly1305::XChaCha20Poly1305 as KeyInit05>::new_from_slice(key)
                .map_err(|_| anyhow!("invalid XChaCha20 key length"))?;
            Aead05::encrypt(
                &cipher,
                chacha20poly1305::XNonce::from_slice(nonce),
                Payload05 {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| anyhow!("XChaCha20-Poly1305 encryption failed"))
        }
        Algorithm::AsconAead128 => {
            let cipher = <ascon_aead::AsconAead128 as KeyInit06>::new_from_slice(key)
                .map_err(|_| anyhow!("invalid Ascon key length"))?;
            let nonce: &ascon_aead::AsconAead128Nonce = nonce
                .try_into()
                .map_err(|_| anyhow!("invalid Ascon nonce length"))?;
            Aead06::encrypt(
                &cipher,
                nonce,
                Payload06 {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| anyhow!("Ascon-AEAD128 encryption failed"))
        }
        Algorithm::Aegis256 => {
            let key: &[u8; 32] = key
                .try_into()
                .map_err(|_| anyhow!("invalid AEGIS-256 key length"))?;
            let nonce: &[u8; 32] = nonce
                .try_into()
                .map_err(|_| anyhow!("invalid AEGIS-256 nonce length"))?;
            let mut output = plaintext.to_vec();
            let tag =
                aegis::aegis256::Aegis256::<16>::new(key, nonce).encrypt_in_place(&mut output, aad);
            output.extend_from_slice(&tag);
            Ok(output)
        }
        Algorithm::Aegis128L => {
            let key: &[u8; 16] = key
                .try_into()
                .map_err(|_| anyhow!("invalid AEGIS-128L key length"))?;
            let nonce: &[u8; 16] = nonce
                .try_into()
                .map_err(|_| anyhow!("invalid AEGIS-128L nonce length"))?;
            let mut output = plaintext.to_vec();
            let tag = aegis::aegis128l::Aegis128L::<16>::new(key, nonce)
                .encrypt_in_place(&mut output, aad);
            output.extend_from_slice(&tag);
            Ok(output)
        }
        Algorithm::Serpent256 | Algorithm::Threefish1024 | Algorithm::Rabbit => {
            bail!("internal error: non-AEAD cipher passed to AEAD encryption")
        }
    }
}

fn decrypt_chunk(
    algorithm: Algorithm,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    mut ciphertext: Vec<u8>,
) -> Result<Vec<u8>> {
    match algorithm {
        Algorithm::Aes256GcmSiv => {
            let cipher = <aes_gcm_siv::Aes256GcmSiv as KeyInit05>::new_from_slice(key)
                .map_err(|_| anyhow!("invalid AES-256 key length"))?;
            Aead05::decrypt(
                &cipher,
                aes_gcm_siv::Nonce::from_slice(nonce),
                Payload05 {
                    msg: &ciphertext,
                    aad,
                },
            )
            .map_err(|_| anyhow!("authentication failed"))
        }
        Algorithm::XChaCha20Poly1305 => {
            let cipher = <chacha20poly1305::XChaCha20Poly1305 as KeyInit05>::new_from_slice(key)
                .map_err(|_| anyhow!("invalid XChaCha20 key length"))?;
            Aead05::decrypt(
                &cipher,
                chacha20poly1305::XNonce::from_slice(nonce),
                Payload05 {
                    msg: &ciphertext,
                    aad,
                },
            )
            .map_err(|_| anyhow!("authentication failed"))
        }
        Algorithm::AsconAead128 => {
            let cipher = <ascon_aead::AsconAead128 as KeyInit06>::new_from_slice(key)
                .map_err(|_| anyhow!("invalid Ascon key length"))?;
            let nonce: &ascon_aead::AsconAead128Nonce = nonce
                .try_into()
                .map_err(|_| anyhow!("invalid Ascon nonce length"))?;
            Aead06::decrypt(
                &cipher,
                nonce,
                Payload06 {
                    msg: &ciphertext,
                    aad,
                },
            )
            .map_err(|_| anyhow!("authentication failed"))
        }
        Algorithm::Aegis256 => {
            let key: &[u8; 32] = key
                .try_into()
                .map_err(|_| anyhow!("invalid AEGIS-256 key length"))?;
            let nonce: &[u8; 32] = nonce
                .try_into()
                .map_err(|_| anyhow!("invalid AEGIS-256 nonce length"))?;
            let split = ciphertext
                .len()
                .checked_sub(16)
                .context("AEGIS-256 ciphertext is shorter than its tag")?;
            let mut tag = [0_u8; 16];
            tag.copy_from_slice(&ciphertext[split..]);
            ciphertext.truncate(split);
            aegis::aegis256::Aegis256::<16>::new(key, nonce)
                .decrypt_in_place(&mut ciphertext, &tag, aad)
                .map_err(|_| anyhow!("authentication failed"))?;
            Ok(ciphertext)
        }
        Algorithm::Aegis128L => {
            let key: &[u8; 16] = key
                .try_into()
                .map_err(|_| anyhow!("invalid AEGIS-128L key length"))?;
            let nonce: &[u8; 16] = nonce
                .try_into()
                .map_err(|_| anyhow!("invalid AEGIS-128L nonce length"))?;
            let split = ciphertext
                .len()
                .checked_sub(16)
                .context("AEGIS-128L ciphertext is shorter than its tag")?;
            let mut tag = [0_u8; 16];
            tag.copy_from_slice(&ciphertext[split..]);
            ciphertext.truncate(split);
            aegis::aegis128l::Aegis128L::<16>::new(key, nonce)
                .decrypt_in_place(&mut ciphertext, &tag, aad)
                .map_err(|_| anyhow!("authentication failed"))?;
            Ok(ciphertext)
        }
        Algorithm::Serpent256 | Algorithm::Threefish1024 | Algorithm::Rabbit => {
            bail!("internal error: non-AEAD cipher passed to AEAD decryption")
        }
    }
}
