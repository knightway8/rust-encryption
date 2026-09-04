use super::CHUNK_SIZE;
use super::format::{HEADER_LEN, Header};
use crate::Algorithm;
use anyhow::{Context, Result, anyhow, bail};
use cipher::{BlockCipherEncrypt, KeyInit, KeyIvInit, StreamCipher};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha512;
use std::io::{Read, Seek, SeekFrom, Write};
use zeroize::{Zeroize, Zeroizing};

type HmacSha512 = Hmac<Sha512>;

pub(super) fn encrypt(
    reader: &mut impl Read,
    writer: &mut impl Write,
    algorithm: Algorithm,
    master_key: &[u8],
    header: &Header,
) -> Result<()> {
    let (mut engine, mac_key) = derive_engine_and_mac(algorithm, master_key, &header.nonce_seed)?;
    let mut mac = <HmacSha512 as Mac>::new_from_slice(&*mac_key)
        .map_err(|_| anyhow!("could not initialize HMAC-SHA-512"))?;
    mac.update(header.bytes());

    let mut remaining = header.plaintext_len;
    let mut buffer = Zeroizing::new(vec![0_u8; CHUNK_SIZE]);
    while remaining != 0 {
        let length = usize::try_from(remaining.min(CHUNK_SIZE as u64))
            .context("chunk length does not fit this platform")?;
        reader
            .read_exact(&mut buffer[..length])
            .context("input ended during legacy cipher encryption")?;
        engine.apply_keystream(&mut buffer[..length])?;
        mac.update(&buffer[..length]);
        writer
            .write_all(&buffer[..length])
            .context("cannot write legacy cipher ciphertext")?;
        remaining -= length as u64;
    }

    let tag = mac.finalize().into_bytes();
    writer
        .write_all(&tag)
        .context("cannot write legacy cipher authentication tag")
}

pub(super) fn decrypt(
    reader: &mut (impl Read + Seek),
    writer: &mut impl Write,
    algorithm: Algorithm,
    master_key: &[u8],
    header: &Header,
) -> Result<()> {
    let (mut engine, mac_key) = derive_engine_and_mac(algorithm, master_key, &header.nonce_seed)?;
    let mut buffer = Zeroizing::new(vec![0_u8; CHUNK_SIZE]);

    // Authenticate the complete file before decrypting any plaintext.
    let mut first_mac = <HmacSha512 as Mac>::new_from_slice(&*mac_key)
        .map_err(|_| anyhow!("could not initialize HMAC-SHA-512"))?;
    first_mac.update(header.bytes());
    let mut remaining = header.plaintext_len;
    while remaining != 0 {
        let length = usize::try_from(remaining.min(CHUNK_SIZE as u64))
            .context("chunk length does not fit this platform")?;
        reader
            .read_exact(&mut buffer[..length])
            .context("encrypted file ended during authentication")?;
        first_mac.update(&buffer[..length]);
        remaining -= length as u64;
    }
    let mut stored_tag = [0_u8; 64];
    reader
        .read_exact(&mut stored_tag)
        .context("encrypted file is missing its authentication tag")?;
    first_mac
        .verify_slice(&stored_tag)
        .map_err(|_| anyhow!("authentication failed: wrong key or damaged encrypted file"))?;
    stored_tag.zeroize();

    reader
        .seek(SeekFrom::Start(HEADER_LEN as u64))
        .context("cannot rewind authenticated encrypted file")?;

    // Authenticate again while decrypting so a concurrent file change is also
    // detected before the private temporary output is installed.
    let mut second_mac = <HmacSha512 as Mac>::new_from_slice(&*mac_key)
        .map_err(|_| anyhow!("could not initialize HMAC-SHA-512"))?;
    second_mac.update(header.bytes());
    remaining = header.plaintext_len;
    while remaining != 0 {
        let length = usize::try_from(remaining.min(CHUNK_SIZE as u64))
            .context("chunk length does not fit this platform")?;
        reader
            .read_exact(&mut buffer[..length])
            .context("encrypted file changed during decryption")?;
        second_mac.update(&buffer[..length]);
        engine.apply_keystream(&mut buffer[..length])?;
        writer
            .write_all(&buffer[..length])
            .context("cannot write legacy cipher plaintext")?;
        buffer[..length].zeroize();
        remaining -= length as u64;
    }
    reader
        .read_exact(&mut stored_tag)
        .context("encrypted file changed during decryption")?;
    second_mac
        .verify_slice(&stored_tag)
        .map_err(|_| anyhow!("encrypted file changed during decryption"))?;
    stored_tag.zeroize();
    Ok(())
}

enum LegacyEngine {
    Serpent {
        cipher: Box<serpent::Serpent>,
        counter: u128,
    },
    Threefish {
        cipher: Box<threefish::Threefish1024>,
        counter: u128,
    },
    Rabbit(rabbit::Rabbit),
}

impl LegacyEngine {
    fn apply_keystream(&mut self, data: &mut [u8]) -> Result<()> {
        match self {
            Self::Serpent { cipher, counter } => {
                for chunk in data.chunks_mut(16) {
                    let mut block = cipher::Block::<serpent::Serpent>::default();
                    block.copy_from_slice(&counter.to_be_bytes());
                    cipher.encrypt_block(&mut block);
                    for (byte, mask) in chunk.iter_mut().zip(block.iter()) {
                        *byte ^= mask;
                    }
                    *counter = counter
                        .checked_add(1)
                        .context("Serpent-CTR counter exhausted")?;
                }
                Ok(())
            }
            Self::Threefish { cipher, counter } => {
                for chunk in data.chunks_mut(128) {
                    let mut block = cipher::Block::<threefish::Threefish1024>::default();
                    block[112..].copy_from_slice(&counter.to_be_bytes());
                    cipher.encrypt_block(&mut block);
                    for (byte, mask) in chunk.iter_mut().zip(block.iter()) {
                        *byte ^= mask;
                    }
                    *counter = counter
                        .checked_add(1)
                        .context("Threefish-CTR counter exhausted")?;
                }
                Ok(())
            }
            Self::Rabbit(cipher) => {
                cipher.apply_keystream(data);
                Ok(())
            }
        }
    }
}

fn derive_engine_and_mac(
    algorithm: Algorithm,
    master_key: &[u8],
    salt: &[u8; 32],
) -> Result<(LegacyEngine, Zeroizing<[u8; 64]>)> {
    let hkdf = Hkdf::<Sha512>::new(Some(salt), master_key);
    match algorithm {
        Algorithm::Serpent256 => {
            let mut material = Zeroizing::new([0_u8; 96]);
            hkdf.expand(b"x3x/v1/serpent-256-ctr/hmac-sha-512", &mut *material)
                .map_err(|_| anyhow!("Serpent key derivation failed"))?;
            let cipher = <serpent::Serpent as KeyInit>::new_from_slice(&material[..32])
                .map_err(|_| anyhow!("could not initialize Serpent-256"))?;
            let mut mac_key = Zeroizing::new([0_u8; 64]);
            mac_key.copy_from_slice(&material[32..]);
            Ok((
                LegacyEngine::Serpent {
                    cipher: Box::new(cipher),
                    counter: 0,
                },
                mac_key,
            ))
        }
        Algorithm::Threefish1024 => {
            let mut material = Zeroizing::new([0_u8; 208]);
            hkdf.expand(b"x3x/v1/threefish-1024-ctr/hmac-sha-512", &mut *material)
                .map_err(|_| anyhow!("Threefish key derivation failed"))?;
            let encryption_key: &[u8; 128] = material[..128]
                .try_into()
                .expect("fixed Threefish key slice");
            let tweak: &[u8; 16] = material[128..144]
                .try_into()
                .expect("fixed Threefish tweak slice");
            let cipher = threefish::Threefish1024::new_with_tweak(encryption_key, tweak);
            let mut mac_key = Zeroizing::new([0_u8; 64]);
            mac_key.copy_from_slice(&material[144..]);
            Ok((
                LegacyEngine::Threefish {
                    cipher: Box::new(cipher),
                    counter: 0,
                },
                mac_key,
            ))
        }
        Algorithm::Rabbit => {
            let mut material = Zeroizing::new([0_u8; 88]);
            hkdf.expand(b"x3x/v1/rabbit/hmac-sha-512", &mut *material)
                .map_err(|_| anyhow!("Rabbit key derivation failed"))?;
            let cipher =
                <rabbit::Rabbit as KeyIvInit>::new_from_slices(&material[..16], &material[16..24])
                    .map_err(|_| anyhow!("could not initialize Rabbit"))?;
            let mut mac_key = Zeroizing::new([0_u8; 64]);
            mac_key.copy_from_slice(&material[24..]);
            Ok((LegacyEngine::Rabbit(cipher), mac_key))
        }
        Algorithm::Aes256GcmSiv
        | Algorithm::XChaCha20Poly1305
        | Algorithm::AsconAead128
        | Algorithm::Aegis256
        | Algorithm::Aegis128L => {
            bail!("internal error: AEAD cipher passed to legacy construction")
        }
    }
}
