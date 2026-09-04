use super::password::{KDF_ID_ARGON2ID, PasswordKdf};
use crate::Algorithm;
use anyhow::{Result, bail};

pub(super) const HEADER_LEN: usize = 64;
const MAGIC: &[u8; 8] = b"X3XCRYPT";
const KEY_FILE_FORMAT_VERSION: u8 = 1;
const PASSWORD_FORMAT_VERSION: u8 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Keying {
    KeyFile,
    Password(PasswordKdf),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ExpectedKeying {
    KeyFile,
    Password,
}

#[derive(Clone)]
pub(super) struct Header {
    bytes: [u8; HEADER_LEN],
    pub(super) plaintext_len: u64,
    pub(super) nonce_seed: [u8; 32],
    pub(super) keying: Keying,
}

impl Header {
    pub(super) fn new(
        algorithm: Algorithm,
        plaintext_len: u64,
        nonce_seed: [u8; 32],
        chunk_size: usize,
        keying: Keying,
    ) -> Self {
        let mut bytes = [0_u8; HEADER_LEN];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8] = match keying {
            Keying::KeyFile => KEY_FILE_FORMAT_VERSION,
            Keying::Password(parameters) => {
                bytes[56..60].copy_from_slice(&parameters.memory_kib.to_le_bytes());
                bytes[60..62].copy_from_slice(&parameters.iterations.to_le_bytes());
                bytes[62] = parameters.lanes;
                bytes[63] = KDF_ID_ARGON2ID;
                PASSWORD_FORMAT_VERSION
            }
        };
        bytes[9] = algorithm.id();
        bytes[10] = u8::try_from(algorithm.tag_len()).expect("tag length fits in u8");
        bytes[11] = u8::try_from(algorithm.nonce_len()).expect("nonce length fits in u8");
        bytes[12..16].copy_from_slice(
            &u32::try_from(chunk_size)
                .expect("chunk size fits in u32")
                .to_le_bytes(),
        );
        bytes[16..24].copy_from_slice(&plaintext_len.to_le_bytes());
        bytes[24..56].copy_from_slice(&nonce_seed);
        Self {
            bytes,
            plaintext_len,
            nonce_seed,
            keying,
        }
    }

    pub(super) fn parse(
        bytes: [u8; HEADER_LEN],
        expected_algorithm: Algorithm,
        expected_chunk_size: usize,
        expected_keying: ExpectedKeying,
    ) -> Result<Self> {
        if &bytes[..8] != MAGIC {
            bail!("input is not an x3x encrypted file");
        }
        let actual_algorithm = Algorithm::from_id(bytes[9])?;
        if actual_algorithm != expected_algorithm {
            bail!(
                "file uses {actual_algorithm}, not {expected_algorithm}; use the matching binary"
            );
        }
        let keying = match bytes[8] {
            KEY_FILE_FORMAT_VERSION => {
                if expected_keying == ExpectedKeying::Password {
                    bail!(
                        "file uses a key file; use the '{}' binary",
                        expected_algorithm.command()
                    );
                }
                if bytes[56..].iter().any(|byte| *byte != 0) {
                    bail!("encrypted file header has nonzero reserved bytes");
                }
                Keying::KeyFile
            }
            PASSWORD_FORMAT_VERSION => {
                if expected_keying == ExpectedKeying::KeyFile {
                    bail!(
                        "file is password-protected; use the '{}' binary",
                        expected_algorithm.password_command()
                    );
                }
                if bytes[63] != KDF_ID_ARGON2ID {
                    bail!("unsupported password KDF identifier {}", bytes[63]);
                }
                let memory_kib = u32::from_le_bytes(bytes[56..60].try_into().expect("fixed slice"));
                let iterations = u16::from_le_bytes(bytes[60..62].try_into().expect("fixed slice"));
                let parameters = PasswordKdf::from_header(memory_kib, iterations, bytes[62])?;
                Keying::Password(parameters)
            }
            version => bail!("unsupported x3x format version {version}"),
        };
        if usize::from(bytes[10]) != expected_algorithm.tag_len()
            || usize::from(bytes[11]) != expected_algorithm.nonce_len()
        {
            bail!("invalid algorithm parameters in encrypted file header");
        }
        let chunk_size = u32::from_le_bytes(bytes[12..16].try_into().expect("fixed slice"));
        if usize::try_from(chunk_size).ok() != Some(expected_chunk_size) {
            bail!("unsupported encrypted file chunk size {chunk_size}");
        }
        let plaintext_len = u64::from_le_bytes(bytes[16..24].try_into().expect("fixed slice"));
        let mut nonce_seed = [0_u8; 32];
        nonce_seed.copy_from_slice(&bytes[24..56]);
        Ok(Self {
            bytes,
            plaintext_len,
            nonce_seed,
            keying,
        })
    }

    pub(super) fn bytes(&self) -> &[u8; HEADER_LEN] {
        &self.bytes
    }
}

pub(super) fn chunk_count(plaintext_len: u64, chunk_size: usize) -> u64 {
    if plaintext_len == 0 {
        1
    } else {
        plaintext_len.div_ceil(chunk_size as u64)
    }
}

pub(super) fn chunk_plaintext_len(
    plaintext_len: u64,
    chunk_size: usize,
    chunk_index: u64,
) -> usize {
    if plaintext_len == 0 {
        return 0;
    }
    let offset = chunk_index
        .checked_mul(chunk_size as u64)
        .expect("valid chunk offset");
    usize::try_from((plaintext_len - offset).min(chunk_size as u64))
        .expect("chunk length fits in usize")
}

pub(super) fn chunk_aad(
    header: &Header,
    chunk_index: u64,
    plaintext_len: usize,
    is_final: bool,
) -> [u8; 80] {
    let mut aad = [0_u8; 80];
    aad[..HEADER_LEN].copy_from_slice(header.bytes());
    aad[64..72].copy_from_slice(&chunk_index.to_le_bytes());
    aad[72..76].copy_from_slice(
        &u32::try_from(plaintext_len)
            .expect("chunk length fits in u32")
            .to_le_bytes(),
    );
    aad[76] = u8::from(is_final);
    aad
}

pub(super) fn chunk_nonce(seed: &[u8; 32], nonce_len: usize, chunk_index: u64) -> Vec<u8> {
    let mut nonce = seed[..nonce_len].to_vec();
    let index = chunk_index.to_be_bytes();
    let tail = nonce_len - index.len();
    for (output, counter) in nonce[tail..].iter_mut().zip(index) {
        *output ^= counter;
    }
    nonce
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::CHUNK_SIZE;

    const ALGORITHMS: [Algorithm; 8] = [
        Algorithm::Aes256GcmSiv,
        Algorithm::XChaCha20Poly1305,
        Algorithm::Serpent256,
        Algorithm::Threefish1024,
        Algorithm::AsconAead128,
        Algorithm::Rabbit,
        Algorithm::Aegis256,
        Algorithm::Aegis128L,
    ];

    #[test]
    fn key_file_headers_round_trip_for_every_algorithm() {
        let mut nonce_seed = [0_u8; 32];
        for (index, byte) in nonce_seed.iter_mut().enumerate() {
            *byte = u8::try_from(index).expect("nonce index fits in u8");
        }

        for algorithm in ALGORITHMS {
            let header = Header::new(
                algorithm,
                1_234_567,
                nonce_seed,
                CHUNK_SIZE,
                Keying::KeyFile,
            );
            let bytes = header.bytes();
            assert_eq!(&bytes[..8], b"X3XCRYPT");
            assert_eq!(bytes[8], 1);
            assert_eq!(bytes[9], algorithm.id());
            assert_eq!(usize::from(bytes[10]), algorithm.tag_len());
            assert_eq!(usize::from(bytes[11]), algorithm.nonce_len());
            assert_eq!(
                u32::from_le_bytes(bytes[12..16].try_into().expect("fixed chunk field")),
                u32::try_from(CHUNK_SIZE).expect("chunk size fits in u32")
            );
            assert_eq!(
                u64::from_le_bytes(bytes[16..24].try_into().expect("fixed length field")),
                1_234_567
            );
            assert_eq!(&bytes[24..56], &nonce_seed);
            assert!(bytes[56..].iter().all(|byte| *byte == 0));

            let parsed = Header::parse(*bytes, algorithm, CHUNK_SIZE, ExpectedKeying::KeyFile)
                .expect("parse generated key-file header");
            assert_eq!(parsed.plaintext_len, 1_234_567);
            assert_eq!(parsed.nonce_seed, nonce_seed);
            assert_eq!(parsed.keying, Keying::KeyFile);
        }
    }

    #[test]
    fn password_header_records_and_parses_its_kdf() {
        let parameters = PasswordKdf::testing();
        let header = Header::new(
            Algorithm::Aes256GcmSiv,
            17,
            [0x5A; 32],
            CHUNK_SIZE,
            Keying::Password(parameters),
        );
        let bytes = header.bytes();
        assert_eq!(bytes[8], 2);
        assert_eq!(
            u32::from_le_bytes(bytes[56..60].try_into().expect("fixed memory field")),
            parameters.memory_kib
        );
        assert_eq!(
            u16::from_le_bytes(bytes[60..62].try_into().expect("fixed iteration field")),
            parameters.iterations
        );
        assert_eq!(bytes[62], parameters.lanes);
        assert_eq!(bytes[63], KDF_ID_ARGON2ID);

        let parsed = Header::parse(
            *bytes,
            Algorithm::Aes256GcmSiv,
            CHUNK_SIZE,
            ExpectedKeying::Password,
        )
        .expect("parse generated password header");
        assert_eq!(parsed.keying, Keying::Password(parameters));
    }

    #[test]
    fn parser_rejects_every_structural_header_mismatch() {
        let header = Header::new(
            Algorithm::Aes256GcmSiv,
            3,
            [0x33; 32],
            CHUNK_SIZE,
            Keying::KeyFile,
        );
        let valid = *header.bytes();
        let mut malformed_headers = Vec::new();

        for offset in [0_usize, 8, 9, 10, 11, 12, 56] {
            let mut malformed = valid;
            malformed[offset] ^= if offset == 8 || offset == 9 {
                0x7F
            } else {
                0x01
            };
            malformed_headers.push(malformed);
        }

        for malformed in malformed_headers {
            assert!(
                Header::parse(
                    malformed,
                    Algorithm::Aes256GcmSiv,
                    CHUNK_SIZE,
                    ExpectedKeying::KeyFile,
                )
                .is_err()
            );
        }

        assert!(
            Header::parse(
                valid,
                Algorithm::XChaCha20Poly1305,
                CHUNK_SIZE,
                ExpectedKeying::KeyFile,
            )
            .is_err()
        );
        assert!(
            Header::parse(
                valid,
                Algorithm::Aes256GcmSiv,
                CHUNK_SIZE / 2,
                ExpectedKeying::KeyFile,
            )
            .is_err()
        );
    }

    #[test]
    fn chunk_math_covers_empty_exact_and_partial_records() {
        assert_eq!(chunk_count(0, CHUNK_SIZE), 1);
        assert_eq!(chunk_plaintext_len(0, CHUNK_SIZE, 0), 0);
        assert_eq!(chunk_count(1, CHUNK_SIZE), 1);
        assert_eq!(chunk_plaintext_len(1, CHUNK_SIZE, 0), 1);
        assert_eq!(chunk_count(CHUNK_SIZE as u64, CHUNK_SIZE), 1);
        assert_eq!(
            chunk_plaintext_len(CHUNK_SIZE as u64, CHUNK_SIZE, 0),
            CHUNK_SIZE
        );
        assert_eq!(chunk_count(CHUNK_SIZE as u64 + 1, CHUNK_SIZE), 2);
        assert_eq!(
            chunk_plaintext_len(CHUNK_SIZE as u64 + 1, CHUNK_SIZE, 0),
            CHUNK_SIZE
        );
        assert_eq!(chunk_plaintext_len(CHUNK_SIZE as u64 + 1, CHUNK_SIZE, 1), 1);
    }

    #[test]
    fn record_nonce_and_aad_bind_position_length_and_finality() {
        let seed = [0xA5_u8; 32];
        let first_nonce = chunk_nonce(&seed, 12, 0);
        let second_nonce = chunk_nonce(&seed, 12, 1);
        assert_eq!(first_nonce, seed[..12]);
        assert_ne!(first_nonce, second_nonce);
        assert_eq!(second_nonce[11], 0xA4);

        let header = Header::new(
            Algorithm::Aes256GcmSiv,
            7,
            seed,
            CHUNK_SIZE,
            Keying::KeyFile,
        );
        let aad = chunk_aad(&header, 9, 7, true);
        assert_eq!(&aad[..64], header.bytes());
        assert_eq!(
            u64::from_le_bytes(aad[64..72].try_into().expect("fixed index field")),
            9
        );
        assert_eq!(
            u32::from_le_bytes(aad[72..76].try_into().expect("fixed length field")),
            7
        );
        assert_eq!(aad[76], 1);
        assert_eq!(&aad[77..], &[0, 0, 0]);
    }
}
