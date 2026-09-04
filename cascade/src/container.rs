//! Versioned, authenticated on-disk envelope.
//!
//! The entire header is authenticated. It intentionally contains no filename or
//! cascade metadata: another encryption pass simply encrypts these bytes as data.

use zeroize::Zeroizing;

use crate::{
    algorithms::{Algorithm, SALT_LEN},
    error::AppError,
};

const MAGIC: &[u8; 8] = b"CASCFILE";
const VERSION: u8 = 1;
const FIXED_HEADER_LEN: usize = 32;
const FLAGS: u8 = 0;

/// Encrypt using fresh OS-generated salt and nonce material.
pub fn encrypt(
    algorithm: Algorithm,
    master_key: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, AppError> {
    let mut salt = [0_u8; SALT_LEN];
    getrandom::fill(&mut salt).map_err(|_| AppError::Random)?;

    let mut nonce = vec![0_u8; algorithm.nonce_len()];
    getrandom::fill(&mut nonce).map_err(|_| AppError::Random)?;

    encrypt_with_material(algorithm, master_key, plaintext, &salt, &nonce)
}

/// Encrypt with caller-provided public material. Kept separate for reproducible
/// construction tests; production callers use [`encrypt`].
pub(crate) fn encrypt_with_material(
    algorithm: Algorithm,
    master_key: &[u8],
    plaintext: &[u8],
    salt: &[u8; SALT_LEN],
    nonce: &[u8],
) -> Result<Vec<u8>, AppError> {
    if master_key.len() != algorithm.key_len() || nonce.len() != algorithm.nonce_len() {
        return Err(AppError::EncryptionFailed);
    }

    let header = build_header(algorithm, plaintext.len(), salt, nonce)?;
    let expected_ciphertext_len = algorithm
        .expected_ciphertext_len(plaintext.len())
        .ok_or(AppError::InputTooLarge)?;
    let (ciphertext, tag) = algorithm.seal(master_key, salt, nonce, &header, plaintext)?;

    if ciphertext.len() != expected_ciphertext_len || tag.len() != algorithm.tag_len() {
        return Err(AppError::EncryptionFailed);
    }

    let output_len = encrypted_len(algorithm, plaintext.len())?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(output_len)
        .map_err(|_| AppError::Allocation)?;
    output.extend_from_slice(&header);
    output.extend_from_slice(&ciphertext);
    output.extend_from_slice(&tag);
    Ok(output)
}

/// Exact v1 envelope length without allocating or performing cryptography.
pub(crate) fn encrypted_len(algorithm: Algorithm, plaintext_len: usize) -> Result<usize, AppError> {
    FIXED_HEADER_LEN
        .checked_add(SALT_LEN)
        .and_then(|len| len.checked_add(algorithm.nonce_len()))
        .and_then(|len| {
            algorithm
                .expected_ciphertext_len(plaintext_len)
                .and_then(|ciphertext_len| len.checked_add(ciphertext_len))
        })
        .and_then(|len| len.checked_add(algorithm.tag_len()))
        .ok_or(AppError::InputTooLarge)
}

/// Parse, authenticate, and decrypt an envelope for the explicitly selected suite.
pub fn decrypt(
    selected: Algorithm,
    master_key: &[u8],
    encrypted: &[u8],
) -> Result<Zeroizing<Vec<u8>>, AppError> {
    if master_key.len() != selected.key_len() {
        return Err(AppError::DecryptionFailed);
    }

    let parsed = ParsedEnvelope::parse(encrypted)?;
    if parsed.algorithm != selected {
        return Err(AppError::AlgorithmMismatch {
            selected: selected.name(),
            actual: parsed.algorithm.name(),
        });
    }

    let plaintext = selected.open(
        master_key,
        &parsed.salt,
        parsed.nonce,
        parsed.header,
        parsed.ciphertext,
        parsed.tag,
    )?;

    if plaintext.len() != parsed.plaintext_len {
        return Err(AppError::DecryptionFailed);
    }
    Ok(plaintext)
}

fn build_header(
    algorithm: Algorithm,
    plaintext_len: usize,
    salt: &[u8; SALT_LEN],
    nonce: &[u8],
) -> Result<Vec<u8>, AppError> {
    let header_len = FIXED_HEADER_LEN
        .checked_add(SALT_LEN)
        .and_then(|len| len.checked_add(nonce.len()))
        .ok_or(AppError::InputTooLarge)?;
    let header_len_u16 = u16::try_from(header_len).map_err(|_| AppError::InputTooLarge)?;
    let nonce_len_u16 = u16::try_from(nonce.len()).map_err(|_| AppError::InputTooLarge)?;
    let plaintext_len_u64 = u64::try_from(plaintext_len).map_err(|_| AppError::InputTooLarge)?;

    let mut header = Vec::new();
    header
        .try_reserve_exact(header_len)
        .map_err(|_| AppError::Allocation)?;
    header.extend_from_slice(MAGIC);
    header.push(VERSION);
    header.push(algorithm.id());
    header.push(algorithm.suite_id());
    header.push(FLAGS);
    header.extend_from_slice(&header_len_u16.to_be_bytes());
    header.extend_from_slice(&nonce_len_u16.to_be_bytes());
    header.extend_from_slice(&plaintext_len_u64.to_be_bytes());
    header.extend_from_slice(&[0_u8; 8]);
    header.extend_from_slice(salt);
    header.extend_from_slice(nonce);

    if header.len() != header_len {
        return Err(AppError::EncryptionFailed);
    }
    Ok(header)
}

struct ParsedEnvelope<'a> {
    algorithm: Algorithm,
    plaintext_len: usize,
    salt: [u8; SALT_LEN],
    nonce: &'a [u8],
    header: &'a [u8],
    ciphertext: &'a [u8],
    tag: &'a [u8],
}

impl<'a> ParsedEnvelope<'a> {
    fn parse(input: &'a [u8]) -> Result<Self, AppError> {
        let fixed = input
            .get(..FIXED_HEADER_LEN)
            .ok_or(AppError::InvalidFormat)?;
        if fixed.get(..MAGIC.len()) != Some(MAGIC) {
            return Err(AppError::InvalidFormat);
        }

        let version = fixed[8];
        if version != VERSION {
            return Err(AppError::UnsupportedVersion(version));
        }
        let algorithm = Algorithm::from_id(fixed[9]).ok_or(AppError::InvalidFormat)?;
        if fixed[10] != algorithm.suite_id() || fixed[11] != FLAGS || fixed[24..32] != [0; 8] {
            return Err(AppError::InvalidFormat);
        }

        let header_len = usize::from(u16::from_be_bytes([fixed[12], fixed[13]]));
        let nonce_len = usize::from(u16::from_be_bytes([fixed[14], fixed[15]]));
        let plaintext_len_u64 = u64::from_be_bytes(
            fixed[16..24]
                .try_into()
                .map_err(|_| AppError::InvalidFormat)?,
        );
        let plaintext_len =
            usize::try_from(plaintext_len_u64).map_err(|_| AppError::InputTooLarge)?;

        let expected_header_len = FIXED_HEADER_LEN
            .checked_add(SALT_LEN)
            .and_then(|len| len.checked_add(nonce_len))
            .ok_or(AppError::InvalidFormat)?;
        if nonce_len != algorithm.nonce_len() || header_len != expected_header_len {
            return Err(AppError::InvalidFormat);
        }

        let header = input.get(..header_len).ok_or(AppError::InvalidFormat)?;
        let salt_end = FIXED_HEADER_LEN + SALT_LEN;
        let salt: [u8; SALT_LEN] = header[FIXED_HEADER_LEN..salt_end]
            .try_into()
            .map_err(|_| AppError::InvalidFormat)?;
        let nonce = &header[salt_end..];

        let body = input.get(header_len..).ok_or(AppError::InvalidFormat)?;
        if body.len() < algorithm.tag_len() {
            return Err(AppError::InvalidFormat);
        }
        let tag_start = body.len() - algorithm.tag_len();
        let (ciphertext, tag) = body.split_at(tag_start);

        let expected_ciphertext_len = algorithm
            .expected_ciphertext_len(plaintext_len)
            .ok_or(AppError::InvalidFormat)?;
        if ciphertext.len() != expected_ciphertext_len {
            return Err(AppError::InvalidFormat);
        }

        Ok(Self {
            algorithm,
            plaintext_len,
            salt,
            nonce,
            header,
            ciphertext,
            tag,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALGORITHMS: [Algorithm; 4] = [
        Algorithm::Aes256GcmSiv,
        Algorithm::Serpent256,
        Algorithm::XChaCha20Poly1305,
        Algorithm::Threefish1024,
    ];

    fn key(algorithm: Algorithm) -> Vec<u8> {
        vec![algorithm.id().wrapping_mul(41); algorithm.key_len()]
    }

    fn public_material(algorithm: Algorithm) -> ([u8; SALT_LEN], Vec<u8>) {
        (
            [algorithm.id().wrapping_mul(23); SALT_LEN],
            vec![algorithm.id().wrapping_mul(67); algorithm.nonce_len()],
        )
    }

    fn plaintext(length: usize) -> Vec<u8> {
        (0..length)
            .map(|index| (index as u8).wrapping_mul(29).wrapping_add(11))
            .collect()
    }

    #[test]
    fn header_layout_is_stable() {
        let algorithm = Algorithm::Aes256GcmSiv;
        let salt = [0x55; SALT_LEN];
        let nonce = [0x22; 12];
        let header = build_header(algorithm, 0x0102_0304, &salt, &nonce).unwrap();

        assert_eq!(&header[..8], b"CASCFILE");
        assert_eq!(header[8..12], [1, 1, 0x11, 0]);
        assert_eq!(u16::from_be_bytes([header[12], header[13]]), 76);
        assert_eq!(u16::from_be_bytes([header[14], header[15]]), 12);
        assert_eq!(
            u64::from_be_bytes(header[16..24].try_into().unwrap()),
            0x0102_0304
        );
        assert_eq!(&header[32..64], &salt);
        assert_eq!(&header[64..], &nonce);
    }

    #[test]
    fn parser_rejects_short_and_unknown_files() {
        for length in 0..FIXED_HEADER_LEN {
            assert!(matches!(
                ParsedEnvelope::parse(&vec![0; length]),
                Err(AppError::InvalidFormat)
            ));
        }
        let mut input = vec![0; FIXED_HEADER_LEN];
        input[..8].copy_from_slice(MAGIC);
        input[8] = VERSION;
        input[9] = 99;
        assert!(matches!(
            ParsedEnvelope::parse(&input),
            Err(AppError::InvalidFormat)
        ));
    }

    #[test]
    fn every_suite_round_trips_all_important_boundaries() {
        for algorithm in ALGORITHMS {
            let key = key(algorithm);
            let (salt, nonce) = public_material(algorithm);
            for length in [
                0, 1, 11, 12, 15, 16, 17, 23, 24, 31, 32, 33, 127, 128, 129, 255, 256, 257, 4096,
            ] {
                let plaintext = plaintext(length);
                let encrypted =
                    encrypt_with_material(algorithm, &key, &plaintext, &salt, &nonce).unwrap();
                let decrypted = decrypt(algorithm, &key, &encrypted).unwrap();
                assert_eq!(
                    decrypted.as_slice(),
                    plaintext,
                    "{} length {length}",
                    algorithm.name()
                );
            }
        }
    }

    #[test]
    fn every_single_bit_mutation_is_rejected() {
        for algorithm in ALGORITHMS {
            let key = key(algorithm);
            let (salt, nonce) = public_material(algorithm);
            let encrypted =
                encrypt_with_material(algorithm, &key, &plaintext(33), &salt, &nonce).unwrap();

            for byte_index in 0..encrypted.len() {
                for bit in 0..8 {
                    let mut changed = encrypted.clone();
                    changed[byte_index] ^= 1 << bit;
                    assert!(
                        decrypt(algorithm, &key, &changed).is_err(),
                        "{} accepted mutation at byte {byte_index}, bit {bit}",
                        algorithm.name()
                    );
                }
            }
        }
    }

    #[test]
    fn every_truncation_and_appended_data_is_rejected() {
        for algorithm in ALGORITHMS {
            let key = key(algorithm);
            let (salt, nonce) = public_material(algorithm);
            let encrypted =
                encrypt_with_material(algorithm, &key, &plaintext(19), &salt, &nonce).unwrap();

            for length in 0..encrypted.len() {
                assert!(
                    decrypt(algorithm, &key, &encrypted[..length]).is_err(),
                    "{} accepted truncation at {length}",
                    algorithm.name()
                );
            }
            let mut appended = encrypted;
            appended.push(0);
            assert!(decrypt(algorithm, &key, &appended).is_err());
        }
    }

    #[test]
    fn wrong_keys_and_wrong_selected_algorithms_are_rejected() {
        for algorithm in ALGORITHMS {
            let root_key = key(algorithm);
            let (salt, nonce) = public_material(algorithm);
            let encrypted =
                encrypt_with_material(algorithm, &root_key, b"classified", &salt, &nonce).unwrap();

            let mut wrong_key = root_key.clone();
            wrong_key[0] ^= 1;
            assert!(matches!(
                decrypt(algorithm, &wrong_key, &encrypted),
                Err(AppError::DecryptionFailed)
            ));

            for selected in ALGORITHMS {
                if selected != algorithm {
                    let selected_key = key(selected);
                    assert!(decrypt(selected, &selected_key, &encrypted).is_err());
                }
            }
        }
    }

    #[test]
    fn all_ordered_two_layer_cascades_round_trip_in_reverse() {
        let original = plaintext(513);
        for inner_algorithm in ALGORITHMS {
            for outer_algorithm in ALGORITHMS {
                let inner_key = key(inner_algorithm);
                let outer_key = key(outer_algorithm);
                let (inner_salt, inner_nonce) = public_material(inner_algorithm);
                let (mut outer_salt, mut outer_nonce) = public_material(outer_algorithm);
                outer_salt[0] ^= 0x80;
                outer_nonce[0] ^= 0x80;

                let inner = encrypt_with_material(
                    inner_algorithm,
                    &inner_key,
                    &original,
                    &inner_salt,
                    &inner_nonce,
                )
                .unwrap();
                let outer = encrypt_with_material(
                    outer_algorithm,
                    &outer_key,
                    &inner,
                    &outer_salt,
                    &outer_nonce,
                )
                .unwrap();
                let recovered_inner = decrypt(outer_algorithm, &outer_key, &outer).unwrap();
                let recovered = decrypt(inner_algorithm, &inner_key, &recovered_inner).unwrap();
                assert_eq!(
                    recovered.as_slice(),
                    original,
                    "{} inside {}",
                    inner_algorithm.name(),
                    outer_algorithm.name()
                );
            }
        }
    }

    #[test]
    fn fresh_random_material_changes_the_container() {
        for algorithm in ALGORITHMS {
            let key = key(algorithm);
            let first = encrypt(algorithm, &key, b"identical plaintext").unwrap();
            let second = encrypt(algorithm, &key, b"identical plaintext").unwrap();
            assert_ne!(
                first,
                second,
                "{} reused all public material",
                algorithm.name()
            );
        }
    }

    #[test]
    fn envelope_length_cap_keeps_every_output_reprocessable() {
        let cap = usize::try_from(crate::file_io::MAX_FILE_BYTES).unwrap();
        for algorithm in ALGORITHMS {
            assert!(encrypted_len(algorithm, cap).unwrap() > cap);
            let largest_safe = ((cap - 512)..cap)
                .rev()
                .find(|length| encrypted_len(algorithm, *length).unwrap() <= cap)
                .unwrap();
            assert!(encrypted_len(algorithm, largest_safe).unwrap() <= cap);
            assert!(encrypted_len(algorithm, largest_safe + 1).unwrap() > cap);
            assert!(matches!(
                encrypted_len(algorithm, usize::MAX),
                Err(AppError::InputTooLarge)
            ));
        }
    }

    #[test]
    fn malformed_inputs_never_panic() {
        // Deterministic pseudo-random non-format corpus keeps this test
        // reproducible and checks the parser's earliest rejection paths.
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        for length in 0..512 {
            let mut bytes = vec![0_u8; length];
            for byte in &mut bytes {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *byte = state as u8;
            }
            for algorithm in ALGORITHMS {
                let _ = decrypt(algorithm, &key(algorithm), &bytes);
            }
        }
    }

    #[test]
    fn canonical_shaped_garbage_and_adversarial_lengths_are_rejected() {
        for algorithm in ALGORITHMS {
            let root_key = key(algorithm);
            let (salt, nonce) = public_material(algorithm);
            for plaintext_len in [0, 1, 15, 16, 17, 127, 128, 129, 255] {
                let mut shaped = build_header(algorithm, plaintext_len, &salt, &nonce).unwrap();
                shaped.resize(encrypted_len(algorithm, plaintext_len).unwrap(), 0);
                assert!(matches!(
                    decrypt(algorithm, &root_key, &shaped),
                    Err(AppError::DecryptionFailed)
                ));
            }
        }

        let algorithm = Algorithm::Aes256GcmSiv;
        let root_key = key(algorithm);
        let (salt, nonce) = public_material(algorithm);
        let valid = encrypt_with_material(algorithm, &root_key, b"body", &salt, &nonce).unwrap();
        for mutate in [
            |bytes: &mut [u8]| bytes[12..14].copy_from_slice(&0_u16.to_be_bytes()),
            |bytes: &mut [u8]| bytes[12..14].copy_from_slice(&u16::MAX.to_be_bytes()),
            |bytes: &mut [u8]| bytes[14..16].copy_from_slice(&0_u16.to_be_bytes()),
            |bytes: &mut [u8]| bytes[14..16].copy_from_slice(&u16::MAX.to_be_bytes()),
            |bytes: &mut [u8]| bytes[16..24].copy_from_slice(&u64::MAX.to_be_bytes()),
            |bytes: &mut [u8]| bytes[24..32].fill(0xff),
        ] {
            let mut malformed = valid.clone();
            mutate(&mut malformed);
            assert!(decrypt(algorithm, &root_key, &malformed).is_err());
        }
    }

    fn decode_hex(input: &str) -> Vec<u8> {
        fn nibble(byte: u8) -> u8 {
            match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                _ => panic!("invalid fixture hex"),
            }
        }

        let input: Vec<u8> = input
            .bytes()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect();
        assert_eq!(input.len() % 2, 0);
        input
            .chunks_exact(2)
            .map(|pair| (nibble(pair[0]) << 4) | nibble(pair[1]))
            .collect()
    }

    #[test]
    fn committed_v1_fixtures_preserve_encrypt_and_decrypt_compatibility() {
        let plaintext = b"cascade v1 compatibility fixture\0\xff";
        let fixtures = [
            (
                Algorithm::Aes256GcmSiv,
                include_str!("../tests/fixtures/v1-aes.hex"),
            ),
            (
                Algorithm::Serpent256,
                include_str!("../tests/fixtures/v1-serpent.hex"),
            ),
            (
                Algorithm::XChaCha20Poly1305,
                include_str!("../tests/fixtures/v1-xchacha.hex"),
            ),
            (
                Algorithm::Threefish1024,
                include_str!("../tests/fixtures/v1-threefish.hex"),
            ),
        ];
        for (algorithm, fixture) in fixtures {
            let (salt, nonce) = public_material(algorithm);
            let expected = decode_hex(fixture);
            let encrypted =
                encrypt_with_material(algorithm, &key(algorithm), plaintext, &salt, &nonce)
                    .unwrap();
            assert_eq!(encrypted, expected, "{} fixture changed", algorithm.name());
            assert_eq!(
                decrypt(algorithm, &key(algorithm), &expected)
                    .unwrap()
                    .as_slice(),
                plaintext,
                "{} fixture no longer decrypts",
                algorithm.name()
            );
        }
    }
}
