use super::*;
use aes::cipher::{Array, BlockCipherEncrypt, KeyInit, StreamCipherSeek};
use std::collections::HashSet;
use std::fs;
use std::io;

const TEST_CONFIG: GeneratorConfig<'static> = GeneratorConfig {
    application_salt: b"test application salt",
    application_pepper: b"test application pepper",
    domain: b"versakey tests/v1",
};

fn cheap_params() -> Params {
    Params::new(32, 1, 1, Some(DERIVED_KEY_BYTES)).expect("valid cheap test parameters")
}

fn cheap_scrypt_params() -> ScryptParams {
    ScryptParams::new(4, 1, 1).expect("valid cheap scrypt test parameters")
}

fn fixed_key(seed: u8) -> [u8; DERIVED_KEY_BYTES] {
    let mut key = [0_u8; DERIVED_KEY_BYTES];
    for (index, byte) in key.iter_mut().enumerate() {
        *byte = seed.wrapping_add(index as u8);
    }
    key
}

fn stream(key: &[u8; DERIVED_KEY_BYTES], size: u64, buffer_size: usize) -> Vec<u8> {
    let mut output = Vec::new();
    write_stream_with_buffer(&mut output, key, size, buffer_size).expect("stream generation");
    output
}

fn generator_stream(
    key: &[u8; DERIVED_KEY_BYTES],
    size: u64,
    buffer_size: usize,
    generator: StreamGenerator,
) -> Vec<u8> {
    let mut output = Vec::new();
    write_stream_with_generator(&mut output, key, size, buffer_size, generator)
        .expect("stream generation");
    output
}

fn cheap_derived_key(
    password: &str,
    size: u64,
    config: GeneratorConfig<'_>,
) -> Zeroizing<[u8; DERIVED_KEY_BYTES]> {
    derive_stream_key_with_params(password, size, config, cheap_params())
        .expect("test key derivation")
}

fn cheap_scrypt_derived_key(
    password: &str,
    size: u64,
    config: GeneratorConfig<'_>,
) -> Zeroizing<[u8; DERIVED_KEY_BYTES]> {
    derive_scrypt_stream_key_with_params(password, size, config, cheap_scrypt_params())
        .expect("test scrypt key derivation")
}

fn cheap_pbkdf2_derived_key(
    password: &str,
    size: u64,
    config: GeneratorConfig<'_>,
) -> Zeroizing<[u8; DERIVED_KEY_BYTES]> {
    derive_pbkdf2_stream_key_with_rounds(password, size, config, 8)
        .expect("test PBKDF2 key derivation")
}

#[test]
fn parse_size_accepts_exact_boundaries_and_whitespace() {
    assert_eq!(parse_size("1"), Ok(1));
    assert_eq!(parse_size("20000000000"), Ok(MAX_KEY_BYTES));
    assert_eq!(parse_size(" \r\n\t42 \n"), Ok(42));
    assert_eq!(parse_size("0000016"), Ok(16));
}

#[test]
fn parse_size_accepts_hundreds_of_valid_values() {
    for size in 1..=512_u64 {
        assert_eq!(parse_size(&size.to_string()), Ok(size), "size {size}");
    }
}

#[test]
fn parse_size_accepts_values_near_maximum() {
    for distance in 0..512_u64 {
        let size = MAX_KEY_BYTES - distance;
        assert_eq!(parse_size(&size.to_string()), Ok(size), "size {size}");
    }
}

#[test]
fn parse_size_rejects_empty_and_zero() {
    for input in ["", " ", "\t", "\r\n"] {
        assert_eq!(parse_size(input), Err(SizeError::Empty), "input {input:?}");
    }
    for input in ["0", "00", "000000"] {
        assert_eq!(parse_size(input), Err(SizeError::OutOfRange));
    }
}

#[test]
fn parse_size_rejects_values_above_maximum_and_u64() {
    for input in [
        "20000000001",
        "20000001000",
        "18446744073709551615",
        "18446744073709551616",
    ] {
        assert_eq!(parse_size(input), Err(SizeError::OutOfRange));
    }
}

#[test]
fn parse_size_rejects_non_decimal_notation() {
    for input in [
        "-1",
        "+1",
        "1.0",
        "1e3",
        "1_000",
        "1,000",
        "0x10",
        "0b10",
        "\u{ff11}\u{ff12}",
        "\u{0661}\u{0662}",
    ] {
        assert_eq!(
            parse_size(input),
            Err(SizeError::NotDecimal),
            "input {input:?}"
        );
    }
}

#[test]
fn parse_size_rejects_every_common_unit_suffix() {
    for suffix in ["B", "b", "KB", "KiB", "MB", "MiB", "GB", "GiB", "bytes"] {
        let input = format!("10{suffix}");
        assert_eq!(parse_size(&input), Err(SizeError::NotDecimal), "{input}");
    }
}

#[test]
fn validate_size_has_exact_boundaries() {
    assert_eq!(validate_size(0), Err(SizeError::OutOfRange));
    assert_eq!(validate_size(1), Ok(()));
    assert_eq!(validate_size(MAX_KEY_BYTES), Ok(()));
    assert_eq!(validate_size(MAX_KEY_BYTES + 1), Err(SizeError::OutOfRange));
}

#[test]
fn effective_salt_is_unambiguous() {
    let left = GeneratorConfig {
        application_salt: b"ab",
        application_pepper: b"same pepper",
        domain: b"c",
    };
    let right = GeneratorConfig {
        application_salt: b"a",
        application_pepper: b"same pepper",
        domain: b"bc",
    };
    assert_ne!(
        build_effective_salt(left, 100).unwrap(),
        build_effective_salt(right, 100).unwrap()
    );
}

#[test]
fn effective_salt_binds_requested_length() {
    assert_ne!(
        build_effective_salt(TEST_CONFIG, 100).unwrap(),
        build_effective_salt(TEST_CONFIG, 101).unwrap()
    );
}

#[test]
fn peppered_effective_salt_is_unambiguous_and_binds_every_input() {
    let baseline = build_peppered_effective_salt(TEST_CONFIG, 100).unwrap();
    for changed in [
        GeneratorConfig {
            application_salt: b"different salt",
            ..TEST_CONFIG
        },
        GeneratorConfig {
            application_pepper: b"different pepper",
            ..TEST_CONFIG
        },
        GeneratorConfig {
            domain: b"different domain",
            ..TEST_CONFIG
        },
    ] {
        assert_ne!(
            baseline,
            build_peppered_effective_salt(changed, 100).unwrap()
        );
    }
    assert_ne!(
        baseline,
        build_peppered_effective_salt(TEST_CONFIG, 101).unwrap()
    );

    let left = GeneratorConfig {
        application_salt: b"ab",
        application_pepper: b"d",
        domain: b"c",
    };
    let right = GeneratorConfig {
        application_salt: b"a",
        application_pepper: b"d",
        domain: b"bc",
    };
    assert_ne!(
        build_peppered_effective_salt(left, 100).unwrap(),
        build_peppered_effective_salt(right, 100).unwrap()
    );
}

#[test]
fn scrypt_matches_rfc_7914_first_vector() {
    let params = ScryptParams::new(4, 1, 1).unwrap();
    let mut output = [0_u8; 64];
    scrypt(b"", b"", &params, &mut output).unwrap();
    assert_eq!(
        output,
        [
            0x77, 0xd6, 0x57, 0x62, 0x38, 0x65, 0x7b, 0x20, 0x3b, 0x19, 0xca, 0x42, 0xc1, 0x8a,
            0x04, 0x97, 0xf1, 0x6b, 0x48, 0x44, 0xe3, 0x07, 0x4a, 0xe8, 0xdf, 0xdf, 0xfa, 0x3f,
            0xed, 0xe2, 0x14, 0x42, 0xfc, 0xd0, 0x06, 0x9d, 0xed, 0x09, 0x48, 0xf8, 0x32, 0x6a,
            0x75, 0x3a, 0x0f, 0xc8, 0x1f, 0x17, 0xe8, 0xd3, 0xe0, 0xfb, 0x2e, 0x0d, 0x36, 0x28,
            0xcf, 0x35, 0xe2, 0x0c, 0x38, 0xd1, 0x89, 0x06,
        ]
    );
}

#[test]
fn pbkdf2_sha256_matches_known_vector() {
    let mut output = [0_u8; 32];
    pbkdf2_hmac::<Sha256>(b"password", b"salt", 1, &mut output);
    assert_eq!(
        output,
        [
            0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c, 0x43, 0xe7, 0x22, 0x52, 0x56, 0xc4,
            0xf8, 0x37, 0xa8, 0x65, 0x48, 0xc9, 0x2c, 0xcc, 0x35, 0x48, 0x08, 0x05, 0x98, 0x7c,
            0xb7, 0x0b, 0xe1, 0x7b,
        ]
    );
}

#[test]
fn derived_key_is_deterministic() {
    assert_eq!(
        *cheap_derived_key("correct horse battery staple", 4096, TEST_CONFIG),
        *cheap_derived_key("correct horse battery staple", 4096, TEST_CONFIG)
    );
}

#[test]
fn different_password_changes_derived_key() {
    assert_ne!(
        *cheap_derived_key("password one", 4096, TEST_CONFIG),
        *cheap_derived_key("password two", 4096, TEST_CONFIG)
    );
}

#[test]
fn password_is_unicode_and_whitespace_sensitive() {
    let exact = cheap_derived_key(" pässword🔑 ", 4096, TEST_CONFIG);
    assert_ne!(*exact, *cheap_derived_key("pässword🔑 ", 4096, TEST_CONFIG));
    assert_ne!(*exact, *cheap_derived_key(" pässword🔑", 4096, TEST_CONFIG));
    assert_ne!(
        *exact,
        *cheap_derived_key(" pässword🔐 ", 4096, TEST_CONFIG)
    );
}

#[test]
fn different_salt_changes_derived_key() {
    let changed = GeneratorConfig {
        application_salt: b"a different test salt",
        ..TEST_CONFIG
    };
    assert_ne!(
        *cheap_derived_key("password", 4096, TEST_CONFIG),
        *cheap_derived_key("password", 4096, changed)
    );
}

#[test]
fn different_pepper_changes_derived_key() {
    let changed = GeneratorConfig {
        application_pepper: b"a different test pepper",
        ..TEST_CONFIG
    };
    assert_ne!(
        *cheap_derived_key("password", 4096, TEST_CONFIG),
        *cheap_derived_key("password", 4096, changed)
    );
}

#[test]
fn different_domain_changes_derived_key() {
    let changed = GeneratorConfig {
        domain: b"versakey tests/v2",
        ..TEST_CONFIG
    };
    assert_ne!(
        *cheap_derived_key("password", 4096, TEST_CONFIG),
        *cheap_derived_key("password", 4096, changed)
    );
}

#[test]
fn different_lengths_do_not_share_a_stream_prefix() {
    let key_100 = cheap_derived_key("password", 100, TEST_CONFIG);
    let key_101 = cheap_derived_key("password", 101, TEST_CONFIG);
    let output_100 = stream(&key_100, 100, 31);
    let output_101 = stream(&key_101, 101, 31);
    assert_ne!(output_100, output_101[..100]);
}

#[test]
fn scrypt_derivation_is_deterministic_and_input_sensitive() {
    let baseline = cheap_scrypt_derived_key("password", 4096, TEST_CONFIG);
    assert_eq!(
        *baseline,
        *cheap_scrypt_derived_key("password", 4096, TEST_CONFIG)
    );
    assert_ne!(
        *baseline,
        *cheap_scrypt_derived_key("different password", 4096, TEST_CONFIG)
    );
    for changed in [
        GeneratorConfig {
            application_salt: b"different salt",
            ..TEST_CONFIG
        },
        GeneratorConfig {
            application_pepper: b"different pepper",
            ..TEST_CONFIG
        },
        GeneratorConfig {
            domain: b"different domain",
            ..TEST_CONFIG
        },
    ] {
        assert_ne!(
            *baseline,
            *cheap_scrypt_derived_key("password", 4096, changed)
        );
    }
    assert_ne!(
        *baseline,
        *cheap_scrypt_derived_key("password", 4097, TEST_CONFIG)
    );
    assert_ne!(
        *baseline,
        *derive_scrypt_stream_key_with_params(
            "password",
            4096,
            TEST_CONFIG,
            ScryptParams::new(5, 1, 1).unwrap(),
        )
        .unwrap()
    );
}

#[test]
fn pbkdf2_derivation_is_deterministic_and_input_sensitive() {
    let baseline = cheap_pbkdf2_derived_key("password", 4096, TEST_CONFIG);
    assert_eq!(
        *baseline,
        *cheap_pbkdf2_derived_key("password", 4096, TEST_CONFIG)
    );
    assert_ne!(
        *baseline,
        *cheap_pbkdf2_derived_key("different password", 4096, TEST_CONFIG)
    );
    for changed in [
        GeneratorConfig {
            application_salt: b"different salt",
            ..TEST_CONFIG
        },
        GeneratorConfig {
            application_pepper: b"different pepper",
            ..TEST_CONFIG
        },
        GeneratorConfig {
            domain: b"different domain",
            ..TEST_CONFIG
        },
    ] {
        assert_ne!(
            *baseline,
            *cheap_pbkdf2_derived_key("password", 4096, changed)
        );
    }
    assert_ne!(
        *baseline,
        *cheap_pbkdf2_derived_key("password", 4097, TEST_CONFIG)
    );
    assert_ne!(
        *baseline,
        *derive_pbkdf2_stream_key_with_rounds("password", 4096, TEST_CONFIG, 9).unwrap()
    );
}

#[test]
fn new_kdfs_reject_empty_passwords_and_zero_pbkdf2_rounds() {
    assert!(matches!(
        derive_scrypt_stream_key_with_params("", 64, TEST_CONFIG, cheap_scrypt_params()),
        Err(GenerateError::EmptyPassword)
    ));
    assert!(matches!(
        derive_pbkdf2_stream_key_with_rounds("", 64, TEST_CONFIG, 8),
        Err(GenerateError::EmptyPassword)
    ));
    assert!(matches!(
        derive_pbkdf2_stream_key_with_rounds("password", 64, TEST_CONFIG, 0),
        Err(GenerateError::InvalidConfiguration(_))
    ));
}

#[test]
fn production_kdf_parameters_are_pinned() {
    let params = production_params().unwrap();
    assert_eq!(params.m_cost(), ARGON2_MEMORY_KIB);
    assert_eq!(params.t_cost(), ARGON2_ITERATIONS);
    assert_eq!(params.p_cost(), ARGON2_LANES);
    assert_eq!(params.output_len(), Some(DERIVED_KEY_BYTES));

    let scrypt = production_scrypt_params().unwrap();
    assert_eq!(scrypt.log_n(), 16);
    assert_eq!(scrypt.n(), 65_536);
    assert_eq!(scrypt.r(), 8);
    assert_eq!(scrypt.p(), 1);
    assert_eq!(PBKDF2_ITERATIONS, 600_000);
}

#[test]
fn production_suite_outputs_match_known_answers() {
    let argon2_key = derive_production_stream_key(
        "production fixture",
        64,
        TEST_CONFIG,
        GeneratorSuite::Argon2idAes256Ctr,
    )
    .unwrap();
    assert_eq!(
        *argon2_key,
        [
            136, 121, 137, 75, 30, 32, 184, 28, 35, 199, 42, 101, 249, 36, 233, 123, 128, 237, 136,
            236, 189, 246, 223, 130, 128, 186, 131, 12, 57, 183, 198, 66,
        ]
    );

    let scrypt_key = derive_production_stream_key(
        "production fixture",
        64,
        TEST_CONFIG,
        GeneratorSuite::ScryptAes256Ctr,
    )
    .unwrap();
    let pbkdf2_key = derive_production_stream_key(
        "production fixture",
        64,
        TEST_CONFIG,
        GeneratorSuite::Pbkdf2Sha256Aes256Ctr,
    )
    .unwrap();
    let outputs = [
        generator_stream(&argon2_key, 64, 17, StreamGenerator::Aes256Ctr),
        generator_stream(&scrypt_key, 64, 17, StreamGenerator::Aes256Ctr),
        generator_stream(&pbkdf2_key, 64, 17, StreamGenerator::Aes256Ctr),
        generator_stream(&argon2_key, 64, 17, StreamGenerator::ChaCha20),
        generator_stream(&argon2_key, 64, 17, StreamGenerator::Blake3Xof),
    ];
    let expected = [
        [
            13, 181, 150, 213, 200, 171, 182, 111, 92, 152, 33, 17, 170, 94, 176, 253, 131, 217,
            200, 205, 204, 47, 198, 202, 61, 147, 92, 226, 87, 74, 170, 201, 218, 122, 40, 24, 126,
            237, 177, 76, 105, 144, 12, 188, 232, 57, 200, 179, 225, 167, 196, 54, 68, 182, 54,
            123, 176, 177, 138, 239, 254, 190, 194, 171,
        ],
        [
            156, 130, 71, 202, 4, 84, 222, 178, 19, 197, 242, 15, 107, 157, 21, 19, 45, 20, 152, 1,
            149, 143, 157, 219, 47, 40, 103, 91, 184, 97, 56, 180, 119, 82, 204, 54, 74, 153, 213,
            215, 204, 90, 60, 46, 159, 45, 225, 31, 245, 154, 39, 153, 77, 93, 140, 39, 154, 94,
            72, 113, 92, 200, 3, 220,
        ],
        [
            65, 113, 196, 164, 244, 202, 2, 108, 220, 87, 36, 140, 191, 53, 83, 57, 67, 179, 4,
            193, 103, 161, 123, 93, 215, 206, 19, 29, 178, 228, 57, 210, 48, 217, 180, 191, 180,
            56, 134, 197, 184, 50, 153, 190, 99, 78, 22, 52, 37, 158, 169, 246, 242, 216, 147, 212,
            183, 128, 178, 54, 109, 196, 79, 236,
        ],
        [
            29, 15, 49, 215, 74, 177, 51, 54, 15, 191, 140, 213, 150, 124, 219, 137, 188, 93, 85,
            66, 237, 57, 18, 90, 190, 108, 223, 74, 233, 85, 11, 49, 137, 43, 32, 51, 218, 20, 190,
            71, 78, 74, 164, 211, 101, 101, 253, 253, 151, 213, 178, 132, 58, 14, 93, 150, 184, 22,
            50, 38, 8, 115, 173, 205,
        ],
        [
            201, 180, 78, 104, 49, 157, 205, 155, 20, 126, 128, 43, 153, 45, 66, 138, 103, 160,
            226, 16, 234, 212, 69, 221, 20, 69, 72, 79, 63, 173, 162, 206, 53, 124, 76, 2, 124,
            202, 129, 58, 116, 17, 151, 214, 54, 181, 110, 87, 163, 2, 112, 7, 103, 182, 143, 251,
            143, 5, 212, 181, 251, 169, 83, 135,
        ],
    ];
    for (index, (output, expected)) in outputs.iter().zip(expected.iter()).enumerate() {
        assert_eq!(
            output.as_slice(),
            expected.as_slice(),
            "production suite output {index}"
        );
    }
}

#[test]
fn suites_select_the_expected_stream_generators() {
    for (suite, expected) in [
        (
            GeneratorSuite::Argon2idAes256Ctr,
            StreamGenerator::Aes256Ctr,
        ),
        (GeneratorSuite::ScryptAes256Ctr, StreamGenerator::Aes256Ctr),
        (
            GeneratorSuite::Pbkdf2Sha256Aes256Ctr,
            StreamGenerator::Aes256Ctr,
        ),
        (GeneratorSuite::Argon2idChaCha20, StreamGenerator::ChaCha20),
        (
            GeneratorSuite::Argon2idBlake3Xof,
            StreamGenerator::Blake3Xof,
        ),
    ] {
        assert_eq!(suite.stream_generator(), expected, "suite {suite:?}");
    }
}

#[test]
fn suite_display_names_are_stable_and_distinct() {
    let names = [
        (GeneratorSuite::Argon2idAes256Ctr, "Argon2id + AES-256-CTR"),
        (GeneratorSuite::ScryptAes256Ctr, "scrypt + AES-256-CTR"),
        (
            GeneratorSuite::Pbkdf2Sha256Aes256Ctr,
            "PBKDF2-HMAC-SHA-256 + AES-256-CTR",
        ),
        (GeneratorSuite::Argon2idChaCha20, "Argon2id + ChaCha20"),
        (
            GeneratorSuite::Argon2idBlake3Xof,
            "Argon2id + keyed BLAKE3 XOF",
        ),
    ];
    for (suite, expected) in names {
        assert_eq!(suite.display_name(), expected);
    }
    assert_eq!(
        names
            .into_iter()
            .map(|(suite, _)| suite.display_name())
            .collect::<HashSet<_>>()
            .len(),
        names.len()
    );
}

#[test]
fn all_five_suites_are_domain_separated_with_cheap_kdfs() {
    let password = "suite separation fixture";
    let size = 257;
    let config = |domain| GeneratorConfig {
        domain,
        ..TEST_CONFIG
    };
    let argon2_key = cheap_derived_key(password, size, config(b"test/argon2id-aes256-ctr/v1"));
    let scrypt_key = cheap_scrypt_derived_key(password, size, config(b"test/scrypt-aes256-ctr/v1"));
    let pbkdf2_key = cheap_pbkdf2_derived_key(password, size, config(b"test/pbkdf2-aes256-ctr/v1"));
    let chacha_key = cheap_derived_key(password, size, config(b"test/argon2id-chacha20/v1"));
    let blake3_key = cheap_derived_key(password, size, config(b"test/argon2id-blake3/v1"));

    let keys = [
        *argon2_key,
        *scrypt_key,
        *pbkdf2_key,
        *chacha_key,
        *blake3_key,
    ];
    assert_eq!(keys.into_iter().collect::<HashSet<_>>().len(), keys.len());

    let outputs = [
        generator_stream(&argon2_key, size, 31, StreamGenerator::Aes256Ctr),
        generator_stream(&scrypt_key, size, 31, StreamGenerator::Aes256Ctr),
        generator_stream(&pbkdf2_key, size, 31, StreamGenerator::Aes256Ctr),
        generator_stream(&chacha_key, size, 31, StreamGenerator::ChaCha20),
        generator_stream(&blake3_key, size, 31, StreamGenerator::Blake3Xof),
    ];
    let distinct: HashSet<&[u8]> = outputs.iter().map(Vec::as_slice).collect();
    assert_eq!(distinct.len(), outputs.len());
}

#[test]
fn chacha20_zero_key_stream_matches_known_answer() {
    let output = generator_stream(
        &[0_u8; DERIVED_KEY_BYTES],
        64,
        11,
        StreamGenerator::ChaCha20,
    );
    assert_eq!(
        output.as_slice(),
        &[
            0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90, 0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86,
            0xbd, 0x28, 0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a, 0xa8, 0x36, 0xef, 0xcc,
            0x8b, 0x77, 0x0d, 0xc7, 0xda, 0x41, 0x59, 0x7c, 0x51, 0x57, 0x48, 0x8d, 0x77, 0x24,
            0xe0, 0x3f, 0xb8, 0xd8, 0x4a, 0x37, 0x6a, 0x43, 0xb8, 0xf4, 0x15, 0x18, 0xa1, 0x1c,
            0xc3, 0x87, 0xb6, 0x69, 0xb2, 0xee, 0x65, 0x86,
        ]
    );
}

#[test]
fn chacha20_fails_closed_at_its_counter_limit() {
    let key = [0_u8; DERIVED_KEY_BYTES];
    let nonce = [0_u8; CHACHA_NONCE_BYTES];
    let mut cipher = ChaCha20::new((&key).into(), (&nonce).into());
    let final_supported_block = (u64::from(u32::MAX) - 1) * 64;
    cipher.try_seek(final_supported_block).unwrap();

    let mut final_block = [0_u8; 64];
    cipher.try_apply_keystream(&mut final_block).unwrap();
    let mut overflow = [0_u8; 1];
    assert!(cipher.try_apply_keystream(&mut overflow).is_err());
}

#[test]
fn blake3_keyed_xof_stream_matches_known_answer() {
    let output = generator_stream(&fixed_key(0), 64, 13, StreamGenerator::Blake3Xof);
    assert_eq!(
        output.as_slice(),
        &[
            16, 57, 221, 137, 17, 128, 221, 159, 180, 79, 204, 180, 26, 13, 106, 19, 167, 153, 49,
            15, 48, 22, 17, 116, 171, 228, 222, 85, 215, 67, 82, 146, 10, 124, 82, 133, 176, 246,
            172, 65, 237, 197, 25, 207, 15, 35, 68, 144, 251, 72, 79, 40, 83, 160, 144, 242, 156,
            187, 122, 27, 87, 90, 108, 244,
        ]
    );
}

#[test]
fn every_stream_generator_writes_exact_boundary_lengths() {
    let key = fixed_key(7);
    for generator in [
        StreamGenerator::Aes256Ctr,
        StreamGenerator::ChaCha20,
        StreamGenerator::Blake3Xof,
    ] {
        for size in [
            1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 255, 256, 257, 1023, 1024, 1025, 4095, 4096,
            4097,
        ] {
            assert_eq!(
                generator_stream(&key, size, 257, generator).len(),
                size as usize,
                "generator {generator:?}, size {size}"
            );
        }
    }
}

#[test]
fn every_stream_generator_is_independent_of_buffer_partitioning() {
    let key = fixed_key(19);
    for generator in [
        StreamGenerator::Aes256Ctr,
        StreamGenerator::ChaCha20,
        StreamGenerator::Blake3Xof,
    ] {
        let expected = generator_stream(&key, 4103, 4103, generator);
        for buffer_size in [1, 2, 3, 7, 15, 16, 17, 31, 63, 64, 65, 127, 1024, 4096] {
            assert_eq!(
                generator_stream(&key, 4103, buffer_size, generator),
                expected,
                "generator {generator:?}, buffer size {buffer_size}"
            );
        }
    }
}

#[test]
fn every_stream_generator_rejects_invalid_size_and_zero_buffer_before_writing() {
    let key = fixed_key(23);
    for generator in [
        StreamGenerator::Aes256Ctr,
        StreamGenerator::ChaCha20,
        StreamGenerator::Blake3Xof,
    ] {
        let mut output = Vec::new();
        let error = write_stream_with_generator(&mut output, &key, 1, 0, generator).unwrap_err();
        assert!(matches!(error, GenerateError::InvalidConfiguration(_)));
        assert!(output.is_empty());

        for size in [0, MAX_KEY_BYTES + 1, u64::MAX] {
            let mut output = Vec::new();
            let error =
                write_stream_with_generator(&mut output, &key, size, 32, generator).unwrap_err();
            assert!(matches!(error, GenerateError::InvalidSize(_)));
            assert!(output.is_empty());
        }
    }
}

#[test]
fn stream_writes_exact_lengths_around_important_boundaries() {
    let key = fixed_key(7);
    for size in [
        1, 2, 15, 16, 17, 31, 32, 33, 63, 64, 65, 255, 256, 257, 4095, 4096, 4097, 8191, 8192, 8193,
    ] {
        assert_eq!(stream(&key, size, 4096).len(), size as usize, "size {size}");
    }
}

#[test]
fn stream_is_independent_of_buffer_partitioning() {
    let key = fixed_key(19);
    let expected = stream(&key, 10_003, 10_003);
    for buffer_size in [1, 2, 3, 7, 15, 16, 17, 31, 63, 64, 65, 127, 1024, 4096] {
        assert_eq!(
            stream(&key, 10_003, buffer_size),
            expected,
            "buffer size {buffer_size}"
        );
    }
}

#[test]
fn hundreds_of_stream_lengths_match_one_shot_reference() {
    let key = fixed_key(41);
    let reference = stream(&key, 4096, 4096);
    for size in 1..=1024_u64 {
        let buffer_size = ((size * 73) % 97 + 1) as usize;
        assert_eq!(
            stream(&key, size, buffer_size),
            reference[..size as usize],
            "size {size}, buffer {buffer_size}"
        );
    }
}

#[test]
fn fixed_key_stream_has_prefix_property() {
    let key = fixed_key(83);
    let short = stream(&key, 1000, 19);
    let long = stream(&key, 2000, 113);
    assert_eq!(short, long[..1000]);
}

#[test]
fn aes_ctr_stream_matches_direct_counter_encryption() {
    let key = fixed_key(0);
    let output = stream(&key, 16 * 256, 37);
    let cipher = Aes256::new(&Array::from(key));

    for counter in 0..256_u128 {
        let mut block = Array::from(counter.to_be_bytes());
        cipher.encrypt_block(&mut block);
        let start = counter as usize * 16;
        assert_eq!(output[start..start + 16], block[..], "counter {counter}");
    }
}

#[test]
fn aligned_blocks_do_not_repeat_in_large_fixture() {
    let key = fixed_key(101);
    let output = stream(&key, 1024 * 1024, 7777);
    let mut blocks = HashSet::with_capacity(output.len() / 16);
    for block in output.as_chunks::<16>().0 {
        assert!(blocks.insert(*block));
    }
    assert_eq!(blocks.len(), output.len() / 16);
}

#[test]
fn aligned_blocks_stay_unique_across_many_keys() {
    for seed in 0..=63_u8 {
        let output = stream(&fixed_key(seed), 16 * 512, 1009);
        let blocks: HashSet<[u8; 16]> = output.as_chunks::<16>().0.iter().copied().collect();
        assert_eq!(blocks.len(), 512, "seed {seed}");
    }
}

#[test]
fn stream_does_not_repeat_common_digest_periods() {
    let output = stream(&fixed_key(137), 16 * 1024, 333);
    for period in [16, 32, 64, 128, 256, 512, 1024, 2048, 4096] {
        assert_ne!(
            output[..output.len() - period],
            output[period..],
            "period {period}"
        );
    }
}

#[test]
fn stream_halves_are_different() {
    let output = stream(&fixed_key(173), 64 * 1024, 521);
    assert_ne!(output[..output.len() / 2], output[output.len() / 2..]);
}

#[test]
fn different_aes_keys_change_stream() {
    let first = stream(&fixed_key(1), 4096, 128);
    let second = stream(&fixed_key(2), 4096, 128);
    assert_ne!(first, second);
}

#[test]
fn zero_buffer_size_is_rejected_before_writing() {
    let mut output = Vec::new();
    let error = write_stream_with_buffer(&mut output, &fixed_key(1), 1, 0).unwrap_err();
    assert!(matches!(error, GenerateError::InvalidConfiguration(_)));
    assert!(output.is_empty());
}

#[test]
fn invalid_stream_sizes_are_rejected_before_writing() {
    for size in [0, MAX_KEY_BYTES + 1, u64::MAX] {
        let mut output = Vec::new();
        let error = write_stream_with_buffer(&mut output, &fixed_key(1), size, 32).unwrap_err();
        assert!(matches!(error, GenerateError::InvalidSize(_)));
        assert!(output.is_empty());
    }
}

struct ShortWriter {
    bytes: Vec<u8>,
    maximum_per_write: usize,
}

impl Write for ShortWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let count = buffer.len().min(self.maximum_per_write);
        self.bytes.extend_from_slice(&buffer[..count]);
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn stream_handles_partial_writes() {
    let key = fixed_key(29);
    let expected = stream(&key, 8193, 1024);
    for maximum_per_write in [1, 2, 7, 15, 16, 31, 100] {
        let mut writer = ShortWriter {
            bytes: Vec::new(),
            maximum_per_write,
        };
        write_stream_with_buffer(&mut writer, &key, 8193, 257).unwrap();
        assert_eq!(writer.bytes, expected, "write size {maximum_per_write}");
    }
}

#[test]
fn every_stream_generator_handles_partial_writes() {
    let key = fixed_key(31);
    for generator in [
        StreamGenerator::Aes256Ctr,
        StreamGenerator::ChaCha20,
        StreamGenerator::Blake3Xof,
    ] {
        let expected = generator_stream(&key, 4097, 4097, generator);
        for maximum_per_write in [1, 7, 16, 31, 100] {
            let mut writer = ShortWriter {
                bytes: Vec::new(),
                maximum_per_write,
            };
            write_stream_with_generator(&mut writer, &key, 4097, 257, generator).unwrap();
            assert_eq!(
                writer.bytes, expected,
                "generator {generator:?}, write size {maximum_per_write}"
            );
        }
    }
}

struct InterruptedOnceWriter {
    bytes: Vec<u8>,
    interrupted: bool,
}

impl Write for InterruptedOnceWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if !self.interrupted {
            self.interrupted = true;
            return Err(io::Error::new(io::ErrorKind::Interrupted, "test interrupt"));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn stream_retries_interrupted_writes() {
    let key = fixed_key(43);
    let mut writer = InterruptedOnceWriter {
        bytes: Vec::new(),
        interrupted: false,
    };
    write_stream_with_buffer(&mut writer, &key, 1000, 91).unwrap();
    assert_eq!(writer.bytes, stream(&key, 1000, 1000));
}

#[test]
fn every_stream_generator_retries_interrupted_writes() {
    let key = fixed_key(47);
    for generator in [
        StreamGenerator::Aes256Ctr,
        StreamGenerator::ChaCha20,
        StreamGenerator::Blake3Xof,
    ] {
        let mut writer = InterruptedOnceWriter {
            bytes: Vec::new(),
            interrupted: false,
        };
        write_stream_with_generator(&mut writer, &key, 1000, 91, generator).unwrap();
        assert_eq!(
            writer.bytes,
            generator_stream(&key, 1000, 1000, generator),
            "generator {generator:?}"
        );
    }
}

struct ZeroWriter;

impl Write for ZeroWriter {
    fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        Ok(0)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn stream_reports_write_zero() {
    let error = write_stream_with_buffer(&mut ZeroWriter, &fixed_key(5), 100, 32)
        .expect_err("zero-length writes must fail");
    assert!(matches!(
        error,
        GenerateError::Io(ref io_error) if io_error.kind() == io::ErrorKind::WriteZero
    ));
}

#[test]
fn every_stream_generator_reports_write_zero() {
    let key = fixed_key(59);
    for generator in [
        StreamGenerator::Aes256Ctr,
        StreamGenerator::ChaCha20,
        StreamGenerator::Blake3Xof,
    ] {
        let error = write_stream_with_generator(&mut ZeroWriter, &key, 100, 32, generator)
            .expect_err("zero-length writes must fail");
        assert!(
            matches!(
                error,
                GenerateError::Io(ref io_error) if io_error.kind() == io::ErrorKind::WriteZero
            ),
            "generator {generator:?}"
        );
    }
}

struct FailingWriter {
    accepted: usize,
    fail_after: usize,
}

impl Write for FailingWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self.accepted >= self.fail_after {
            return Err(io::Error::other("injected failure"));
        }
        let count = buffer.len().min(self.fail_after - self.accepted);
        self.accepted += count;
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn stream_propagates_write_failure() {
    let mut writer = FailingWriter {
        accepted: 0,
        fail_after: 123,
    };
    let error = write_stream_with_buffer(&mut writer, &fixed_key(9), 1000, 64).unwrap_err();
    assert!(matches!(error, GenerateError::Io(_)));
    assert_eq!(writer.accepted, 123);
}

#[test]
fn every_stream_generator_propagates_write_failure() {
    let key = fixed_key(53);
    for generator in [
        StreamGenerator::Aes256Ctr,
        StreamGenerator::ChaCha20,
        StreamGenerator::Blake3Xof,
    ] {
        let mut writer = FailingWriter {
            accepted: 0,
            fail_after: 123,
        };
        let error =
            write_stream_with_generator(&mut writer, &key, 1000, 64, generator).unwrap_err();
        assert!(
            matches!(error, GenerateError::Io(_)),
            "generator {generator:?}"
        );
        assert_eq!(writer.accepted, 123, "generator {generator:?}");
    }
}

#[derive(Default)]
struct TrackingWriter {
    total: u64,
    largest_write: usize,
    writes: usize,
}

impl Write for TrackingWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.total += buffer.len() as u64;
        self.largest_write = self.largest_write.max(buffer.len());
        self.writes += 1;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn production_stream_writes_are_bounded_to_one_mibibyte() {
    let size = STREAM_BUFFER_BYTES as u64 * 2 + 17;
    let mut writer = TrackingWriter::default();
    write_stream_with_buffer(&mut writer, &fixed_key(211), size, STREAM_BUFFER_BYTES).unwrap();
    assert_eq!(writer.total, size);
    assert_eq!(writer.largest_write, STREAM_BUFFER_BYTES);
    assert_eq!(writer.writes, 3);
}

#[test]
fn every_stream_generator_uses_bounded_production_writes() {
    let key = fixed_key(223);
    let size = STREAM_BUFFER_BYTES as u64 * 2 + 17;
    for generator in [
        StreamGenerator::Aes256Ctr,
        StreamGenerator::ChaCha20,
        StreamGenerator::Blake3Xof,
    ] {
        let mut writer = TrackingWriter::default();
        write_stream_with_generator(&mut writer, &key, size, STREAM_BUFFER_BYTES, generator)
            .unwrap();
        assert_eq!(writer.total, size, "generator {generator:?}");
        assert_eq!(
            writer.largest_write, STREAM_BUFFER_BYTES,
            "generator {generator:?}"
        );
        assert_eq!(writer.writes, 3, "generator {generator:?}");
    }
}

#[test]
fn maximum_size_counter_and_chunk_arithmetic_is_safe() {
    let blocks = MAX_KEY_BYTES.div_ceil(AES_BLOCK_BYTES);
    assert_eq!(blocks, 1_250_000_000);

    let chacha_blocks = MAX_KEY_BYTES.div_ceil(64);
    let chacha_capacity_blocks = u64::from(u32::MAX);
    assert_eq!(chacha_blocks, 312_500_000);
    assert!(chacha_blocks < chacha_capacity_blocks);
    assert_eq!(chacha_capacity_blocks * 64, 274_877_906_880);

    let mut remaining = MAX_KEY_BYTES;
    let mut chunks = 0_u64;
    let mut last_chunk = 0_u64;
    while remaining != 0 {
        last_chunk = remaining.min(STREAM_BUFFER_BYTES as u64);
        remaining -= last_chunk;
        chunks += 1;
    }
    assert_eq!(chunks, 19_074);
    assert_eq!(last_chunk, 509_952);
}

#[test]
fn atomic_writer_creates_the_requested_file() {
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join(OUTPUT_FILENAME);
    write_atomically(directory.path(), &output, |file| {
        file.write_all(b"complete key")?;
        Ok(())
    })
    .unwrap();
    assert_eq!(fs::read(output).unwrap(), b"complete key");
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
}

#[test]
fn atomic_writer_replaces_and_truncates_existing_file() {
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join(OUTPUT_FILENAME);
    fs::write(&output, vec![0xaa; 4096]).unwrap();
    write_atomically(directory.path(), &output, |file| {
        file.write_all(b"short")?;
        Ok(())
    })
    .unwrap();
    assert_eq!(fs::read(output).unwrap(), b"short");
}

#[test]
fn atomic_writer_retains_private_complete_temp_on_uncertain_persist_failure() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join(OUTPUT_FILENAME);
    fs::create_dir(&output).unwrap();

    let error = write_atomically(directory.path(), &output, |file| {
        file.write_all(b"complete temporary key")?;
        Ok(())
    })
    .unwrap_err();

    let recovery_path = match &error {
        GenerateError::ReplacementOutcomeUncertain { recovery_path, .. } => recovery_path,
        other => panic!("expected outcome-uncertain replacement error, got {other:?}"),
    };
    assert!(
        error
            .to_string()
            .contains("inspect key.key and retained recovery path")
    );
    assert!(
        error
            .to_string()
            .contains(&recovery_path.display().to_string())
    );
    assert!(output.is_dir());
    assert_eq!(recovery_path.parent(), Some(directory.path()));
    assert!(
        recovery_path
            .file_name()
            .unwrap()
            .as_encoded_bytes()
            .starts_with(b".key.key.")
    );
    assert_eq!(fs::read(recovery_path).unwrap(), b"complete temporary key");
    let metadata = fs::metadata(recovery_path).unwrap();
    assert_eq!(metadata.permissions().mode() & 0o777, OUTPUT_FILE_MODE);
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 2);
}

#[test]
fn atomic_writer_preserves_existing_file_on_failure() {
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join(OUTPUT_FILENAME);
    fs::write(&output, b"old key remains").unwrap();
    let result = write_atomically(directory.path(), &output, |file| {
        file.write_all(b"partial new key")?;
        Err(GenerateError::Io(io::Error::other("injected failure")))
    });
    assert!(result.is_err());
    assert_eq!(fs::read(output).unwrap(), b"old key remains");
}

#[test]
fn atomic_writer_removes_temporary_file_after_failure() {
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join(OUTPUT_FILENAME);
    let _ = write_atomically(directory.path(), &output, |_file| {
        Err(GenerateError::Io(io::Error::other("injected failure")))
    });
    let entries: Vec<_> = fs::read_dir(directory.path()).unwrap().collect();
    assert!(entries.is_empty());
}

#[test]
fn atomic_writer_removes_temporary_file_during_unwind() {
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join(OUTPUT_FILENAME);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _: Result<(), GenerateError> = write_atomically(directory.path(), &output, |file| {
            file.write_all(b"partial secret material")?;
            panic!("injected panic while generating");
        });
    }));

    assert!(result.is_err());
    assert!(!output.exists());
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
}

#[test]
fn generated_file_is_named_key_key_and_has_exact_raw_content() {
    let directory = tempfile::tempdir().unwrap();
    let password = "file fixture password";
    let size = 4097;
    let expected_key = cheap_derived_key(password, size, TEST_CONFIG);
    let expected = stream(&expected_key, size, 31);

    let path = generate_key_file_with_params(
        directory.path(),
        password,
        size,
        TEST_CONFIG,
        cheap_params(),
    )
    .unwrap();
    assert_eq!(path.file_name().unwrap(), OUTPUT_FILENAME);
    assert_eq!(fs::read(path).unwrap(), expected);
}

#[test]
fn generated_file_replaces_a_longer_existing_key() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join(OUTPUT_FILENAME);
    fs::write(&path, vec![0xcc; 10_000]).unwrap();
    generate_key_file_with_params(
        directory.path(),
        "password",
        17,
        TEST_CONFIG,
        cheap_params(),
    )
    .unwrap();
    assert_eq!(fs::metadata(path).unwrap().len(), 17);
}

#[test]
fn generated_key_file_has_owner_only_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().unwrap();
    let path = generate_key_file_with_params(
        directory.path(),
        "password",
        64,
        TEST_CONFIG,
        cheap_params(),
    )
    .unwrap();
    let mode = fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, OUTPUT_FILE_MODE);
}

#[test]
fn generated_key_file_ignores_a_maximally_restrictive_umask() {
    use std::os::unix::fs::PermissionsExt;

    const CHILD_MARKER: &str = "VERSAKEY_UMASK_0777_TEST_CHILD";
    const TEST_NAME: &str = "tests::generated_key_file_ignores_a_maximally_restrictive_umask";

    if std::env::var_os(CHILD_MARKER).is_none() {
        let executable = std::env::current_exe().expect("locate the current unit-test executable");
        let output = std::process::Command::new("/bin/sh")
            .args([
                "-c",
                "umask 0777; exec \"$1\" --exact \"$2\" --nocapture",
                "versakey-umask-test",
            ])
            .arg(executable)
            .arg(TEST_NAME)
            .env(CHILD_MARKER, "1")
            .output()
            .expect("launch isolated umask test process");

        assert!(
            output.status.success(),
            "isolated umask test failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }

    // tempfile directories also honor umask; make the child-owned test
    // directory traversable without altering the process-wide umask.
    let directory = tempfile::tempdir().unwrap();
    let masked_mode = fs::metadata(directory.path()).unwrap().permissions().mode() & 0o777;
    assert_eq!(masked_mode, 0o000, "child process did not apply umask 0777");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let path = generate_key_file_with_params(
        directory.path(),
        "password",
        64,
        TEST_CONFIG,
        cheap_params(),
    )
    .unwrap();

    let mode = fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, OUTPUT_FILE_MODE);
}

#[test]
fn replacing_a_permissive_key_restores_owner_only_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join(OUTPUT_FILENAME);
    fs::write(&path, b"insecure old key").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();

    generate_key_file_with_params(
        directory.path(),
        "password",
        64,
        TEST_CONFIG,
        cheap_params(),
    )
    .unwrap();

    let metadata = fs::metadata(path).unwrap();
    assert_eq!(metadata.len(), 64);
    assert_eq!(metadata.permissions().mode() & 0o777, OUTPUT_FILE_MODE);
}

#[test]
fn replacing_a_key_symlink_does_not_modify_its_target() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().unwrap();
    let victim = directory.path().join("must-not-change");
    let output = directory.path().join(OUTPUT_FILENAME);
    fs::write(&victim, b"unrelated file").unwrap();
    symlink(&victim, &output).unwrap();

    generate_key_file_with_params(
        directory.path(),
        "password",
        64,
        TEST_CONFIG,
        cheap_params(),
    )
    .unwrap();

    assert_eq!(fs::read(&victim).unwrap(), b"unrelated file");
    assert!(
        !fs::symlink_metadata(&output)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::metadata(output).unwrap().len(), 64);
}

#[test]
fn invalid_generation_does_not_touch_existing_file() {
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join(OUTPUT_FILENAME);
    fs::write(&output, b"original").unwrap();
    let error = generate_key_file(
        directory.path(),
        Zeroizing::new("password".to_owned()),
        0,
        TEST_CONFIG,
    )
    .unwrap_err();
    assert!(matches!(error, GenerateError::InvalidSize(_)));
    assert_eq!(fs::read(output).unwrap(), b"original");
}

#[test]
fn invalid_configuration_does_not_touch_existing_file() {
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join(OUTPUT_FILENAME);
    fs::write(&output, b"original").unwrap();
    let invalid = GeneratorConfig {
        application_pepper: b"",
        ..TEST_CONFIG
    };
    let error = generate_key_file(
        directory.path(),
        Zeroizing::new("password".to_owned()),
        64,
        invalid,
    )
    .unwrap_err();
    assert!(matches!(error, GenerateError::InvalidConfiguration(_)));
    assert_eq!(fs::read(output).unwrap(), b"original");
}

#[test]
fn library_rejects_empty_password_without_touching_existing_file() {
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join(OUTPUT_FILENAME);
    fs::write(&output, b"original").unwrap();
    let error = generate_key_file(
        directory.path(),
        Zeroizing::new(String::new()),
        64,
        TEST_CONFIG,
    )
    .unwrap_err();
    assert!(matches!(error, GenerateError::EmptyPassword));
    assert_eq!(fs::read(output).unwrap(), b"original");
}

#[test]
fn every_suite_rejects_invalid_input_without_touching_existing_file() {
    for suite in [
        GeneratorSuite::Argon2idAes256Ctr,
        GeneratorSuite::ScryptAes256Ctr,
        GeneratorSuite::Pbkdf2Sha256Aes256Ctr,
        GeneratorSuite::Argon2idChaCha20,
        GeneratorSuite::Argon2idBlake3Xof,
    ] {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join(OUTPUT_FILENAME);
        fs::write(&output, b"original sentinel").unwrap();

        let invalid_size = generate_key_file_with_suite(
            directory.path(),
            Zeroizing::new("password".to_owned()),
            0,
            TEST_CONFIG,
            suite,
        )
        .unwrap_err();
        assert!(
            matches!(invalid_size, GenerateError::InvalidSize(_)),
            "suite {suite:?}"
        );
        assert_eq!(fs::read(&output).unwrap(), b"original sentinel");

        let empty_password = generate_key_file_with_suite(
            directory.path(),
            Zeroizing::new(String::new()),
            64,
            TEST_CONFIG,
            suite,
        )
        .unwrap_err();
        assert!(
            matches!(empty_password, GenerateError::EmptyPassword),
            "suite {suite:?}"
        );
        assert_eq!(fs::read(&output).unwrap(), b"original sentinel");

        let invalid_config = GeneratorConfig {
            domain: b"",
            ..TEST_CONFIG
        };
        let invalid_config = generate_key_file_with_suite(
            directory.path(),
            Zeroizing::new("password".to_owned()),
            64,
            invalid_config,
            suite,
        )
        .unwrap_err();
        assert!(
            matches!(invalid_config, GenerateError::InvalidConfiguration(_)),
            "suite {suite:?}"
        );
        assert_eq!(fs::read(&output).unwrap(), b"original sentinel");
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }
}

#[test]
fn empty_configuration_fields_are_rejected() {
    let configurations = [
        GeneratorConfig {
            application_salt: b"",
            ..TEST_CONFIG
        },
        GeneratorConfig {
            application_pepper: b"",
            ..TEST_CONFIG
        },
        GeneratorConfig {
            domain: b"",
            ..TEST_CONFIG
        },
    ];
    for config in configurations {
        assert!(matches!(
            validate_config(config),
            Err(GenerateError::InvalidConfiguration(_))
        ));
    }
}

#[test]
fn error_messages_never_include_password_material() {
    let password = "SUPER-SECRET-PASSWORD";
    let config = GeneratorConfig {
        application_pepper: b"",
        ..TEST_CONFIG
    };
    let error = derive_stream_key_with_params(password, 100, config, cheap_params())
        .expect_err("empty pepper must fail");
    assert!(!error.to_string().contains(password));
}
