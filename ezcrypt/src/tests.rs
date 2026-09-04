use crate::cli::{CliCommand, PasswordPrompter, parse_args, request_password};
use crate::crypto::{MAX_PASSWORD_BYTES, decrypt_stream, encrypt_stream, validate_password};
use crate::format::{
    CHUNK_SIZE, HEADER_LEN, HEADER_TAG_LEN, Header, KdfParams, MAGIC, MAX_FILE_LEN, MAX_LANES,
    MAX_MEMORY_KIB, MAX_TIME_COST, MIN_MEMORY_KIB, TAG_LEN, VERSION, chunk_aad, final_aad,
    header_aad,
};
use crate::pathing::{Operation, ensure_destination_absent, plan_for_path};
use crate::transaction::transform_plan;
use crate::{EzError, FormatError};
use std::collections::VecDeque;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, Cursor, Read, Write};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

const TEST_KDF: KdfParams = KdfParams {
    memory_kib: 8_192,
    time_cost: 1,
    lanes: 1,
};
const TEST_PASSWORD: &[u8] = b"correct horse battery staple";
const TEST_SALT: [u8; 16] = [0x31; 16];
const TEST_NONCE: [u8; 16] = [0xa7; 16];

const OFF_VERSION: usize = 8;
const OFF_HEADER_LEN: usize = 10;
const OFF_FLAGS: usize = 12;
const OFF_CHUNK_SIZE: usize = 16;
const OFF_PLAINTEXT_LEN: usize = 20;
const OFF_MEMORY: usize = 28;
const OFF_TIME: usize = 32;
const OFF_LANES: usize = 36;
const OFF_SALT: usize = 40;
const OFF_NONCE: usize = 56;
const OFF_RESERVED: usize = 72;

fn header_for(plaintext_len: u64) -> Header {
    Header::new(plaintext_len, TEST_KDF, TEST_SALT, TEST_NONCE).expect("the test header is valid")
}

fn assert_format_error<T>(result: Result<T, EzError>, expected: FormatError) {
    match result {
        Err(EzError::InvalidFormat(actual)) => assert_eq!(actual, expected),
        Err(other) => panic!("expected format error {expected:?}, got {other:?}"),
        Ok(_) => panic!("expected format error {expected:?}, got success"),
    }
}

fn assert_decoded_format_error(bytes: &[u8], expected: FormatError) {
    assert_eq!(Header::decode(bytes).unwrap_err(), expected);
}

fn fixture_payload(len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| {
            let mixed = index.wrapping_mul(131) ^ index.rotate_left(5) ^ 0x5a;
            mixed as u8
        })
        .collect()
}

fn encrypt_bytes(plaintext: &[u8], password: &[u8]) -> Vec<u8> {
    let mut reader = Cursor::new(plaintext);
    let mut encrypted = Vec::new();
    let written = encrypt_stream(
        &mut reader,
        &mut encrypted,
        plaintext.len() as u64,
        password,
        TEST_KDF,
        TEST_SALT,
        TEST_NONCE,
        Path::new("input.bin"),
        Path::new("output.ez"),
    )
    .expect("fixture encryption succeeds");
    assert_eq!(written, encrypted.len() as u64);
    encrypted
}

fn decrypt_bytes(encrypted: &[u8], password: &[u8]) -> Result<Vec<u8>, EzError> {
    let mut reader = Cursor::new(encrypted);
    let mut plaintext = Vec::new();
    let written = decrypt_stream(
        &mut reader,
        &mut plaintext,
        encrypted.len() as u64,
        password,
        Path::new("input.ez"),
        Path::new("output.bin"),
    )?;
    assert_eq!(written, plaintext.len() as u64);
    Ok(plaintext)
}

fn cached_plaintext() -> &'static [u8] {
    static PLAINTEXT: OnceLock<Vec<u8>> = OnceLock::new();
    PLAINTEXT.get_or_init(|| fixture_payload(257)).as_slice()
}

fn cached_encrypted() -> &'static [u8] {
    static ENCRYPTED: OnceLock<Vec<u8>> = OnceLock::new();
    ENCRYPTED
        .get_or_init(|| encrypt_bytes(cached_plaintext(), TEST_PASSWORD))
        .as_slice()
}

fn cached_two_chunk_plaintext() -> &'static [u8] {
    static PLAINTEXT: OnceLock<Vec<u8>> = OnceLock::new();
    PLAINTEXT
        .get_or_init(|| fixture_payload(CHUNK_SIZE as usize * 2))
        .as_slice()
}

fn cached_two_chunk_encrypted() -> &'static [u8] {
    static ENCRYPTED: OnceLock<Vec<u8>> = OnceLock::new();
    ENCRYPTED
        .get_or_init(|| encrypt_bytes(cached_two_chunk_plaintext(), TEST_PASSWORD))
        .as_slice()
}

fn assert_authentication_failure(encrypted: Vec<u8>) {
    let encrypted_len = encrypted.len() as u64;
    let mut reader = Cursor::new(encrypted.as_slice());
    let mut output = Vec::new();
    let result = decrypt_stream(
        &mut reader,
        &mut output,
        encrypted_len,
        TEST_PASSWORD,
        Path::new("damaged.ez"),
        Path::new("damaged"),
    );
    assert!(matches!(result, Err(EzError::AuthenticationFailed)));
}

macro_rules! encrypt_path_case {
    ($name:ident, $input:expr, $output_name:expr) => {
        #[test]
        fn $name() {
            let plan = plan_for_path($input).expect("path should produce a plan");
            assert_eq!(plan.operation(), Operation::Encrypt);
            assert!(plan.input().is_absolute());
            assert_eq!(plan.output().file_name(), Some(OsStr::new($output_name)));
            assert_eq!(plan.input().parent(), plan.output().parent());
        }
    };
}

macro_rules! decrypt_path_case {
    ($name:ident, $input:expr, $output_name:expr) => {
        #[test]
        fn $name() {
            let plan = plan_for_path($input).expect("path should produce a plan");
            assert_eq!(plan.operation(), Operation::Decrypt);
            assert!(plan.input().is_absolute());
            assert_eq!(plan.output().file_name(), Some(OsStr::new($output_name)));
            assert_eq!(plan.input().parent(), plan.output().parent());
        }
    };
}

macro_rules! invalid_path_case {
    ($name:ident, $input:expr) => {
        #[test]
        fn $name() {
            assert!(matches!(
                plan_for_path($input),
                Err(EzError::InvalidPath(_))
            ));
        }
    };
}

macro_rules! invalid_path_reason_case {
    ($name:ident, $input:expr, $reason:expr) => {
        #[test]
        fn $name() {
            match plan_for_path($input) {
                Err(EzError::InvalidPath(reason)) => assert_eq!(reason, $reason),
                Err(other) => panic!("expected invalid-path error, got {other:?}"),
                Ok(plan) => panic!("expected invalid path, got plan {plan:?}"),
            }
        }
    };
}

macro_rules! ads_path_case {
    ($name:ident, $input:expr) => {
        #[test]
        fn $name() {
            assert!(matches!(
                plan_for_path($input),
                Err(EzError::InvalidPath(
                    "path contains a character reserved by Windows"
                ))
            ));
        }
    };
}

encrypt_path_case!(
    path_encrypts_name_without_extension,
    "document",
    "document.ez"
);
encrypt_path_case!(
    path_encrypts_ordinary_extension,
    "document.txt",
    "document.txt.ez"
);
encrypt_path_case!(
    path_encrypts_multiple_extensions,
    "archive.tar.gz",
    "archive.tar.gz.ez"
);
encrypt_path_case!(path_encrypts_dotfile, ".secret", ".secret.ez");
encrypt_path_case!(
    path_encrypts_embedded_ez,
    "report.ez.backup",
    "report.ez.backup.ez"
);
encrypt_path_case!(path_encrypts_ez_prefix, "ez.report", "ez.report.ez");
encrypt_path_case!(path_encrypts_ezx_suffix, "report.ezx", "report.ezx.ez");
encrypt_path_case!(path_encrypts_ez_without_dot, "reportez", "reportez.ez");
encrypt_path_case!(
    path_encrypts_name_with_spaces,
    "my report 2026.txt",
    "my report 2026.txt.ez"
);
encrypt_path_case!(path_encrypts_latin_unicode, "résumé.pdf", "résumé.pdf.ez");
encrypt_path_case!(path_encrypts_cjk_unicode, "資料.bin", "資料.bin.ez");
encrypt_path_case!(
    path_encrypts_emoji_unicode,
    "vault-🔐.bin",
    "vault-🔐.bin.ez"
);
encrypt_path_case!(path_encrypts_combining_unicode, "résumé", "résumé.ez");
encrypt_path_case!(path_encrypts_arabic_unicode, "ملف.dat", "ملف.dat.ez");
encrypt_path_case!(
    path_ignores_ez_on_parent_directory,
    r"folder.ez\plain.txt",
    "plain.txt.ez"
);
encrypt_path_case!(
    path_accepts_explicit_current_directory,
    r".\plain.txt",
    "plain.txt.ez"
);
encrypt_path_case!(
    path_accepts_absolute_drive_letter_path,
    r"C:\folder\plain.txt",
    "plain.txt.ez"
);
encrypt_path_case!(
    path_accepts_verbatim_drive_letter_path,
    r"\\?\C:\folder\plain.txt",
    "plain.txt.ez"
);
encrypt_path_case!(
    path_does_not_fold_fullwidth_ez,
    "report.ｅｚ",
    "report.ｅｚ.ez"
);
encrypt_path_case!(path_encrypts_single_character_name, "x", "x.ez");
encrypt_path_case!(path_encrypts_single_dot_prefix_name, ".x", ".x.ez");

decrypt_path_case!(path_decrypts_lowercase_suffix, "document.ez", "document");
decrypt_path_case!(path_decrypts_uppercase_suffix, "document.EZ", "document");
decrypt_path_case!(path_decrypts_mixed_suffix_ez, "document.eZ", "document");
decrypt_path_case!(
    path_decrypts_upper_e_lower_z_suffix,
    "document.Ez",
    "document"
);
decrypt_path_case!(
    path_decrypts_multiple_extensions,
    "archive.tar.gz.ez",
    "archive.tar.gz"
);
decrypt_path_case!(path_decrypts_dotfile, ".secret.ez", ".secret");
decrypt_path_case!(path_decrypts_latin_unicode, "résumé.pdf.ez", "résumé.pdf");
decrypt_path_case!(path_decrypts_cjk_unicode, "資料.ez", "資料");
decrypt_path_case!(path_decrypts_emoji_unicode, "vault-🔐.ez", "vault-🔐");
decrypt_path_case!(path_decrypts_name_with_spaces, "my report.ez", "my report");
decrypt_path_case!(path_strips_only_one_suffix, "document.ez.ez", "document.ez");
decrypt_path_case!(
    path_strips_one_of_three_suffixes,
    "document.ez.ez.ez",
    "document.ez.ez"
);

decrypt_path_case!(
    path_decrypts_leading_double_dot_regular_name,
    "..hidden.ez",
    "..hidden"
);
decrypt_path_case!(
    path_decrypts_internal_repeated_dots,
    "archive...part.ez",
    "archive...part"
);
decrypt_path_case!(
    path_decrypts_suffix_named_dotfile_from_double_suffix,
    ".ez.ez",
    ".ez"
);

encrypt_path_case!(path_accepts_con_prefix_near_miss, "CONSOLE", "CONSOLE.ez");
encrypt_path_case!(path_accepts_com_zero_near_miss, "COM0", "COM0.ez");
encrypt_path_case!(path_accepts_com_ten_near_miss, "COM10", "COM10.ez");
encrypt_path_case!(
    path_accepts_com_superscript_zero_near_miss,
    "COM⁰",
    "COM⁰.ez"
);
encrypt_path_case!(path_accepts_lpt_zero_near_miss, "LPT0", "LPT0.ez");
encrypt_path_case!(path_accepts_lpt_ten_near_miss, "LPT10", "LPT10.ez");
encrypt_path_case!(
    path_accepts_reserved_text_after_normal_stem,
    "x.CON",
    "x.CON.ez"
);
decrypt_path_case!(path_decrypts_com_ten_near_miss, "COM10.ez", "COM10");
decrypt_path_case!(path_decrypts_lpt_zero_near_miss, "LPT0.ez", "LPT0");
decrypt_path_case!(
    path_decrypts_reserved_text_after_normal_stem,
    "x.CON.ez",
    "x.CON"
);

invalid_path_case!(path_rejects_empty_path, "");
invalid_path_case!(path_rejects_suffix_only_lowercase, ".ez");
invalid_path_case!(path_rejects_suffix_only_uppercase, ".EZ");
invalid_path_case!(path_rejects_suffix_only_mixed_ez, ".eZ");
invalid_path_case!(path_rejects_suffix_only_upper_e_lower_z, ".Ez");
invalid_path_case!(path_rejects_drive_root, r"C:\");
invalid_path_case!(path_rejects_reserved_con_uppercase, "CON");
invalid_path_case!(path_rejects_reserved_con_lowercase, "con");
invalid_path_case!(path_rejects_reserved_con_mixed_case, "CoN");
invalid_path_case!(path_rejects_reserved_con_with_extension, "CON.txt");
invalid_path_case!(path_rejects_reserved_nul_uppercase, "NUL");
invalid_path_case!(path_rejects_reserved_nul_with_extension, "nul.dat");
invalid_path_case!(path_rejects_reserved_prn_uppercase, "PRN");
invalid_path_case!(path_rejects_reserved_prn_with_extension, "prn.txt");
invalid_path_case!(path_rejects_reserved_aux_uppercase, "AUX");
invalid_path_case!(path_rejects_reserved_aux_mixed_case_extension, "Aux.bin");
invalid_path_case!(path_rejects_reserved_com1_uppercase, "COM1");
invalid_path_case!(path_rejects_reserved_com1_extension, "com1.log");
invalid_path_case!(path_rejects_reserved_com9_uppercase, "COM9");
invalid_path_case!(path_rejects_reserved_com9_extension, "com9.log");
invalid_path_case!(path_rejects_reserved_com_superscript_one, "COM¹");
invalid_path_case!(
    path_rejects_reserved_com_superscript_two_extension,
    "com².log"
);
invalid_path_case!(
    path_rejects_reserved_com_superscript_three_mixed_case,
    "CoM³"
);
invalid_path_case!(path_rejects_reserved_lpt1_uppercase, "LPT1");
invalid_path_case!(path_rejects_reserved_lpt1_extension, "lpt1.log");
invalid_path_case!(path_rejects_reserved_lpt9_uppercase, "LPT9");
invalid_path_case!(path_rejects_reserved_lpt9_extension, "lpt9.log");
invalid_path_case!(path_rejects_reserved_lpt_superscript_one, "LPT¹");
invalid_path_case!(
    path_rejects_reserved_lpt_superscript_two_extension,
    "lpt².log"
);
invalid_path_case!(
    path_rejects_reserved_lpt_superscript_three_mixed_case,
    "LpT³"
);
invalid_path_case!(path_rejects_reserved_con_parent_component, r"CON\file.txt");
invalid_path_case!(
    path_rejects_reserved_nul_nested_component,
    r"folder\nul\file.txt"
);
invalid_path_case!(
    path_rejects_reserved_aux_absolute_component,
    r"C:\AUX\file.txt"
);
invalid_path_case!(
    path_rejects_reserved_com1_extension_as_parent,
    r"folder\COM1.dat\file.txt"
);
invalid_path_case!(
    path_rejects_reserved_lpt9_parent_component,
    r"LPT9\file.txt"
);
invalid_path_case!(
    path_rejects_reserved_com_superscript_parent_component,
    r"folder\COM².dat\file.txt"
);
invalid_path_case!(path_rejects_decrypt_output_reserved_con, "CON.ez");
invalid_path_case!(
    path_rejects_decrypt_output_reserved_aux_mixed_case,
    "aux.EZ"
);
invalid_path_case!(path_rejects_decrypt_output_reserved_com1, "com1.ez");
invalid_path_case!(path_rejects_decrypt_output_reserved_lpt9, "lpt9.eZ");
invalid_path_case!(
    path_rejects_decrypt_output_reserved_lpt_superscript_three,
    "lpt³.ez"
);
invalid_path_case!(path_rejects_decrypt_output_ending_in_dot, "foo..ez");
invalid_path_case!(path_rejects_decrypt_output_ending_in_space, "foo .ez");
invalid_path_case!(path_rejects_decrypt_output_equal_to_dot, "..ez");
invalid_path_case!(path_rejects_decrypt_output_equal_to_dot_dot, "...ez");
invalid_path_case!(path_rejects_decrypt_output_ending_in_two_dots, "foo...ez");
invalid_path_case!(path_rejects_decrypt_output_ending_in_two_spaces, "foo  .ez");
invalid_path_case!(
    path_rejects_decrypt_output_ending_in_dot_then_space,
    "foo. .ez"
);
invalid_path_case!(
    path_rejects_mixed_case_decrypt_output_ending_in_dot,
    "foo..EZ"
);
invalid_path_case!(
    path_rejects_mixed_case_decrypt_output_ending_in_space,
    "foo .eZ"
);
invalid_path_case!(
    path_rejects_nested_decrypt_output_ending_in_dot,
    r"folder\foo..ez"
);
invalid_path_reason_case!(
    path_rejects_final_component_ending_in_dot,
    "trailing.",
    "path components ending in a dot or space are ambiguous on Windows"
);
invalid_path_reason_case!(
    path_rejects_final_component_ending_in_space,
    "trailing ",
    "path components ending in a dot or space are ambiguous on Windows"
);
invalid_path_reason_case!(
    path_rejects_parent_component_ending_in_dot,
    r"folder.\plain.txt",
    "path components ending in a dot or space are ambiguous on Windows"
);
invalid_path_reason_case!(
    path_rejects_parent_component_ending_in_space,
    r"folder \plain.txt",
    "path components ending in a dot or space are ambiguous on Windows"
);
invalid_path_reason_case!(
    path_rejects_ez_name_with_ambiguous_trailing_dot,
    "secret.ez.",
    "path components ending in a dot or space are ambiguous on Windows"
);
invalid_path_reason_case!(
    path_rejects_ez_name_with_ambiguous_trailing_space,
    "secret.ez ",
    "path components ending in a dot or space are ambiguous on Windows"
);
invalid_path_reason_case!(
    path_rejects_leading_parent_directory,
    r"..\plain.txt",
    "parent-directory components are not allowed"
);
invalid_path_reason_case!(
    path_rejects_nested_parent_directory,
    r"folder\..\plain.txt",
    "parent-directory components are not allowed"
);
invalid_path_reason_case!(
    path_rejects_parent_directory_in_absolute_path,
    r"C:\folder\..\plain.txt",
    "parent-directory components are not allowed"
);
invalid_path_reason_case!(
    path_rejects_parent_directory_after_multiple_components,
    r"folder\child\..\plain.txt",
    "parent-directory components are not allowed"
);
invalid_path_reason_case!(
    path_rejects_unc_prefix,
    r"\\server\share\plain.txt",
    "only local drive-letter paths are supported"
);
invalid_path_reason_case!(
    path_rejects_verbatim_unc_prefix,
    r"\\?\UNC\server\share\plain.txt",
    "only local drive-letter paths are supported"
);
invalid_path_reason_case!(
    path_rejects_device_namespace_prefix,
    r"\\.\C:\plain.txt",
    "only local drive-letter paths are supported"
);
invalid_path_reason_case!(
    path_rejects_named_pipe_prefix,
    r"\\.\pipe\ezcrypt-test",
    "only local drive-letter paths are supported"
);
invalid_path_reason_case!(
    path_rejects_volume_guid_prefix,
    r"\\?\Volume{12345678-1234-1234-1234-123456789abc}\plain.txt",
    "only local drive-letter paths are supported"
);
ads_path_case!(path_rejects_simple_alternate_stream, "file:secret");
ads_path_case!(path_rejects_named_data_stream, "file.txt:secret:$DATA");
ads_path_case!(
    path_rejects_nested_alternate_stream,
    r"folder\file.bin:metadata"
);
ads_path_case!(path_rejects_colon_only_file_name, ":");

#[test]
fn path_preserves_unpaired_utf16_surrogate() {
    let original = OsString::from_wide(&[0xd800, b'.' as u16, b'x' as u16]);
    let plan = plan_for_path(PathBuf::from(&original)).unwrap();
    let output: Vec<u16> = plan.output().file_name().unwrap().encode_wide().collect();
    assert_eq!(
        output,
        [
            0xd800,
            b'.' as u16,
            b'x' as u16,
            b'.' as u16,
            b'e' as u16,
            b'z' as u16
        ]
    );
}

#[test]
fn path_accepts_252_unit_plain_name_whose_encrypted_name_is_255_units() {
    let name = "a".repeat(252);
    let plan = plan_for_path(&name).unwrap();
    assert_eq!(plan.operation(), Operation::Encrypt);
    assert_eq!(
        plan.output().file_name().unwrap().encode_wide().count(),
        255
    );
}

#[test]
fn path_rejects_253_unit_plain_name_because_suffix_would_exceed_limit() {
    let name = "a".repeat(253);
    match plan_for_path(&name) {
        Err(EzError::InvalidPath(reason)) => {
            assert_eq!(reason, "encrypted file name would exceed 255 UTF-16 units")
        }
        other => panic!("unexpected result: {other:?}"),
    }
}

#[test]
fn path_rejects_255_unit_plain_name_because_suffix_would_exceed_limit() {
    let name = "a".repeat(255);
    match plan_for_path(&name) {
        Err(EzError::InvalidPath(reason)) => {
            assert_eq!(reason, "encrypted file name would exceed 255 UTF-16 units")
        }
        other => panic!("unexpected result: {other:?}"),
    }
}

#[test]
fn path_rejects_256_unit_component_before_absolute_resolution() {
    let name = "a".repeat(256);
    match plan_for_path(&name) {
        Err(EzError::InvalidPath(reason)) => {
            assert_eq!(reason, "path component exceeds 255 UTF-16 units")
        }
        other => panic!("unexpected result: {other:?}"),
    }
}

#[test]
fn path_accepts_255_unit_encrypted_name_for_decryption() {
    let encrypted_name = format!("{}.ez", "a".repeat(252));
    let plan = plan_for_path(&encrypted_name).unwrap();
    assert_eq!(plan.operation(), Operation::Decrypt);
    assert_eq!(
        plan.output().file_name().unwrap().encode_wide().count(),
        252
    );
}

#[test]
fn path_rejects_256_unit_encrypted_name() {
    let encrypted_name = format!("{}.ez", "a".repeat(253));
    match plan_for_path(&encrypted_name) {
        Err(EzError::InvalidPath(reason)) => {
            assert_eq!(reason, "path component exceeds 255 UTF-16 units")
        }
        other => panic!("unexpected result: {other:?}"),
    }
}

#[test]
fn path_counts_non_bmp_characters_as_two_utf16_units_when_encrypting() {
    let name = "🔐".repeat(126);
    assert_eq!(OsStr::new(&name).encode_wide().count(), 252);
    let plan = plan_for_path(&name).unwrap();
    assert_eq!(
        plan.output().file_name().unwrap().encode_wide().count(),
        255
    );
}

#[test]
fn path_rejects_non_bmp_name_when_suffix_exceeds_utf16_limit() {
    let name = "🔐".repeat(127);
    assert_eq!(OsStr::new(&name).encode_wide().count(), 254);
    assert!(matches!(
        plan_for_path(&name),
        Err(EzError::InvalidPath(
            "encrypted file name would exceed 255 UTF-16 units"
        ))
    ));
}

#[test]
fn path_rejects_non_bmp_component_over_utf16_limit() {
    let name = "🔐".repeat(128);
    assert_eq!(OsStr::new(&name).encode_wide().count(), 256);
    assert!(matches!(
        plan_for_path(&name),
        Err(EzError::InvalidPath(
            "path component exceeds 255 UTF-16 units"
        ))
    ));
}

#[test]
fn unsupported_drive_error_explains_local_fixed_drive_requirement() {
    let message = EzError::UnsupportedDrive(PathBuf::from(r"Z:\example.bin")).to_string();
    assert!(message.contains("not on a local fixed drive"));
    assert!(message.contains("example.bin"));
}

#[test]
fn operation_past_tense_is_stable_for_encrypt() {
    assert_eq!(Operation::Encrypt.past_tense(), "Encrypted");
}

#[test]
fn operation_past_tense_is_stable_for_decrypt() {
    assert_eq!(Operation::Decrypt.past_tense(), "Decrypted");
}

macro_rules! cli_transform_case {
    ($name:ident, $value:expr) => {
        #[test]
        fn $name() {
            let value = OsString::from($value);
            assert_eq!(
                parse_args([value.clone()]).unwrap(),
                CliCommand::Transform(PathBuf::from(value))
            );
        }
    };
}

macro_rules! cli_unknown_option_case {
    ($name:ident, $value:expr) => {
        #[test]
        fn $name() {
            let error = parse_args([OsString::from($value)]).unwrap_err();
            assert_eq!(
                error.0,
                "unknown option; use -- before a file name that starts with '-'"
            );
        }
    };
}

macro_rules! cli_separator_case {
    ($name:ident, $value:expr) => {
        #[test]
        fn $name() {
            let value = OsString::from($value);
            assert_eq!(
                parse_args([OsString::from("--"), value.clone()]).unwrap(),
                CliCommand::Transform(PathBuf::from(value))
            );
        }
    };
}

cli_transform_case!(cli_accepts_plain_file_name, "file.txt");
cli_transform_case!(cli_accepts_encrypted_file_name, "file.txt.ez");
cli_transform_case!(cli_accepts_dotfile, ".secret");
cli_transform_case!(cli_accepts_spaces, "my file.txt");
cli_transform_case!(cli_accepts_latin_unicode, "résumé.txt");
cli_transform_case!(cli_accepts_cjk_unicode, "資料.bin");
cli_transform_case!(cli_accepts_emoji_unicode, "🔐.dat");
cli_transform_case!(cli_accepts_relative_subdirectory, r"folder\file.txt");
cli_transform_case!(cli_accepts_absolute_drive_path, r"C:\data\file.txt");
cli_transform_case!(cli_accepts_unc_path, r"\\server\share\file.txt");
cli_transform_case!(cli_accepts_leading_space, " file.txt");
cli_transform_case!(cli_accepts_trailing_space_for_later_validation, "file.txt ");

cli_unknown_option_case!(cli_rejects_short_unknown_option, "-x");
cli_unknown_option_case!(cli_rejects_long_unknown_option, "--verbose");
cli_unknown_option_case!(cli_rejects_password_option, "--password");
cli_unknown_option_case!(cli_rejects_inline_password_option, "--password=secret");
cli_unknown_option_case!(cli_rejects_short_password_option, "-p");
cli_unknown_option_case!(cli_rejects_dash_file_without_separator, "-file.txt");
cli_unknown_option_case!(cli_rejects_triple_dash, "---");
cli_unknown_option_case!(cli_rejects_help_assignment, "--help=yes");
cli_unknown_option_case!(cli_rejects_version_assignment, "--version=1");
cli_unknown_option_case!(cli_rejects_single_dash, "-");

cli_separator_case!(cli_separator_allows_dash_file, "-file.txt");
cli_separator_case!(cli_separator_allows_help_as_file, "--help");
cli_separator_case!(cli_separator_allows_version_as_file, "--version");
cli_separator_case!(
    cli_separator_allows_password_text_as_file,
    "--password=secret"
);
cli_separator_case!(cli_separator_allows_triple_dash_file, "---");
cli_separator_case!(cli_separator_allows_single_dash_file, "-");

#[test]
fn cli_accepts_long_help() {
    assert_eq!(
        parse_args([OsString::from("--help")]).unwrap(),
        CliCommand::Help
    );
}

#[test]
fn cli_accepts_short_help() {
    assert_eq!(
        parse_args([OsString::from("-h")]).unwrap(),
        CliCommand::Help
    );
}

#[test]
fn cli_accepts_long_version() {
    assert_eq!(
        parse_args([OsString::from("--version")]).unwrap(),
        CliCommand::Version
    );
}

#[test]
fn cli_accepts_short_version() {
    assert_eq!(
        parse_args([OsString::from("-V")]).unwrap(),
        CliCommand::Version
    );
}

#[test]
fn cli_rejects_zero_arguments() {
    assert_eq!(
        parse_args(Vec::<OsString>::new()).unwrap_err().0,
        "exactly one file name is required"
    );
}

#[test]
fn cli_rejects_two_file_names() {
    assert_eq!(
        parse_args([OsString::from("one"), OsString::from("two")])
            .unwrap_err()
            .0,
        "exactly one file name is required"
    );
}

#[test]
fn cli_rejects_three_file_names() {
    assert_eq!(
        parse_args([
            OsString::from("one"),
            OsString::from("two"),
            OsString::from("three"),
        ])
        .unwrap_err()
        .0,
        "exactly one file name is required"
    );
}

#[test]
fn cli_rejects_separator_without_file() {
    assert_eq!(
        parse_args([OsString::from("--")]).unwrap_err().0,
        "exactly one file name is required"
    );
}

#[test]
fn cli_rejects_separator_with_two_files() {
    assert_eq!(
        parse_args([
            OsString::from("--"),
            OsString::from("one"),
            OsString::from("two"),
        ])
        .unwrap_err()
        .0,
        "exactly one file name is required"
    );
}

#[test]
fn cli_rejects_extra_separator_after_file() {
    assert_eq!(
        parse_args([OsString::from("one"), OsString::from("--")])
            .unwrap_err()
            .0,
        "exactly one file name is required"
    );
}

#[test]
fn cli_rejects_two_separators_and_file() {
    assert_eq!(
        parse_args([
            OsString::from("--"),
            OsString::from("--"),
            OsString::from("file"),
        ])
        .unwrap_err()
        .0,
        "exactly one file name is required"
    );
}

#[test]
fn cli_rejects_non_unicode_dash_option() {
    let value = OsString::from_wide(&[b'-' as u16, 0xd800]);
    assert!(parse_args([value]).is_err());
}

enum PromptReply {
    Text(String),
    Error(io::ErrorKind),
}

struct ScriptedPrompter {
    replies: VecDeque<PromptReply>,
    prompts: Vec<String>,
}

impl ScriptedPrompter {
    fn texts(values: &[&str]) -> Self {
        Self {
            replies: values
                .iter()
                .map(|value| PromptReply::Text((*value).to_owned()))
                .collect(),
            prompts: Vec::new(),
        }
    }

    fn with_replies(replies: impl IntoIterator<Item = PromptReply>) -> Self {
        Self {
            replies: replies.into_iter().collect(),
            prompts: Vec::new(),
        }
    }
}

impl PasswordPrompter for ScriptedPrompter {
    fn prompt(&mut self, prompt: &str) -> io::Result<String> {
        self.prompts.push(prompt.to_owned());
        match self
            .replies
            .pop_front()
            .expect("test supplied enough replies")
        {
            PromptReply::Text(value) => Ok(value),
            PromptReply::Error(kind) => Err(io::Error::new(kind, "injected prompt failure")),
        }
    }
}

macro_rules! valid_password_length_case {
    ($name:ident, $length:expr) => {
        #[test]
        fn $name() {
            let password = vec![b'x'; $length];
            validate_password(&password).unwrap();
        }
    };
}

valid_password_length_case!(password_accepts_one_byte, 1);
valid_password_length_case!(password_accepts_two_bytes, 2);
valid_password_length_case!(password_accepts_fifteen_bytes, 15);
valid_password_length_case!(password_accepts_sixteen_bytes, 16);
valid_password_length_case!(password_accepts_seventeen_bytes, 17);
valid_password_length_case!(password_accepts_255_bytes, 255);
valid_password_length_case!(password_accepts_1024_bytes, 1_024);
valid_password_length_case!(password_accepts_4096_bytes, 4_096);
valid_password_length_case!(password_accepts_65536_bytes, 65_536);
valid_password_length_case!(password_accepts_maximum_bytes, MAX_PASSWORD_BYTES);

#[test]
fn password_rejects_empty_value() {
    assert!(matches!(
        validate_password(b""),
        Err(EzError::InvalidPassword("password must not be empty"))
    ));
}

#[test]
fn password_rejects_one_over_maximum() {
    let password = vec![b'x'; MAX_PASSWORD_BYTES + 1];
    assert!(matches!(
        validate_password(&password),
        Err(EzError::InvalidPassword("password is too long"))
    ));
}

#[test]
fn password_encrypt_prompts_twice_and_accepts_match() {
    let mut prompt = ScriptedPrompter::texts(&["secret", "secret"]);
    let password = request_password(Operation::Encrypt, &mut prompt).unwrap();
    assert_eq!(password.as_str(), "secret");
    assert_eq!(prompt.prompts, ["Password: ", "Confirm password: "]);
}

#[test]
fn password_decrypt_prompts_once() {
    let mut prompt = ScriptedPrompter::texts(&["secret", "unused"]);
    let password = request_password(Operation::Decrypt, &mut prompt).unwrap();
    assert_eq!(password.as_str(), "secret");
    assert_eq!(prompt.prompts, ["Password: "]);
    assert_eq!(prompt.replies.len(), 1);
}

#[test]
fn password_encrypt_rejects_text_mismatch() {
    let mut prompt = ScriptedPrompter::texts(&["secret", "different"]);
    assert!(matches!(
        request_password(Operation::Encrypt, &mut prompt),
        Err(EzError::InvalidPassword("confirmation does not match"))
    ));
}

#[test]
fn password_encrypt_rejects_case_mismatch() {
    let mut prompt = ScriptedPrompter::texts(&["Secret", "secret"]);
    assert!(request_password(Operation::Encrypt, &mut prompt).is_err());
}

#[test]
fn password_encrypt_rejects_unicode_normalization_mismatch() {
    let mut prompt = ScriptedPrompter::texts(&["é", "é"]);
    assert!(request_password(Operation::Encrypt, &mut prompt).is_err());
}

#[test]
fn password_encrypt_accepts_exact_unicode_match() {
    let mut prompt = ScriptedPrompter::texts(&["密碼🔐", "密碼🔐"]);
    assert_eq!(
        request_password(Operation::Encrypt, &mut prompt)
            .unwrap()
            .as_str(),
        "密碼🔐"
    );
}

#[test]
fn password_encrypt_accepts_embedded_nul_match() {
    let mut prompt = ScriptedPrompter::texts(&["a\0b", "a\0b"]);
    assert_eq!(
        request_password(Operation::Encrypt, &mut prompt)
            .unwrap()
            .as_bytes(),
        b"a\0b"
    );
}

#[test]
fn password_encrypt_rejects_empty_before_confirmation() {
    let mut prompt = ScriptedPrompter::texts(&["", ""]);
    assert!(matches!(
        request_password(Operation::Encrypt, &mut prompt),
        Err(EzError::InvalidPassword("password must not be empty"))
    ));
    assert_eq!(prompt.prompts, ["Password: "]);
}

#[test]
fn password_decrypt_rejects_empty() {
    let mut prompt = ScriptedPrompter::texts(&[""]);
    assert!(request_password(Operation::Decrypt, &mut prompt).is_err());
    assert_eq!(prompt.prompts, ["Password: "]);
}

#[test]
fn password_propagates_first_prompt_error() {
    let mut prompt =
        ScriptedPrompter::with_replies([PromptReply::Error(io::ErrorKind::Interrupted)]);
    match request_password(Operation::Encrypt, &mut prompt) {
        Err(EzError::PasswordPrompt(error)) => assert_eq!(error.kind(), io::ErrorKind::Interrupted),
        other => panic!("unexpected result: {other:?}"),
    }
    assert_eq!(prompt.prompts, ["Password: "]);
}

#[test]
fn password_propagates_confirmation_prompt_error() {
    let mut prompt = ScriptedPrompter::with_replies([
        PromptReply::Text("secret".to_owned()),
        PromptReply::Error(io::ErrorKind::UnexpectedEof),
    ]);
    match request_password(Operation::Encrypt, &mut prompt) {
        Err(EzError::PasswordPrompt(error)) => {
            assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof)
        }
        other => panic!("unexpected result: {other:?}"),
    }
    assert_eq!(prompt.prompts, ["Password: ", "Confirm password: "]);
}

macro_rules! valid_kdf_case {
    ($name:ident, $memory:expr, $time:expr, $lanes:expr) => {
        #[test]
        fn $name() {
            KdfParams {
                memory_kib: $memory,
                time_cost: $time,
                lanes: $lanes,
            }
            .validate()
            .unwrap();
        }
    };
}

macro_rules! invalid_kdf_case {
    ($name:ident, $memory:expr, $time:expr, $lanes:expr) => {
        #[test]
        fn $name() {
            assert_eq!(
                KdfParams {
                    memory_kib: $memory,
                    time_cost: $time,
                    lanes: $lanes,
                }
                .validate()
                .unwrap_err(),
                FormatError::InvalidKdfParameters
            );
        }
    };
}

valid_kdf_case!(kdf_accepts_minimum_memory, MIN_MEMORY_KIB, 1, 1);
valid_kdf_case!(kdf_accepts_maximum_memory, MAX_MEMORY_KIB, 1, 1);
valid_kdf_case!(kdf_accepts_time_cost_one, MIN_MEMORY_KIB, 1, 1);
valid_kdf_case!(kdf_accepts_time_cost_two, MIN_MEMORY_KIB, 2, 1);
valid_kdf_case!(kdf_accepts_time_cost_three, MIN_MEMORY_KIB, 3, 1);
invalid_kdf_case!(kdf_rejects_time_cost_four, MIN_MEMORY_KIB, 4, 1);
invalid_kdf_case!(kdf_rejects_time_cost_five, MIN_MEMORY_KIB, 5, 1);
valid_kdf_case!(
    kdf_accepts_maximum_time_cost,
    MIN_MEMORY_KIB,
    MAX_TIME_COST,
    1
);
valid_kdf_case!(kdf_accepts_one_lane, MIN_MEMORY_KIB, 1, 1);
invalid_kdf_case!(kdf_rejects_two_lanes, MIN_MEMORY_KIB, 1, 2);
invalid_kdf_case!(kdf_rejects_three_lanes, MIN_MEMORY_KIB, 1, 3);
valid_kdf_case!(kdf_accepts_maximum_lanes, MIN_MEMORY_KIB, 1, MAX_LANES);

invalid_kdf_case!(kdf_rejects_zero_memory, 0, 1, 1);
invalid_kdf_case!(kdf_rejects_one_kib_memory, 1, 1, 1);
invalid_kdf_case!(kdf_rejects_memory_below_minimum, MIN_MEMORY_KIB - 1, 1, 1);
invalid_kdf_case!(kdf_rejects_memory_above_maximum, MAX_MEMORY_KIB + 1, 1, 1);
invalid_kdf_case!(kdf_rejects_max_u32_memory, u32::MAX, 1, 1);
invalid_kdf_case!(kdf_rejects_zero_time_cost, MIN_MEMORY_KIB, 0, 1);
invalid_kdf_case!(
    kdf_rejects_time_above_maximum,
    MIN_MEMORY_KIB,
    MAX_TIME_COST + 1,
    1
);
invalid_kdf_case!(kdf_rejects_max_u32_time, MIN_MEMORY_KIB, u32::MAX, 1);
invalid_kdf_case!(kdf_rejects_zero_lanes, MIN_MEMORY_KIB, 1, 0);
invalid_kdf_case!(
    kdf_rejects_lanes_above_maximum,
    MIN_MEMORY_KIB,
    1,
    MAX_LANES + 1
);
invalid_kdf_case!(kdf_rejects_max_u32_lanes, MIN_MEMORY_KIB, 1, u32::MAX);

macro_rules! header_roundtrip_case {
    ($name:ident, $length:expr) => {
        #[test]
        fn $name() {
            let header = header_for($length);
            let encoded = header.encode();
            assert_eq!(encoded.len(), HEADER_LEN);
            assert_eq!(Header::decode(&encoded).unwrap(), header);
        }
    };
}

header_roundtrip_case!(header_roundtrips_zero_length, 0);
header_roundtrip_case!(header_roundtrips_one_byte, 1);
header_roundtrip_case!(header_roundtrips_fifteen_bytes, 15);
header_roundtrip_case!(header_roundtrips_sixteen_bytes, 16);
header_roundtrip_case!(header_roundtrips_seventeen_bytes, 17);
header_roundtrip_case!(header_roundtrips_chunk_minus_one, CHUNK_SIZE as u64 - 1);
header_roundtrip_case!(header_roundtrips_exact_chunk, CHUNK_SIZE as u64);
header_roundtrip_case!(header_roundtrips_chunk_plus_one, CHUNK_SIZE as u64 + 1);
header_roundtrip_case!(
    header_roundtrips_two_chunks_minus_one,
    CHUNK_SIZE as u64 * 2 - 1
);
header_roundtrip_case!(header_roundtrips_exactly_two_chunks, CHUNK_SIZE as u64 * 2);
header_roundtrip_case!(
    header_roundtrips_two_chunks_plus_one,
    CHUNK_SIZE as u64 * 2 + 1
);
header_roundtrip_case!(header_roundtrips_many_chunks, CHUNK_SIZE as u64 * 97 + 123);

#[test]
fn header_encoding_has_expected_magic() {
    assert_eq!(&header_for(123).encode()[..8], &MAGIC);
}

#[test]
fn header_encoding_has_expected_version() {
    assert_eq!(
        u16::from_le_bytes(
            header_for(123).encode()[OFF_VERSION..OFF_VERSION + 2]
                .try_into()
                .unwrap()
        ),
        VERSION
    );
}

#[test]
fn header_encoding_is_little_endian_for_plaintext_length() {
    let length = 0x0102_0304_0506_0708;
    assert_eq!(
        &header_for(length).encode()[OFF_PLAINTEXT_LEN..OFF_PLAINTEXT_LEN + 8],
        &length.to_le_bytes()
    );
}

#[test]
fn header_rejects_all_zero_salt() {
    assert_eq!(
        Header::new(0, TEST_KDF, [0; 16], TEST_NONCE).unwrap_err(),
        FormatError::InvalidSalt
    );
}

#[test]
fn header_rejects_all_zero_nonce_prefix() {
    assert_eq!(
        Header::new(0, TEST_KDF, TEST_SALT, [0; 16]).unwrap_err(),
        FormatError::InvalidNonce
    );
}

#[test]
fn header_accepts_salt_with_single_nonzero_byte() {
    let mut salt = [0; 16];
    salt[15] = 1;
    Header::new(0, TEST_KDF, salt, TEST_NONCE).unwrap();
}

#[test]
fn header_accepts_nonce_with_single_nonzero_byte() {
    let mut nonce = [0; 16];
    nonce[15] = 1;
    Header::new(0, TEST_KDF, TEST_SALT, nonce).unwrap();
}

#[test]
fn header_rejects_unrepresentable_plaintext_length() {
    assert_eq!(
        Header::new(MAX_FILE_LEN, TEST_KDF, TEST_SALT, TEST_NONCE).unwrap_err(),
        FormatError::SizeOverflow
    );
}

#[test]
fn header_accepts_largest_plaintext_with_representable_encoding() {
    const MAX_PLAINTEXT_LEN: u64 = 9_223_231_301_513_871_247;

    let header = Header::new(MAX_PLAINTEXT_LEN, TEST_KDF, TEST_SALT, TEST_NONCE).unwrap();
    assert_eq!(header.encoded_len().unwrap(), MAX_FILE_LEN);
}

#[test]
fn header_rejects_one_byte_above_largest_representable_encoding() {
    const FIRST_UNREPRESENTABLE_PLAINTEXT_LEN: u64 = 9_223_231_301_513_871_248;

    assert_eq!(
        Header::new(
            FIRST_UNREPRESENTABLE_PLAINTEXT_LEN,
            TEST_KDF,
            TEST_SALT,
            TEST_NONCE,
        )
        .unwrap_err(),
        FormatError::SizeOverflow
    );
}

macro_rules! header_chunk_count_case {
    ($name:ident, $length:expr, $chunks:expr) => {
        #[test]
        fn $name() {
            assert_eq!(header_for($length).chunk_count().unwrap(), $chunks);
        }
    };
}

header_chunk_count_case!(header_counts_zero_chunks, 0, 0);
header_chunk_count_case!(header_counts_one_byte_as_one_chunk, 1, 1);
header_chunk_count_case!(
    header_counts_chunk_minus_one_as_one,
    CHUNK_SIZE as u64 - 1,
    1
);
header_chunk_count_case!(header_counts_exact_chunk_as_one, CHUNK_SIZE as u64, 1);
header_chunk_count_case!(
    header_counts_chunk_plus_one_as_two,
    CHUNK_SIZE as u64 + 1,
    2
);
header_chunk_count_case!(
    header_counts_two_chunks_minus_one_as_two,
    CHUNK_SIZE as u64 * 2 - 1,
    2
);
header_chunk_count_case!(header_counts_exactly_two_chunks, CHUNK_SIZE as u64 * 2, 2);
header_chunk_count_case!(
    header_counts_two_chunks_plus_one_as_three,
    CHUNK_SIZE as u64 * 2 + 1,
    3
);
header_chunk_count_case!(header_counts_ten_exact_chunks, CHUNK_SIZE as u64 * 10, 10);
header_chunk_count_case!(
    header_counts_ten_chunks_plus_one_as_eleven,
    CHUNK_SIZE as u64 * 10 + 1,
    11
);

#[test]
fn header_reports_full_first_chunk() {
    assert_eq!(
        header_for(CHUNK_SIZE as u64 + 17)
            .chunk_plaintext_len(0)
            .unwrap(),
        CHUNK_SIZE as usize
    );
}

#[test]
fn header_reports_partial_last_chunk() {
    assert_eq!(
        header_for(CHUNK_SIZE as u64 + 17)
            .chunk_plaintext_len(1)
            .unwrap(),
        17
    );
}

#[test]
fn header_reports_full_exact_last_chunk() {
    assert_eq!(
        header_for(CHUNK_SIZE as u64 * 2)
            .chunk_plaintext_len(1)
            .unwrap(),
        CHUNK_SIZE as usize
    );
}

#[test]
fn header_rejects_chunk_index_for_empty_file() {
    assert_eq!(
        header_for(0).chunk_plaintext_len(0).unwrap_err(),
        FormatError::SizeOverflow
    );
}

#[test]
fn header_rejects_chunk_index_equal_to_count() {
    assert_eq!(
        header_for(CHUNK_SIZE as u64 + 1)
            .chunk_plaintext_len(2)
            .unwrap_err(),
        FormatError::SizeOverflow
    );
}

#[test]
fn header_rejects_maximum_chunk_index() {
    assert_eq!(
        header_for(1).chunk_plaintext_len(u64::MAX).unwrap_err(),
        FormatError::SizeOverflow
    );
}

macro_rules! encoded_length_case {
    ($name:ident, $length:expr) => {
        #[test]
        fn $name() {
            let header = header_for($length);
            let expected =
                HEADER_LEN as u64 + 16 + $length + header.chunk_count().unwrap() * 16 + 16;
            assert_eq!(header.encoded_len().unwrap(), expected);
        }
    };
}

encoded_length_case!(encoded_length_empty, 0);
encoded_length_case!(encoded_length_one_byte, 1);
encoded_length_case!(encoded_length_fifteen_bytes, 15);
encoded_length_case!(encoded_length_sixteen_bytes, 16);
encoded_length_case!(encoded_length_chunk_minus_one, CHUNK_SIZE as u64 - 1);
encoded_length_case!(encoded_length_exact_chunk, CHUNK_SIZE as u64);
encoded_length_case!(encoded_length_chunk_plus_one, CHUNK_SIZE as u64 + 1);
encoded_length_case!(
    encoded_length_two_chunks_minus_one,
    CHUNK_SIZE as u64 * 2 - 1
);
encoded_length_case!(encoded_length_exactly_two_chunks, CHUNK_SIZE as u64 * 2);
encoded_length_case!(
    encoded_length_two_chunks_plus_one,
    CHUNK_SIZE as u64 * 2 + 1
);

macro_rules! truncated_header_case {
    ($name:ident, $length:expr) => {
        #[test]
        fn $name() {
            let bytes = vec![0u8; $length];
            assert_decoded_format_error(&bytes, FormatError::TruncatedHeader);
        }
    };
}

truncated_header_case!(decode_rejects_zero_header_bytes, 0);
truncated_header_case!(decode_rejects_one_header_byte, 1);
truncated_header_case!(decode_rejects_seven_header_bytes, 7);
truncated_header_case!(decode_rejects_eight_header_bytes, 8);
truncated_header_case!(decode_rejects_nine_header_bytes, 9);
truncated_header_case!(decode_rejects_thirty_nine_header_bytes, 39);
truncated_header_case!(decode_rejects_fifty_five_header_bytes, 55);
truncated_header_case!(decode_rejects_seventy_one_header_bytes, 71);
truncated_header_case!(decode_rejects_seventy_nine_header_bytes, 79);
truncated_header_case!(decode_rejects_oversized_header_slice, 81);

macro_rules! bad_magic_byte_case {
    ($name:ident, $offset:expr) => {
        #[test]
        fn $name() {
            let mut bytes = header_for(123).encode();
            bytes[$offset] ^= 0x80;
            assert_decoded_format_error(&bytes, FormatError::BadMagic);
        }
    };
}

bad_magic_byte_case!(decode_authenticates_magic_byte_zero, 0);
bad_magic_byte_case!(decode_authenticates_magic_byte_one, 1);
bad_magic_byte_case!(decode_authenticates_magic_byte_two, 2);
bad_magic_byte_case!(decode_authenticates_magic_byte_three, 3);
bad_magic_byte_case!(decode_authenticates_magic_byte_four, 4);
bad_magic_byte_case!(decode_authenticates_magic_byte_five, 5);
bad_magic_byte_case!(decode_authenticates_magic_byte_six, 6);
bad_magic_byte_case!(decode_authenticates_magic_byte_seven, 7);

macro_rules! decode_u16_error_case {
    ($name:ident, $offset:expr, $value:expr, $error:expr) => {
        #[test]
        fn $name() {
            let mut bytes = header_for(123).encode();
            bytes[$offset..$offset + 2].copy_from_slice(&$value.to_le_bytes());
            assert_decoded_format_error(&bytes, $error);
        }
    };
}

decode_u16_error_case!(
    decode_rejects_version_zero,
    OFF_VERSION,
    0u16,
    FormatError::UnsupportedVersion
);
decode_u16_error_case!(
    decode_rejects_version_two,
    OFF_VERSION,
    2u16,
    FormatError::UnsupportedVersion
);
decode_u16_error_case!(
    decode_rejects_maximum_version,
    OFF_VERSION,
    u16::MAX,
    FormatError::UnsupportedVersion
);
decode_u16_error_case!(
    decode_rejects_header_length_zero,
    OFF_HEADER_LEN,
    0u16,
    FormatError::BadHeaderLength
);
decode_u16_error_case!(
    decode_rejects_header_length_79,
    OFF_HEADER_LEN,
    79u16,
    FormatError::BadHeaderLength
);
decode_u16_error_case!(
    decode_rejects_header_length_81,
    OFF_HEADER_LEN,
    81u16,
    FormatError::BadHeaderLength
);
decode_u16_error_case!(
    decode_rejects_maximum_header_length,
    OFF_HEADER_LEN,
    u16::MAX,
    FormatError::BadHeaderLength
);

macro_rules! decode_u32_error_case {
    ($name:ident, $offset:expr, $value:expr, $error:expr) => {
        #[test]
        fn $name() {
            let mut bytes = header_for(123).encode();
            bytes[$offset..$offset + 4].copy_from_slice(&$value.to_le_bytes());
            assert_decoded_format_error(&bytes, $error);
        }
    };
}

decode_u32_error_case!(
    decode_rejects_flag_bit_zero,
    OFF_FLAGS,
    1u32,
    FormatError::UnsupportedFlags
);
decode_u32_error_case!(
    decode_rejects_high_flag_bit,
    OFF_FLAGS,
    0x8000_0000u32,
    FormatError::UnsupportedFlags
);
decode_u32_error_case!(
    decode_rejects_all_flag_bits,
    OFF_FLAGS,
    u32::MAX,
    FormatError::UnsupportedFlags
);
decode_u32_error_case!(
    decode_rejects_zero_chunk_size,
    OFF_CHUNK_SIZE,
    0u32,
    FormatError::InvalidChunkSize
);
decode_u32_error_case!(
    decode_rejects_one_byte_chunk_size,
    OFF_CHUNK_SIZE,
    1u32,
    FormatError::InvalidChunkSize
);
decode_u32_error_case!(
    decode_rejects_chunk_size_minus_one,
    OFF_CHUNK_SIZE,
    CHUNK_SIZE - 1,
    FormatError::InvalidChunkSize
);
decode_u32_error_case!(
    decode_rejects_chunk_size_plus_one,
    OFF_CHUNK_SIZE,
    CHUNK_SIZE + 1,
    FormatError::InvalidChunkSize
);
decode_u32_error_case!(
    decode_rejects_maximum_chunk_size,
    OFF_CHUNK_SIZE,
    u32::MAX,
    FormatError::InvalidChunkSize
);
decode_u32_error_case!(
    decode_rejects_zero_header_memory,
    OFF_MEMORY,
    0u32,
    FormatError::InvalidKdfParameters
);
decode_u32_error_case!(
    decode_rejects_low_header_memory,
    OFF_MEMORY,
    MIN_MEMORY_KIB - 1,
    FormatError::InvalidKdfParameters
);
decode_u32_error_case!(
    decode_rejects_high_header_memory,
    OFF_MEMORY,
    MAX_MEMORY_KIB + 1,
    FormatError::InvalidKdfParameters
);
decode_u32_error_case!(
    decode_rejects_zero_header_time,
    OFF_TIME,
    0u32,
    FormatError::InvalidKdfParameters
);
decode_u32_error_case!(
    decode_rejects_high_header_time,
    OFF_TIME,
    MAX_TIME_COST + 1,
    FormatError::InvalidKdfParameters
);
decode_u32_error_case!(
    decode_rejects_zero_header_lanes,
    OFF_LANES,
    0u32,
    FormatError::InvalidKdfParameters
);
decode_u32_error_case!(
    decode_rejects_high_header_lanes,
    OFF_LANES,
    MAX_LANES + 1,
    FormatError::InvalidKdfParameters
);

macro_rules! reserved_byte_case {
    ($name:ident, $offset:expr) => {
        #[test]
        fn $name() {
            let mut bytes = header_for(123).encode();
            bytes[$offset] = 1;
            assert_decoded_format_error(&bytes, FormatError::ReservedBytes);
        }
    };
}

reserved_byte_case!(decode_checks_reserved_byte_72, 72);
reserved_byte_case!(decode_checks_reserved_byte_73, 73);
reserved_byte_case!(decode_checks_reserved_byte_74, 74);
reserved_byte_case!(decode_checks_reserved_byte_75, 75);
reserved_byte_case!(decode_checks_reserved_byte_76, 76);
reserved_byte_case!(decode_checks_reserved_byte_77, 77);
reserved_byte_case!(decode_checks_reserved_byte_78, 78);
reserved_byte_case!(decode_checks_reserved_byte_79, 79);

#[test]
fn decode_rejects_zero_salt() {
    let mut bytes = header_for(123).encode();
    bytes[OFF_SALT..OFF_NONCE].fill(0);
    assert_decoded_format_error(&bytes, FormatError::InvalidSalt);
}

#[test]
fn decode_rejects_zero_nonce() {
    let mut bytes = header_for(123).encode();
    bytes[OFF_NONCE..OFF_RESERVED].fill(0);
    assert_decoded_format_error(&bytes, FormatError::InvalidNonce);
}

#[test]
fn header_nonce_contains_prefix_and_zero_counter() {
    let nonce = header_for(0).nonce(0);
    assert_eq!(&nonce[..16], &TEST_NONCE);
    assert_eq!(&nonce[16..], &0u64.to_le_bytes());
}

#[test]
fn header_nonce_contains_counter_one() {
    assert_eq!(&header_for(0).nonce(1)[16..], &1u64.to_le_bytes());
}

#[test]
fn header_nonce_contains_multibyte_counter() {
    let counter = 0x0102_0304_0506_0708;
    assert_eq!(&header_for(0).nonce(counter)[16..], &counter.to_le_bytes());
}

#[test]
fn header_nonce_contains_maximum_counter() {
    assert_eq!(
        &header_for(0).nonce(u64::MAX)[16..],
        &u64::MAX.to_le_bytes()
    );
}

#[test]
fn header_nonces_are_unique_for_first_thousand_counters() {
    let header = header_for(0);
    for left in 0..1_000u64 {
        assert_ne!(header.nonce(left), header.nonce(left + 1));
    }
}

#[test]
fn header_aad_has_domain_prefix_and_complete_header() {
    let encoded = header_for(123).encode();
    let aad = header_aad(&encoded);
    assert!(aad.starts_with(b"EZCRYPT-HDR-V1"));
    assert!(aad.ends_with(&encoded));
}

#[test]
fn chunk_aad_binds_chunk_index() {
    let encoded = header_for(123).encode();
    assert_ne!(chunk_aad(&encoded, 0, 123), chunk_aad(&encoded, 1, 123));
}

#[test]
fn chunk_aad_binds_plaintext_length() {
    let encoded = header_for(123).encode();
    assert_ne!(chunk_aad(&encoded, 0, 122), chunk_aad(&encoded, 0, 123));
}

#[test]
fn chunk_aad_binds_header() {
    let first = header_for(123).encode();
    let second = header_for(124).encode();
    assert_ne!(chunk_aad(&first, 0, 123), chunk_aad(&second, 0, 123));
}

#[test]
fn final_aad_binds_chunk_count() {
    let encoded = header_for(123).encode();
    assert_ne!(final_aad(&encoded, 0), final_aad(&encoded, 1));
}

#[test]
fn aad_domains_are_distinct() {
    let encoded = header_for(123).encode();
    assert_ne!(header_aad(&encoded), chunk_aad(&encoded, 0, 123));
    assert_ne!(header_aad(&encoded), final_aad(&encoded, 1));
    assert_ne!(chunk_aad(&encoded, 0, 123), final_aad(&encoded, 1));
}

macro_rules! stream_roundtrip_case {
    ($name:ident, $length:expr) => {
        #[test]
        fn $name() {
            let plaintext = fixture_payload($length);
            let encrypted = encrypt_bytes(&plaintext, TEST_PASSWORD);
            assert_ne!(encrypted, plaintext);
            assert_eq!(decrypt_bytes(&encrypted, TEST_PASSWORD).unwrap(), plaintext);
        }
    };
}

stream_roundtrip_case!(stream_roundtrips_empty_file, 0);
stream_roundtrip_case!(stream_roundtrips_one_byte, 1);
stream_roundtrip_case!(stream_roundtrips_fifteen_bytes, 15);
stream_roundtrip_case!(stream_roundtrips_sixteen_bytes, 16);
stream_roundtrip_case!(stream_roundtrips_seventeen_bytes, 17);
stream_roundtrip_case!(stream_roundtrips_255_bytes, 255);
stream_roundtrip_case!(stream_roundtrips_4096_bytes, 4_096);
stream_roundtrip_case!(stream_roundtrips_chunk_minus_one, CHUNK_SIZE as usize - 1);
stream_roundtrip_case!(stream_roundtrips_exact_chunk, CHUNK_SIZE as usize);
stream_roundtrip_case!(stream_roundtrips_chunk_plus_one, CHUNK_SIZE as usize + 1);
stream_roundtrip_case!(
    stream_roundtrips_two_chunks_plus_seventeen,
    CHUNK_SIZE as usize * 2 + 17
);

#[test]
fn stream_roundtrips_all_zero_payload() {
    let plaintext = vec![0; 8_193];
    assert_eq!(
        decrypt_bytes(&encrypt_bytes(&plaintext, TEST_PASSWORD), TEST_PASSWORD).unwrap(),
        plaintext
    );
}

#[test]
fn stream_roundtrips_all_ff_payload() {
    let plaintext = vec![0xff; 8_193];
    assert_eq!(
        decrypt_bytes(&encrypt_bytes(&plaintext, TEST_PASSWORD), TEST_PASSWORD).unwrap(),
        plaintext
    );
}

#[test]
fn stream_ciphertext_length_matches_header_formula() {
    let plaintext = fixture_payload(CHUNK_SIZE as usize + 7);
    let encrypted = encrypt_bytes(&plaintext, TEST_PASSWORD);
    assert_eq!(
        encrypted.len() as u64,
        header_for(plaintext.len() as u64).encoded_len().unwrap()
    );
}

#[test]
fn stream_matches_independent_libsodium_v1_known_answer() {
    // Generated independently with Python 3.14.4 ctypes against libsodium
    // 1.0.18. crypto_pwhash(ALG_ARGON2ID13) used opslimit=1,
    // memlimit=8_192 KiB, and libsodium's hard-coded p=1; record encryption
    // used crypto_aead_xchacha20poly1305_ietf_encrypt. Do not regenerate this
    // fixture with ezcrypt itself.
    #[rustfmt::skip]
    const EXPECTED: [u8; 129] = [
        // Header.
        0x45, 0x5a, 0x43, 0x52, 0x59, 0x50, 0x54, 0x00, 0x01, 0x00, 0x50, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x20, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x31, 0x31,
        0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
        0xa7, 0xa7, 0xa7, 0xa7, 0xa7, 0xa7, 0xa7, 0xa7, 0xa7, 0xa7, 0xa7, 0xa7, 0xa7, 0xa7,
        0xa7, 0xa7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // Header tag.
        0xfc, 0xc3, 0xba, 0x5d, 0xb4, 0x59, 0x59, 0xe8, 0x9d, 0xdb, 0x57, 0x6c, 0x8e, 0x8d,
        0xfe, 0x6f,
        // One ciphertext byte and its chunk tag.
        0x37, 0x48, 0xe8, 0xd3, 0xa1, 0xa9, 0x67, 0x92, 0x2a, 0x33, 0xf7, 0x9a, 0x02, 0x24,
        0xc8, 0x6d, 0xc7,
        // Final tag.
        0xc1, 0xbb, 0x6c, 0x04, 0xfe, 0xfa, 0x33, 0xe2, 0x79, 0x47, 0x57, 0x68, 0x4a, 0x0d,
        0xea, 0x0d,
    ];

    let encrypted = encrypt_bytes(&[0x42], TEST_PASSWORD);
    assert_eq!(encrypted.as_slice(), EXPECTED);
    assert_eq!(
        decrypt_bytes(&EXPECTED, TEST_PASSWORD).unwrap().as_slice(),
        &[0x42]
    );
}

#[test]
fn stream_rejects_wrong_password() {
    assert!(matches!(
        decrypt_bytes(cached_encrypted(), b"wrong password"),
        Err(EzError::AuthenticationFailed)
    ));
}

#[test]
fn stream_rejects_reordered_full_chunk_records_before_output() {
    let mut encrypted = cached_two_chunk_encrypted().to_vec();
    let data_offset = HEADER_LEN + HEADER_TAG_LEN as usize;
    let record_len = CHUNK_SIZE as usize + TAG_LEN as usize;
    encrypted[data_offset..data_offset + record_len * 2].rotate_left(record_len);

    let mut reader = Cursor::new(&encrypted);
    let mut output = Vec::new();
    let result = decrypt_stream(
        &mut reader,
        &mut output,
        encrypted.len() as u64,
        TEST_PASSWORD,
        Path::new("reordered.ez"),
        Path::new("reordered"),
    );

    assert!(matches!(result, Err(EzError::AuthenticationFailed)));
    assert!(output.is_empty());
}

#[test]
fn stream_rejects_duplicated_chunk_record_without_writing_duplicate() {
    let mut encrypted = cached_two_chunk_encrypted().to_vec();
    let data_offset = HEADER_LEN + HEADER_TAG_LEN as usize;
    let record_len = CHUNK_SIZE as usize + TAG_LEN as usize;
    let first_record = encrypted[data_offset..data_offset + record_len].to_vec();
    encrypted[data_offset + record_len..data_offset + record_len * 2]
        .copy_from_slice(&first_record);

    let mut reader = Cursor::new(&encrypted);
    let mut output = Vec::new();
    let result = decrypt_stream(
        &mut reader,
        &mut output,
        encrypted.len() as u64,
        TEST_PASSWORD,
        Path::new("duplicated.ez"),
        Path::new("duplicated"),
    );

    assert!(matches!(result, Err(EzError::AuthenticationFailed)));
    assert_eq!(
        output.as_slice(),
        &cached_two_chunk_plaintext()[..CHUNK_SIZE as usize]
    );
}

#[test]
fn stream_rejects_truncated_second_chunk_when_reported_length_is_stale() {
    let original = cached_two_chunk_encrypted();
    let reported_len = original.len() as u64;
    let data_offset = HEADER_LEN + HEADER_TAG_LEN as usize;
    let record_len = CHUNK_SIZE as usize + TAG_LEN as usize;
    let truncated = &original[..data_offset + record_len + 123];

    let mut reader = Cursor::new(truncated);
    let mut output = Vec::new();
    let result = decrypt_stream(
        &mut reader,
        &mut output,
        reported_len,
        TEST_PASSWORD,
        Path::new("truncated.ez"),
        Path::new("truncated"),
    );

    assert_format_error(result, FormatError::LengthMismatch);
    assert_eq!(
        output.as_slice(),
        &cached_two_chunk_plaintext()[..CHUNK_SIZE as usize]
    );
}

macro_rules! auth_mutation_case {
    ($name:ident, $offset:expr) => {
        #[test]
        fn $name() {
            let mut encrypted = cached_encrypted().to_vec();
            let offset = $offset;
            encrypted[offset] ^= 0x01;
            assert_authentication_failure(encrypted);
        }
    };
}

auth_mutation_case!(stream_authenticates_first_salt_byte, OFF_SALT);
auth_mutation_case!(stream_authenticates_last_salt_byte, OFF_NONCE - 1);
auth_mutation_case!(stream_authenticates_first_nonce_byte, OFF_NONCE);
auth_mutation_case!(stream_authenticates_last_nonce_byte, OFF_RESERVED - 1);
auth_mutation_case!(stream_authenticates_first_header_tag_byte, HEADER_LEN);
auth_mutation_case!(stream_authenticates_middle_header_tag_byte, HEADER_LEN + 8);
auth_mutation_case!(stream_authenticates_last_header_tag_byte, HEADER_LEN + 15);
auth_mutation_case!(stream_authenticates_first_ciphertext_byte, HEADER_LEN + 16);
auth_mutation_case!(
    stream_authenticates_middle_ciphertext_byte,
    HEADER_LEN + 16 + 128
);
auth_mutation_case!(
    stream_authenticates_last_ciphertext_byte,
    HEADER_LEN + 16 + 256
);
auth_mutation_case!(
    stream_authenticates_first_data_tag_byte,
    HEADER_LEN + 16 + 257
);
auth_mutation_case!(
    stream_authenticates_middle_data_tag_byte,
    HEADER_LEN + 16 + 257 + 8
);
auth_mutation_case!(
    stream_authenticates_last_data_tag_byte,
    HEADER_LEN + 16 + 257 + 15
);
auth_mutation_case!(
    stream_authenticates_first_final_tag_byte,
    HEADER_LEN + 16 + 257 + 16
);
auth_mutation_case!(
    stream_authenticates_middle_final_tag_byte,
    HEADER_LEN + 16 + 257 + 16 + 8
);
auth_mutation_case!(
    stream_authenticates_last_final_tag_byte,
    HEADER_LEN + 16 + 257 + 16 + 15
);

#[test]
fn stream_authenticates_valid_but_changed_kdf_memory() {
    let mut encrypted = cached_encrypted().to_vec();
    encrypted[OFF_MEMORY..OFF_MEMORY + 4].copy_from_slice(&(TEST_KDF.memory_kib + 1).to_le_bytes());
    assert_authentication_failure(encrypted);
}

#[test]
fn stream_rejects_changed_plaintext_length_before_output() {
    let mut encrypted = cached_encrypted().to_vec();
    encrypted[OFF_PLAINTEXT_LEN] ^= 1;
    let mut reader = Cursor::new(&encrypted);
    let mut output = Vec::new();
    let result = decrypt_stream(
        &mut reader,
        &mut output,
        encrypted.len() as u64,
        TEST_PASSWORD,
        Path::new("damaged.ez"),
        Path::new("damaged"),
    );
    assert_format_error(result, FormatError::LengthMismatch);
    assert!(output.is_empty());
}

macro_rules! truncated_stream_case {
    ($name:ident, $length:expr, $error:expr) => {
        #[test]
        fn $name() {
            let encrypted = cached_encrypted();
            let length = $length;
            let mut reader = Cursor::new(&encrypted[..length]);
            let mut output = Vec::new();
            let result = decrypt_stream(
                &mut reader,
                &mut output,
                length as u64,
                TEST_PASSWORD,
                Path::new("truncated.ez"),
                Path::new("truncated"),
            );
            assert_format_error(result, $error);
            assert!(output.is_empty());
        }
    };
}

truncated_stream_case!(
    stream_rejects_zero_byte_file,
    0,
    FormatError::TruncatedHeader
);
truncated_stream_case!(
    stream_rejects_one_byte_file,
    1,
    FormatError::TruncatedHeader
);
truncated_stream_case!(
    stream_rejects_magic_only_file,
    8,
    FormatError::TruncatedHeader
);
truncated_stream_case!(
    stream_rejects_header_minus_one_file,
    HEADER_LEN - 1,
    FormatError::TruncatedHeader
);
truncated_stream_case!(
    stream_rejects_header_only_file,
    HEADER_LEN,
    FormatError::LengthMismatch
);
truncated_stream_case!(
    stream_rejects_partial_header_tag_file,
    HEADER_LEN + 8,
    FormatError::LengthMismatch
);
truncated_stream_case!(
    stream_rejects_header_tag_only_file,
    HEADER_LEN + 16,
    FormatError::LengthMismatch
);
truncated_stream_case!(
    stream_rejects_partial_ciphertext_file,
    HEADER_LEN + 16 + 100,
    FormatError::LengthMismatch
);
truncated_stream_case!(
    stream_rejects_file_without_data_tag,
    HEADER_LEN + 16 + 257,
    FormatError::LengthMismatch
);
truncated_stream_case!(
    stream_rejects_file_without_final_tag,
    HEADER_LEN + 16 + 257 + 16,
    FormatError::LengthMismatch
);

#[test]
fn stream_rejects_file_missing_last_byte() {
    let encrypted = cached_encrypted();
    let truncated = &encrypted[..encrypted.len() - 1];
    assert_format_error(
        decrypt_bytes(truncated, TEST_PASSWORD),
        FormatError::LengthMismatch,
    );
}

#[test]
fn stream_rejects_appended_byte_when_length_reports_actual_size() {
    let mut encrypted = cached_encrypted().to_vec();
    encrypted.push(0);
    assert_format_error(
        decrypt_bytes(&encrypted, TEST_PASSWORD),
        FormatError::LengthMismatch,
    );
}

#[test]
fn stream_rejects_appended_byte_even_when_length_lies() {
    let mut encrypted = cached_encrypted().to_vec();
    let declared = encrypted.len() as u64;
    encrypted.push(0x42);
    let mut reader = Cursor::new(&encrypted);
    let mut output = Vec::new();
    let result = decrypt_stream(
        &mut reader,
        &mut output,
        declared,
        TEST_PASSWORD,
        Path::new("appended.ez"),
        Path::new("appended"),
    );
    assert_format_error(result, FormatError::LengthMismatch);
}

#[test]
fn stream_encryption_detects_short_source() {
    let plaintext = fixture_payload(31);
    let mut reader = Cursor::new(&plaintext);
    let mut output = Vec::new();
    let result = encrypt_stream(
        &mut reader,
        &mut output,
        32,
        TEST_PASSWORD,
        TEST_KDF,
        TEST_SALT,
        TEST_NONCE,
        Path::new("changed.bin"),
        Path::new("changed.bin.ez"),
    );
    assert!(matches!(result, Err(EzError::InputChanged(_))));
}

#[test]
fn stream_encryption_detects_growing_source() {
    let plaintext = fixture_payload(33);
    let mut reader = Cursor::new(&plaintext);
    let mut output = Vec::new();
    let result = encrypt_stream(
        &mut reader,
        &mut output,
        32,
        TEST_PASSWORD,
        TEST_KDF,
        TEST_SALT,
        TEST_NONCE,
        Path::new("changed.bin"),
        Path::new("changed.bin.ez"),
    );
    assert!(matches!(result, Err(EzError::InputChanged(_))));
}

#[test]
fn stream_encryption_rejects_empty_password_before_writing() {
    let mut reader = Cursor::new(b"payload");
    let mut output = Vec::new();
    let result = encrypt_stream(
        &mut reader,
        &mut output,
        7,
        b"",
        TEST_KDF,
        TEST_SALT,
        TEST_NONCE,
        Path::new("input"),
        Path::new("output"),
    );
    assert!(matches!(result, Err(EzError::InvalidPassword(_))));
    assert!(output.is_empty());
}

#[test]
fn stream_decryption_rejects_empty_password_before_reading() {
    let mut reader = Cursor::new(cached_encrypted());
    let original_position = reader.position();
    let mut output = Vec::new();
    let result = decrypt_stream(
        &mut reader,
        &mut output,
        cached_encrypted().len() as u64,
        b"",
        Path::new("input"),
        Path::new("output"),
    );
    assert!(matches!(result, Err(EzError::InvalidPassword(_))));
    assert_eq!(reader.position(), original_position);
    assert!(output.is_empty());
}

#[test]
fn stream_encryption_rejects_zero_salt_before_writing() {
    let mut reader = Cursor::new(b"payload");
    let mut output = Vec::new();
    let result = encrypt_stream(
        &mut reader,
        &mut output,
        7,
        TEST_PASSWORD,
        TEST_KDF,
        [0; 16],
        TEST_NONCE,
        Path::new("input"),
        Path::new("output"),
    );
    assert_format_error(result, FormatError::InvalidSalt);
    assert!(output.is_empty());
}

#[test]
fn stream_encryption_rejects_zero_nonce_before_writing() {
    let mut reader = Cursor::new(b"payload");
    let mut output = Vec::new();
    let result = encrypt_stream(
        &mut reader,
        &mut output,
        7,
        TEST_PASSWORD,
        TEST_KDF,
        TEST_SALT,
        [0; 16],
        Path::new("input"),
        Path::new("output"),
    );
    assert_format_error(result, FormatError::InvalidNonce);
    assert!(output.is_empty());
}

struct FailAfterReader<R> {
    inner: R,
    remaining: usize,
    kind: io::ErrorKind,
}

impl<R: Read> Read for FailAfterReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Err(io::Error::new(self.kind, "injected read failure"));
        }
        let wanted = buffer.len().min(self.remaining);
        let count = self.inner.read(&mut buffer[..wanted])?;
        self.remaining -= count;
        Ok(count)
    }
}

struct FailAfterWriter {
    remaining: usize,
    bytes: Vec<u8>,
}

impl Write for FailAfterWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Err(io::Error::other("injected write failure"));
        }
        let count = buffer.len().min(self.remaining);
        self.bytes.extend_from_slice(&buffer[..count]);
        self.remaining -= count;
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
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
fn stream_encryption_propagates_reader_error() {
    let source = fixture_payload(64);
    let mut reader = FailAfterReader {
        inner: Cursor::new(source),
        remaining: 17,
        kind: io::ErrorKind::PermissionDenied,
    };
    let mut output = Vec::new();
    let result = encrypt_stream(
        &mut reader,
        &mut output,
        64,
        TEST_PASSWORD,
        TEST_KDF,
        TEST_SALT,
        TEST_NONCE,
        Path::new("input"),
        Path::new("output"),
    );
    assert!(
        matches!(result, Err(EzError::Io { source, .. }) if source.kind() == io::ErrorKind::PermissionDenied)
    );
}

#[test]
fn stream_decryption_propagates_header_reader_error() {
    let mut reader = FailAfterReader {
        inner: Cursor::new(cached_encrypted()),
        remaining: 7,
        kind: io::ErrorKind::PermissionDenied,
    };
    let mut output = Vec::new();
    let result = decrypt_stream(
        &mut reader,
        &mut output,
        cached_encrypted().len() as u64,
        TEST_PASSWORD,
        Path::new("input"),
        Path::new("output"),
    );
    assert!(
        matches!(result, Err(EzError::Io { source, .. }) if source.kind() == io::ErrorKind::PermissionDenied)
    );
}

#[test]
fn stream_encryption_propagates_writer_error() {
    let plaintext = fixture_payload(64);
    let mut reader = Cursor::new(&plaintext);
    let mut writer = FailAfterWriter {
        remaining: HEADER_LEN + 10,
        bytes: Vec::new(),
    };
    let result = encrypt_stream(
        &mut reader,
        &mut writer,
        plaintext.len() as u64,
        TEST_PASSWORD,
        TEST_KDF,
        TEST_SALT,
        TEST_NONCE,
        Path::new("input"),
        Path::new("output"),
    );
    assert!(
        matches!(result, Err(EzError::Io { source, .. }) if source.kind() == io::ErrorKind::Other)
    );
}

#[test]
fn stream_encryption_handles_write_zero_as_io_error() {
    let plaintext = fixture_payload(1);
    let mut reader = Cursor::new(&plaintext);
    let result = encrypt_stream(
        &mut reader,
        &mut ZeroWriter,
        1,
        TEST_PASSWORD,
        TEST_KDF,
        TEST_SALT,
        TEST_NONCE,
        Path::new("input"),
        Path::new("output"),
    );
    assert!(
        matches!(result, Err(EzError::Io { source, .. }) if source.kind() == io::ErrorKind::WriteZero)
    );
}

#[test]
fn stream_decryption_propagates_output_writer_error() {
    let encrypted = cached_encrypted();
    let mut reader = Cursor::new(encrypted);
    let mut writer = FailAfterWriter {
        remaining: 100,
        bytes: Vec::new(),
    };
    let result = decrypt_stream(
        &mut reader,
        &mut writer,
        encrypted.len() as u64,
        TEST_PASSWORD,
        Path::new("input"),
        Path::new("output"),
    );
    assert!(
        matches!(result, Err(EzError::Io { source, .. }) if source.kind() == io::ErrorKind::Other)
    );
}

#[test]
fn destination_check_accepts_absent_path() {
    let directory = tempfile::tempdir().unwrap();
    ensure_destination_absent(&directory.path().join("absent")).unwrap();
}

#[test]
fn destination_check_rejects_existing_empty_file() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("exists");
    fs::write(&path, []).unwrap();
    assert!(
        matches!(ensure_destination_absent(&path), Err(EzError::DestinationExists(found)) if found == path)
    );
}

#[test]
fn destination_check_rejects_existing_nonempty_file_without_changing_it() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("exists");
    fs::write(&path, b"do not overwrite").unwrap();
    assert!(matches!(
        ensure_destination_absent(&path),
        Err(EzError::DestinationExists(_))
    ));
    assert_eq!(fs::read(path).unwrap(), b"do not overwrite");
}

#[test]
fn destination_check_rejects_existing_directory() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("destination");
    fs::create_dir(&path).unwrap();
    assert!(matches!(
        ensure_destination_absent(&path),
        Err(EzError::DestinationExists(_))
    ));
}

fn assert_no_pending_transaction_artifacts(directory: &Path) {
    let artifacts: Vec<OsString> = fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .filter(|name| name.to_string_lossy().starts_with(".ezcrypt-"))
        .collect();
    assert!(
        artifacts.is_empty(),
        "temporary transaction artifacts remain: {artifacts:?}"
    );
}

#[test]
fn transaction_roundtrips_real_empty_file() {
    let directory = tempfile::tempdir().unwrap();
    let original = directory.path().join("empty.bin");
    fs::write(&original, []).unwrap();
    let encrypt_plan = plan_for_path(&original).unwrap();
    let encrypted = encrypt_plan.output().to_path_buf();
    let outcome = transform_plan(&encrypt_plan, TEST_PASSWORD, TEST_KDF).unwrap();
    assert_eq!(outcome.operation(), Operation::Encrypt);
    assert_eq!(outcome.plaintext_bytes(), 0);
    assert!(!original.exists());
    assert!(encrypted.exists());
    let decrypt_plan = plan_for_path(&encrypted).unwrap();
    let outcome = transform_plan(&decrypt_plan, TEST_PASSWORD, TEST_KDF).unwrap();
    assert_eq!(outcome.operation(), Operation::Decrypt);
    assert_eq!(outcome.plaintext_bytes(), 0);
    assert!(!encrypted.exists());
    assert_eq!(fs::read(original).unwrap(), b"");
}

#[test]
fn transaction_roundtrips_real_binary_file() {
    let directory = tempfile::tempdir().unwrap();
    let original = directory.path().join("binary data.bin");
    let plaintext = fixture_payload(65_537);
    fs::write(&original, &plaintext).unwrap();
    let encrypt_plan = plan_for_path(&original).unwrap();
    let encrypted = encrypt_plan.output().to_path_buf();
    let encrypted_outcome = transform_plan(&encrypt_plan, TEST_PASSWORD, TEST_KDF).unwrap();
    assert_eq!(encrypted_outcome.plaintext_bytes(), plaintext.len() as u64);
    assert!(!original.exists());
    assert_ne!(fs::read(&encrypted).unwrap(), plaintext);
    let decrypt_plan = plan_for_path(&encrypted).unwrap();
    let decrypted_outcome = transform_plan(&decrypt_plan, TEST_PASSWORD, TEST_KDF).unwrap();
    assert_eq!(decrypted_outcome.plaintext_bytes(), plaintext.len() as u64);
    assert!(!encrypted.exists());
    assert_eq!(fs::read(original).unwrap(), plaintext);
}

#[test]
fn transaction_roundtrips_file_beyond_legacy_max_path() {
    let directory = tempfile::tempdir().unwrap();
    let mut parent = directory.path().to_path_buf();
    let mut segment_index = 0usize;
    while parent
        .join("long-path-payload.bin")
        .as_os_str()
        .encode_wide()
        .count()
        <= 300
    {
        parent.push(format!("segment-{segment_index:02}-{}", "x".repeat(48)));
        segment_index += 1;
    }
    fs::create_dir_all(&parent).unwrap();

    let original = parent.join("long-path-payload.bin");
    assert!(original.as_os_str().encode_wide().count() > 260);
    assert!(
        original
            .iter()
            .all(|component| component.encode_wide().count() <= 255)
    );
    let plaintext = fixture_payload(4_097);
    fs::write(&original, &plaintext).unwrap();

    let encrypt_plan = plan_for_path(&original).unwrap();
    let encrypted = encrypt_plan.output().to_path_buf();
    let encrypted_outcome = transform_plan(&encrypt_plan, TEST_PASSWORD, TEST_KDF).unwrap();
    assert_eq!(encrypted_outcome.plaintext_bytes(), plaintext.len() as u64);
    assert!(!original.exists());
    assert!(encrypted.exists());
    assert_no_pending_transaction_artifacts(&parent);

    let decrypt_plan = plan_for_path(&encrypted).unwrap();
    let decrypted_outcome = transform_plan(&decrypt_plan, TEST_PASSWORD, TEST_KDF).unwrap();
    assert_eq!(decrypted_outcome.plaintext_bytes(), plaintext.len() as u64);
    assert!(!encrypted.exists());
    assert_eq!(fs::read(&original).unwrap(), plaintext);
    assert_no_pending_transaction_artifacts(&parent);
}

#[test]
fn transaction_destination_collision_preserves_both_files() {
    let directory = tempfile::tempdir().unwrap();
    let original = directory.path().join("source.bin");
    let destination = directory.path().join("source.bin.ez");
    fs::write(&original, b"source bytes").unwrap();
    fs::write(&destination, b"existing destination bytes").unwrap();
    let plan = plan_for_path(&original).unwrap();
    assert!(matches!(
        transform_plan(&plan, TEST_PASSWORD, TEST_KDF),
        Err(EzError::DestinationExists(path)) if path == destination
    ));
    assert_eq!(fs::read(original).unwrap(), b"source bytes");
    assert_eq!(
        fs::read(destination).unwrap(),
        b"existing destination bytes"
    );
}

#[test]
fn transaction_invalid_password_preserves_source_and_creates_no_destination() {
    let directory = tempfile::tempdir().unwrap();
    let original = directory.path().join("source.bin");
    fs::write(&original, b"source bytes").unwrap();
    let plan = plan_for_path(&original).unwrap();
    let destination = plan.output().to_path_buf();
    assert!(matches!(
        transform_plan(&plan, b"", TEST_KDF),
        Err(EzError::InvalidPassword(_))
    ));
    assert_eq!(fs::read(original).unwrap(), b"source bytes");
    assert!(!destination.exists());
}

#[test]
fn transaction_wrong_nonempty_password_cleans_plaintext_temp_and_preserves_ciphertext() {
    let directory = tempfile::tempdir().unwrap();
    let encrypted_path = directory.path().join("secret.bin.ez");
    let encrypted = cached_encrypted().to_vec();
    fs::write(&encrypted_path, &encrypted).unwrap();
    let plan = plan_for_path(&encrypted_path).unwrap();
    let plaintext_path = plan.output().to_path_buf();

    assert!(matches!(
        transform_plan(&plan, b"definitely wrong", TEST_KDF),
        Err(EzError::AuthenticationFailed)
    ));
    assert_eq!(fs::read(&encrypted_path).unwrap(), encrypted);
    assert!(!plaintext_path.exists());
    assert_no_pending_transaction_artifacts(directory.path());
}

#[test]
fn transaction_corrupt_final_tag_cleans_late_plaintext_temp_and_preserves_ciphertext() {
    let directory = tempfile::tempdir().unwrap();
    let encrypted_path = directory.path().join("damaged.bin.ez");
    let mut encrypted = cached_encrypted().to_vec();
    *encrypted.last_mut().unwrap() ^= 0x80;
    fs::write(&encrypted_path, &encrypted).unwrap();
    let plan = plan_for_path(&encrypted_path).unwrap();
    let plaintext_path = plan.output().to_path_buf();

    assert!(matches!(
        transform_plan(&plan, TEST_PASSWORD, TEST_KDF),
        Err(EzError::AuthenticationFailed)
    ));
    assert_eq!(fs::read(&encrypted_path).unwrap(), encrypted);
    assert!(!plaintext_path.exists());
    assert_no_pending_transaction_artifacts(directory.path());
}

#[test]
fn transaction_truncated_ciphertext_cleans_temp_and_preserves_source() {
    let directory = tempfile::tempdir().unwrap();
    let encrypted_path = directory.path().join("truncated.bin.ez");
    let mut encrypted = cached_encrypted().to_vec();
    encrypted.truncate(encrypted.len() - 9);
    fs::write(&encrypted_path, &encrypted).unwrap();
    let plan = plan_for_path(&encrypted_path).unwrap();
    let plaintext_path = plan.output().to_path_buf();

    assert_format_error(
        transform_plan(&plan, TEST_PASSWORD, TEST_KDF),
        FormatError::LengthMismatch,
    );
    assert_eq!(fs::read(&encrypted_path).unwrap(), encrypted);
    assert!(!plaintext_path.exists());
    assert_no_pending_transaction_artifacts(directory.path());
}

#[test]
fn transaction_rejects_source_with_alternate_data_stream_without_artifacts() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("source.bin");
    let mut stream_name = input.as_os_str().to_os_string();
    stream_name.push(":private");
    let stream_path = PathBuf::from(stream_name);
    fs::write(&input, b"default stream").unwrap();
    fs::write(&stream_path, b"alternate stream").unwrap();
    let plan = plan_for_path(&input).unwrap();
    let destination = plan.output().to_path_buf();

    assert!(matches!(
        transform_plan(&plan, TEST_PASSWORD, TEST_KDF),
        Err(EzError::AlternateDataStream(path)) if path == input
    ));
    assert_eq!(fs::read(&input).unwrap(), b"default stream");
    assert_eq!(fs::read(&stream_path).unwrap(), b"alternate stream");
    assert!(!destination.exists());
    assert_no_pending_transaction_artifacts(directory.path());
}

#[test]
fn transaction_rejects_directory_input_without_creating_destination() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("folder");
    fs::create_dir(&input).unwrap();
    let plan = plan_for_path(&input).unwrap();
    let destination = plan.output().to_path_buf();
    assert!(transform_plan(&plan, TEST_PASSWORD, TEST_KDF).is_err());
    assert!(input.is_dir());
    assert!(!destination.exists());
}

#[test]
fn transaction_rejects_multiple_hard_links_without_changing_them() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("source.bin");
    let link = directory.path().join("second-name.bin");
    fs::write(&input, b"shared plaintext").unwrap();
    fs::hard_link(&input, &link).unwrap();
    let plan = plan_for_path(&input).unwrap();
    assert!(matches!(
        transform_plan(&plan, TEST_PASSWORD, TEST_KDF),
        Err(EzError::MultipleHardLinks { links, .. }) if links >= 2
    ));
    assert_eq!(fs::read(input).unwrap(), b"shared plaintext");
    assert_eq!(fs::read(link).unwrap(), b"shared plaintext");
}

#[test]
fn authentication_error_message_does_not_reveal_whether_password_was_wrong() {
    assert_eq!(
        EzError::AuthenticationFailed.to_string(),
        "wrong password or encrypted file is damaged"
    );
}

#[test]
fn destination_exists_error_states_nothing_changed() {
    let message = EzError::DestinationExists(PathBuf::from("example.ez")).to_string();
    assert!(message.contains("nothing was changed"));
    assert!(message.contains("example.ez"));
}

#[test]
fn input_changed_error_states_nothing_committed() {
    let message = EzError::InputChanged(PathBuf::from("example")).to_string();
    assert!(message.contains("nothing was committed"));
}

#[test]
fn format_error_messages_are_nonempty_and_distinct() {
    let errors = [
        FormatError::TruncatedHeader,
        FormatError::BadMagic,
        FormatError::UnsupportedVersion,
        FormatError::BadHeaderLength,
        FormatError::UnsupportedFlags,
        FormatError::ReservedBytes,
        FormatError::InvalidChunkSize,
        FormatError::InvalidKdfParameters,
        FormatError::InvalidSalt,
        FormatError::InvalidNonce,
        FormatError::SizeOverflow,
        FormatError::LengthMismatch,
    ];
    let messages: Vec<String> = errors.iter().map(ToString::to_string).collect();
    assert!(messages.iter().all(|message| !message.is_empty()));
    for (index, left) in messages.iter().enumerate() {
        for right in &messages[index + 1..] {
            assert_ne!(left, right);
        }
    }
}
