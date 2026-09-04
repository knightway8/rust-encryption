mod aead;
mod format;
mod legacy;
mod password;

use self::format::{ExpectedKeying, Header, Keying};
use self::password::{PasswordKdf, derive_key};
use crate::io_util::{NewOutput, ensure_absent, files_are_same, local_path, open_regular_file};
use crate::{Algorithm, Mode};
use anyhow::{Context, Result, bail};
use std::ffi::OsStr;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use zeroize::Zeroizing;

/// Plaintext bytes processed per independently authenticated AEAD record.
pub const CHUNK_SIZE: usize = 1024 * 1024;

/// Encrypt or decrypt two bare filenames within one directory.
///
/// # Errors
///
/// Returns an error for invalid filenames, missing or malformed inputs or keys,
/// authentication failure, I/O failure, or an existing output.
pub fn process_file_in(
    directory: &Path,
    algorithm: Algorithm,
    mode: Mode,
    input_name: &OsStr,
    output_name: &OsStr,
) -> Result<()> {
    let input_path = local_path(directory, input_name)?;
    let output_path = local_path(directory, output_name)?;
    let key_path = directory.join(algorithm.key_filename());

    if input_name == OsStr::new(algorithm.key_filename()) {
        bail!("refusing to process the active key file as input");
    }
    if output_name == OsStr::new(algorithm.key_filename()) {
        bail!("refusing to use the active key filename as output");
    }

    let key_file = open_regular_file(&key_path)
        .with_context(|| format!("required key is '{}'", key_path.display()))?;
    let input = open_regular_file(&input_path)?;
    if files_are_same(&input, &key_file).with_context(|| {
        format!(
            "cannot compare input '{}' with key '{}'",
            input_path.display(),
            key_path.display()
        )
    })? {
        bail!("refusing to process the active key file as input");
    }

    let key = read_key(key_file, &key_path, algorithm.key_len())?;
    match mode {
        Mode::Encrypt => encrypt_file(
            input,
            &input_path,
            &output_path,
            algorithm,
            &key,
            Keying::KeyFile,
        ),
        Mode::Decrypt => decrypt_file(
            input,
            &input_path,
            &output_path,
            algorithm,
            &key,
            ExpectedKeying::KeyFile,
        ),
    }
}

/// Encrypt or decrypt using a password instead of an external key file.
///
/// Encryption creates a fresh random salt and derives an algorithm-specific
/// internal key with Argon2id and HKDF-SHA-512. The password container is
/// intentionally distinct from the key-file container.
///
/// # Errors
///
/// Returns an error for an empty password, invalid filenames, malformed input,
/// authentication or key-derivation failure, I/O failure, or an existing
/// output.
pub fn process_password_file_in(
    directory: &Path,
    algorithm: Algorithm,
    mode: Mode,
    input_name: &OsStr,
    output_name: &OsStr,
    password: &[u8],
) -> Result<()> {
    process_password_file_with_kdf_in(
        directory,
        algorithm,
        mode,
        input_name,
        output_name,
        password,
        PasswordKdf::PRODUCTION,
    )
}

fn process_password_file_with_kdf_in(
    directory: &Path,
    algorithm: Algorithm,
    mode: Mode,
    input_name: &OsStr,
    output_name: &OsStr,
    password: &[u8],
    encryption_kdf: PasswordKdf,
) -> Result<()> {
    if password.is_empty() {
        bail!("password must not be empty");
    }
    let input_path = local_path(directory, input_name)?;
    let output_path = local_path(directory, output_name)?;
    ensure_absent(&output_path)?;
    let input = open_regular_file(&input_path)?;

    match mode {
        Mode::Encrypt => {
            let (input, header) = prepare_encryption(
                input,
                &input_path,
                algorithm,
                Keying::Password(encryption_kdf),
            )?;
            let key = derive_key(password, &header.nonce_seed, algorithm, encryption_kdf)?;
            encrypt_prepared(input, &output_path, algorithm, &key, &header)
        }
        Mode::Decrypt => {
            let (reader, header) =
                prepare_decryption(input, &input_path, algorithm, ExpectedKeying::Password)?;
            let Keying::Password(parameters) = header.keying else {
                unreachable!("password header was required");
            };
            let key = derive_key(password, &header.nonce_seed, algorithm, parameters)?;
            decrypt_prepared(reader, &output_path, algorithm, &key, &header)
        }
    }
}

fn read_key(mut file: File, path: &Path, expected_len: usize) -> Result<Zeroizing<Vec<u8>>> {
    let actual_len = file
        .metadata()
        .with_context(|| format!("cannot inspect key '{}'", path.display()))?
        .len();
    if actual_len != expected_len as u64 {
        bail!(
            "key '{}' must contain exactly {expected_len} bytes, but contains {actual_len}",
            path.display()
        );
    }

    let mut key = Zeroizing::new(vec![0_u8; expected_len]);
    file.read_exact(&mut key)
        .with_context(|| format!("cannot read key '{}'", path.display()))?;
    let mut extra = [0_u8; 1];
    if file.read(&mut extra)? != 0 {
        bail!("key '{}' changed while it was being read", path.display());
    }
    Ok(key)
}

fn encrypt_file(
    input: File,
    input_path: &Path,
    output_path: &Path,
    algorithm: Algorithm,
    key: &[u8],
    keying: Keying,
) -> Result<()> {
    let (input, header) = prepare_encryption(input, input_path, algorithm, keying)?;
    encrypt_prepared(input, output_path, algorithm, key, &header)
}

fn prepare_encryption(
    input: File,
    input_path: &Path,
    algorithm: Algorithm,
    keying: Keying,
) -> Result<(File, Header)> {
    let plaintext_len = input
        .metadata()
        .with_context(|| format!("cannot inspect input '{}'", input_path.display()))?
        .len();

    let mut nonce_seed = [0_u8; 32];
    getrandom::fill(&mut nonce_seed)
        .map_err(|error| anyhow::anyhow!("operating-system random generator failed: {error}"))?;
    let header = Header::new(algorithm, plaintext_len, nonce_seed, CHUNK_SIZE, keying);
    Ok((input, header))
}

fn encrypt_prepared(
    mut input: File,
    output_path: &Path,
    algorithm: Algorithm,
    key: &[u8],
    header: &Header,
) -> Result<()> {
    let mut output = NewOutput::create(output_path)?;
    output
        .writer()
        .write_all(header.bytes())
        .context("cannot write encrypted file header")?;

    if algorithm.is_aead() {
        aead::encrypt(&mut input, output.writer(), algorithm, key, header)?;
    } else {
        legacy::encrypt(&mut input, output.writer(), algorithm, key, header)?;
    }

    ensure_eof(
        &mut input,
        "input file changed while it was being encrypted",
    )?;
    output.finish()
}

fn decrypt_file(
    input: File,
    input_path: &Path,
    output_path: &Path,
    algorithm: Algorithm,
    key: &[u8],
    expected_keying: ExpectedKeying,
) -> Result<()> {
    let (reader, header) = prepare_decryption(input, input_path, algorithm, expected_keying)?;
    decrypt_prepared(reader, output_path, algorithm, key, &header)
}

fn prepare_decryption(
    mut input: File,
    input_path: &Path,
    algorithm: Algorithm,
    expected_keying: ExpectedKeying,
) -> Result<(File, Header)> {
    let encrypted_len = input
        .metadata()
        .with_context(|| format!("cannot inspect input '{}'", input_path.display()))?
        .len();
    let mut header_bytes = [0_u8; format::HEADER_LEN];
    input
        .read_exact(&mut header_bytes)
        .context("encrypted file is too short to contain a complete header")?;
    let header = Header::parse(header_bytes, algorithm, CHUNK_SIZE, expected_keying)?;
    verify_encrypted_length(algorithm, &header, encrypted_len)?;
    Ok((input, header))
}

fn decrypt_prepared(
    mut reader: File,
    output_path: &Path,
    algorithm: Algorithm,
    key: &[u8],
    header: &Header,
) -> Result<()> {
    let mut output = NewOutput::create(output_path)?;
    if algorithm.is_aead() {
        aead::decrypt(&mut reader, output.writer(), algorithm, key, header)?;
    } else {
        legacy::decrypt(&mut reader, output.writer(), algorithm, key, header)?;
    }
    ensure_eof(
        &mut reader,
        "encrypted file contains unexpected trailing data",
    )?;
    output.finish()
}

fn verify_encrypted_length(
    algorithm: Algorithm,
    header: &format::Header,
    encrypted_len: u64,
) -> Result<()> {
    let overhead = if algorithm.is_aead() {
        format::chunk_count(header.plaintext_len, CHUNK_SIZE)
            .checked_mul(algorithm.tag_len() as u64)
            .context("encrypted file length overflows")?
    } else {
        algorithm.tag_len() as u64
    };
    let expected = (format::HEADER_LEN as u64)
        .checked_add(header.plaintext_len)
        .and_then(|length| length.checked_add(overhead))
        .context("encrypted file length overflows")?;
    if encrypted_len != expected {
        bail!(
            "encrypted file has invalid length: expected {expected} bytes from its header, found {encrypted_len}"
        );
    }
    Ok(())
}

fn ensure_eof(reader: &mut impl Read, message: &str) -> Result<()> {
    let mut extra = [0_u8; 1];
    if reader.read(&mut extra)? != 0 {
        bail!("{message}");
    }
    Ok(())
}

use std::io::Write;

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

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

    fn password_algorithm_round_trips_and_rejects_a_wrong_password(algorithm: Algorithm) {
        let directory = tempfile::tempdir().expect("create password cipher test directory");
        let plaintext: Vec<u8> = (0_usize..8193)
            .map(|index| u8::try_from(index % 251).expect("test byte fits in u8"))
            .collect();
        fs::write(directory.path().join("plain.bin"), &plaintext).expect("write plaintext");

        process_password_file_with_kdf_in(
            directory.path(),
            algorithm,
            Mode::Encrypt,
            OsStr::new("plain.bin"),
            OsStr::new("encrypted.bin"),
            b"a long and unique test passphrase",
            PasswordKdf::testing(),
        )
        .unwrap_or_else(|error| panic!("{algorithm} password encryption failed: {error:#}"));

        let wrong_password = process_password_file_with_kdf_in(
            directory.path(),
            algorithm,
            Mode::Decrypt,
            OsStr::new("encrypted.bin"),
            OsStr::new("wrong-password.out"),
            b"not the correct passphrase",
            PasswordKdf::testing(),
        );
        assert!(
            wrong_password.is_err(),
            "{algorithm} accepted a wrong password"
        );
        assert!(!directory.path().join("wrong-password.out").exists());

        process_password_file_with_kdf_in(
            directory.path(),
            algorithm,
            Mode::Decrypt,
            OsStr::new("encrypted.bin"),
            OsStr::new("decrypted.bin"),
            b"a long and unique test passphrase",
            PasswordKdf::testing(),
        )
        .unwrap_or_else(|error| panic!("{algorithm} password decryption failed: {error:#}"));

        assert_eq!(
            fs::read(directory.path().join("decrypted.bin")).expect("read decrypted file"),
            plaintext,
            "{algorithm} password round trip differed"
        );
    }

    macro_rules! password_algorithm_test {
        ($name:ident, $algorithm:expr) => {
            #[test]
            fn $name() {
                password_algorithm_round_trips_and_rejects_a_wrong_password($algorithm);
            }
        };
    }

    password_algorithm_test!(
        aesp_round_trips_and_rejects_wrong_password,
        Algorithm::Aes256GcmSiv
    );
    password_algorithm_test!(
        chap_round_trips_and_rejects_wrong_password,
        Algorithm::XChaCha20Poly1305
    );
    password_algorithm_test!(
        serp_round_trips_and_rejects_wrong_password,
        Algorithm::Serpent256
    );
    password_algorithm_test!(
        thfp_round_trips_and_rejects_wrong_password,
        Algorithm::Threefish1024
    );
    password_algorithm_test!(
        ascp_round_trips_and_rejects_wrong_password,
        Algorithm::AsconAead128
    );
    password_algorithm_test!(
        rabbitp_round_trips_and_rejects_wrong_password,
        Algorithm::Rabbit
    );
    password_algorithm_test!(
        aegis256p_round_trips_and_rejects_wrong_password,
        Algorithm::Aegis256
    );
    password_algorithm_test!(
        aegis128lp_round_trips_and_rejects_wrong_password,
        Algorithm::Aegis128L
    );

    #[test]
    #[ignore = "uses production 512 MiB Argon2id parameters twice"]
    fn production_password_kdf_round_trips() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("plain"), b"production KDF").unwrap();

        process_password_file_in(
            directory.path(),
            Algorithm::Aes256GcmSiv,
            Mode::Encrypt,
            OsStr::new("plain"),
            OsStr::new("encrypted"),
            b"a long production KDF test passphrase",
        )
        .unwrap();
        process_password_file_in(
            directory.path(),
            Algorithm::Aes256GcmSiv,
            Mode::Decrypt,
            OsStr::new("encrypted"),
            OsStr::new("decrypted"),
            b"a long production KDF test passphrase",
        )
        .unwrap();

        assert_eq!(
            fs::read(directory.path().join("decrypted")).unwrap(),
            b"production KDF"
        );
    }

    #[test]
    fn password_files_use_fresh_salts_and_authenticate_the_header() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("plain"), b"same plaintext").unwrap();

        for output in ["first.enc", "second.enc"] {
            process_password_file_with_kdf_in(
                directory.path(),
                Algorithm::Aes256GcmSiv,
                Mode::Encrypt,
                OsStr::new("plain"),
                OsStr::new(output),
                b"a long test password",
                PasswordKdf::testing(),
            )
            .unwrap();
        }

        let first = fs::read(directory.path().join("first.enc")).unwrap();
        let second = fs::read(directory.path().join("second.enc")).unwrap();
        assert_eq!(first[8], 2);
        assert_eq!(
            u32::from_le_bytes(first[56..60].try_into().unwrap()),
            PasswordKdf::testing().memory_kib
        );
        assert_ne!(&first[24..56], &second[24..56]);
        assert_ne!(first, second);

        let mut excessive_parameters = first.clone();
        excessive_parameters[56..60]
            .copy_from_slice(&(PasswordKdf::PRODUCTION.memory_kib + 1).to_le_bytes());
        fs::write(
            directory.path().join("excessive-parameters.enc"),
            excessive_parameters,
        )
        .unwrap();
        let excessive_result = process_password_file_with_kdf_in(
            directory.path(),
            Algorithm::Aes256GcmSiv,
            Mode::Decrypt,
            OsStr::new("excessive-parameters.enc"),
            OsStr::new("excessive-parameters.out"),
            b"a long test password",
            PasswordKdf::testing(),
        );
        assert!(
            excessive_result
                .unwrap_err()
                .to_string()
                .contains("password KDF memory cost")
        );
        assert!(!directory.path().join("excessive-parameters.out").exists());

        let mut damaged = first.clone();
        damaged[24] ^= 0x80;
        fs::write(directory.path().join("damaged.enc"), damaged).unwrap();
        assert!(
            process_password_file_with_kdf_in(
                directory.path(),
                Algorithm::Aes256GcmSiv,
                Mode::Decrypt,
                OsStr::new("damaged.enc"),
                OsStr::new("damaged.out"),
                b"a long test password",
                PasswordKdf::testing(),
            )
            .is_err()
        );
        assert!(!directory.path().join("damaged.out").exists());

        let mut damaged_parameters = first;
        damaged_parameters[60] = 2;
        fs::write(
            directory.path().join("damaged-parameters.enc"),
            damaged_parameters,
        )
        .unwrap();
        assert!(
            process_password_file_with_kdf_in(
                directory.path(),
                Algorithm::Aes256GcmSiv,
                Mode::Decrypt,
                OsStr::new("damaged-parameters.enc"),
                OsStr::new("damaged-parameters.out"),
                b"a long test password",
                PasswordKdf::testing(),
            )
            .is_err()
        );
        assert!(!directory.path().join("damaged-parameters.out").exists());
    }

    #[test]
    fn key_file_and_password_containers_cannot_be_mixed() {
        let directory = tempfile::tempdir().unwrap();
        let algorithm = Algorithm::Aes256GcmSiv;
        fs::write(directory.path().join("plain"), b"format separation").unwrap();
        fs::write(
            directory.path().join(algorithm.key_filename()),
            vec![0x42_u8; algorithm.key_len()],
        )
        .unwrap();

        process_file_in(
            directory.path(),
            algorithm,
            Mode::Encrypt,
            OsStr::new("plain"),
            OsStr::new("key-file.enc"),
        )
        .unwrap();
        let password_result = process_password_file_with_kdf_in(
            directory.path(),
            algorithm,
            Mode::Decrypt,
            OsStr::new("key-file.enc"),
            OsStr::new("password.out"),
            b"a long test password",
            PasswordKdf::testing(),
        );
        assert!(
            password_result
                .unwrap_err()
                .to_string()
                .contains("uses a key file")
        );

        process_password_file_with_kdf_in(
            directory.path(),
            algorithm,
            Mode::Encrypt,
            OsStr::new("plain"),
            OsStr::new("password.enc"),
            b"a long test password",
            PasswordKdf::testing(),
        )
        .unwrap();
        let key_file_result = process_file_in(
            directory.path(),
            algorithm,
            Mode::Decrypt,
            OsStr::new("password.enc"),
            OsStr::new("key-file.out"),
        );
        assert!(
            key_file_result
                .unwrap_err()
                .to_string()
                .contains("password-protected")
        );
        assert!(!directory.path().join("password.out").exists());
        assert!(!directory.path().join("key-file.out").exists());
    }
    #[test]
    fn key_file_container_compatibility_vectors_are_stable() {
        use sha2::Digest as _;
        use std::io::Cursor;

        let plaintext: Vec<u8> = (0..CHUNK_SIZE + 17)
            .map(|index| u8::try_from(index % 251).expect("test byte fits in u8"))
            .collect();
        let mut nonce_seed = [0_u8; 32];
        for (index, byte) in nonce_seed.iter_mut().enumerate() {
            *byte = u8::try_from(index * 7 + 3).expect("nonce byte fits in u8");
        }

        let expected_digests = [
            "5b730c79eb35dcdb1dfd38291b13070b536f71510576d638da4d2bc2254b0e48",
            "0bc93d33dd9881776c95783840c968cbd1d96c5378e3ed065fff6c6040ab55f9",
            "eae5bee7d5ee0cae37aab43874c4a8aac243713d970bc5f18b574c54c74e16cb",
            "f925f247a4c21f2210c5d00a40d45a5ad1bd2c073345c9b67e28276d3d127f88",
            "a3aa96be711a4dc84bb68849df5e946c332bc5c679ef84a4bfd8d7ef7f557197",
            "b262635f753e0aa69b82f239b4e5cc7d9c60592260ab66b489c405c9726a8a73",
            "be1aaf55cc1d11405eee3ba856f20c828efa46d23a4e571506cbc7d6e6fcfe0a",
            "5b7e9245fba029c16b5a31512e4de5d6a72609a8f58da5e1a021c4fa495e7fba",
        ];
        for (algorithm, expected_digest) in ALGORITHMS.into_iter().zip(expected_digests) {
            let key = vec![algorithm.id().wrapping_mul(29).wrapping_add(7); algorithm.key_len()];
            let header = Header::new(
                algorithm,
                plaintext.len() as u64,
                nonce_seed,
                CHUNK_SIZE,
                Keying::KeyFile,
            );
            let mut container = header.bytes().to_vec();
            let mut input = Cursor::new(&plaintext);
            if algorithm.is_aead() {
                aead::encrypt(&mut input, &mut container, algorithm, &key, &header)
                    .expect("encrypt fixed AEAD compatibility vector");
            } else {
                legacy::encrypt(&mut input, &mut container, algorithm, &key, &header)
                    .expect("encrypt fixed legacy compatibility vector");
            }
            let digest = sha2::Sha256::digest(&container);
            assert_eq!(
                format!("{digest:x}"),
                expected_digest,
                "{algorithm} container compatibility vector changed"
            );
        }
    }
}
