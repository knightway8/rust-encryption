mod common;

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

fn encrypted_fixture(payload: &[u8]) -> tempfile::TempDir {
    let directory = common::initialized_directory();
    fs::write(directory.path().join("plain.bin"), payload).unwrap();
    be::encrypt_in(
        directory.path(),
        Path::new("plain.bin"),
        Path::new("cipher.age"),
    )
    .unwrap();
    directory
}

fn assert_rejected_without_output(directory: &Path) {
    assert!(
        be::decrypt_in(
            directory,
            Path::new("cipher.age"),
            Path::new("recovered.bin")
        )
        .is_err()
    );
    assert!(!directory.join("recovered.bin").exists());
    common::assert_no_temporary_files(directory);
}

fn overwrite_cipher_byte(directory: &Path, index: usize) {
    let path = directory.join("cipher.age");
    let mut bytes = fs::read(&path).unwrap();
    bytes[index] ^= 0x80;
    fs::write(path, bytes).unwrap();
}

#[test]
fn keygen_creates_matching_age_keypair() {
    let directory = tempfile::tempdir().unwrap();
    let generated = be::keygen_in(directory.path()).unwrap();
    assert!(generated.starts_with("age1"));
    assert_eq!(be::public_key_in(directory.path()).unwrap(), generated);
    assert!(
        fs::read_to_string(directory.path().join(be::SECRET_KEY_FILE))
            .unwrap()
            .starts_with("AGE-SECRET-KEY-1")
    );
    assert_eq!(
        fs::read_to_string(directory.path().join(be::PUBLIC_KEY_FILE))
            .unwrap()
            .trim(),
        generated
    );
}

#[test]
fn keygen_never_overwrites_existing_pair() {
    let directory = common::initialized_directory();
    let secret = fs::read(directory.path().join(be::SECRET_KEY_FILE)).unwrap();
    let public = fs::read(directory.path().join(be::PUBLIC_KEY_FILE)).unwrap();
    assert!(be::keygen_in(directory.path()).is_err());
    assert_eq!(
        fs::read(directory.path().join(be::SECRET_KEY_FILE)).unwrap(),
        secret
    );
    assert_eq!(
        fs::read(directory.path().join(be::PUBLIC_KEY_FILE)).unwrap(),
        public
    );
}

#[test]
fn keygen_never_overwrites_existing_public_key() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(directory.path().join(be::PUBLIC_KEY_FILE), b"keep-public").unwrap();
    assert!(be::keygen_in(directory.path()).is_err());
    assert_eq!(
        fs::read(directory.path().join(be::PUBLIC_KEY_FILE)).unwrap(),
        b"keep-public"
    );
    assert!(!directory.path().join(be::SECRET_KEY_FILE).exists());
}

#[test]
fn keygen_never_overwrites_existing_secret_key() {
    let directory = tempfile::tempdir().unwrap();
    common::replace_secret_key(&directory.path().join(be::SECRET_KEY_FILE), b"keep-secret");
    assert!(be::keygen_in(directory.path()).is_err());
    assert_eq!(
        fs::read(directory.path().join(be::SECRET_KEY_FILE)).unwrap(),
        b"keep-secret"
    );
    assert!(!directory.path().join(be::PUBLIC_KEY_FILE).exists());
}

#[test]
fn encryption_works_with_public_key_only() {
    let directory = common::initialized_directory();
    let secret = fs::read(directory.path().join(be::SECRET_KEY_FILE)).unwrap();
    fs::remove_file(directory.path().join(be::SECRET_KEY_FILE)).unwrap();
    fs::write(
        directory.path().join("plain.bin"),
        b"public-only encryption",
    )
    .unwrap();
    be::encrypt_in(
        directory.path(),
        Path::new("plain.bin"),
        Path::new("cipher.age"),
    )
    .unwrap();
    common::replace_secret_key(&directory.path().join(be::SECRET_KEY_FILE), &secret);
    be::decrypt_in(
        directory.path(),
        Path::new("cipher.age"),
        Path::new("recovered.bin"),
    )
    .unwrap();
    assert_eq!(
        fs::read(directory.path().join("recovered.bin")).unwrap(),
        b"public-only encryption"
    );
}

#[test]
fn mismatched_public_and_secret_keys_are_rejected_for_encryption() {
    let directory = common::initialized_directory();
    let other = common::initialized_directory();
    fs::copy(
        other.path().join(be::PUBLIC_KEY_FILE),
        directory.path().join(be::PUBLIC_KEY_FILE),
    )
    .unwrap();
    fs::write(directory.path().join("plain.bin"), b"data").unwrap();
    assert!(
        be::encrypt_in(
            directory.path(),
            Path::new("plain.bin"),
            Path::new("cipher.age")
        )
        .is_err()
    );
    assert!(!directory.path().join("cipher.age").exists());
}

#[test]
fn wrong_secret_key_is_rejected() {
    let directory = encrypted_fixture(b"wrong-key test");
    let other = common::initialized_directory();
    let wrong = fs::read(other.path().join(be::SECRET_KEY_FILE)).unwrap();
    common::replace_secret_key(&directory.path().join(be::SECRET_KEY_FILE), &wrong);
    assert_rejected_without_output(directory.path());
}

#[test]
fn invalid_secret_key_is_rejected() {
    let directory = common::initialized_directory();
    common::replace_secret_key(
        &directory.path().join(be::SECRET_KEY_FILE),
        b"not-an-age-secret-key\n",
    );
    assert!(be::public_key_in(directory.path()).is_err());
}

#[test]
fn invalid_public_key_is_rejected() {
    let directory = common::initialized_directory();
    fs::write(
        directory.path().join(be::PUBLIC_KEY_FILE),
        b"not-an-age-public-key\n",
    )
    .unwrap();
    fs::write(directory.path().join("plain.bin"), b"data").unwrap();
    assert!(
        be::encrypt_in(
            directory.path(),
            Path::new("plain.bin"),
            Path::new("cipher.age")
        )
        .is_err()
    );
}

#[test]
fn secret_key_file_rejects_multiple_tokens() {
    let directory = common::initialized_directory();
    let secret = fs::read_to_string(directory.path().join(be::SECRET_KEY_FILE)).unwrap();
    common::replace_secret_key(
        &directory.path().join(be::SECRET_KEY_FILE),
        format!("{secret}{secret}").as_bytes(),
    );
    assert!(be::public_key_in(directory.path()).is_err());
}

#[test]
fn public_key_file_rejects_multiple_tokens() {
    let directory = common::initialized_directory();
    let public = fs::read_to_string(directory.path().join(be::PUBLIC_KEY_FILE)).unwrap();
    fs::write(
        directory.path().join(be::PUBLIC_KEY_FILE),
        format!("{public}{public}"),
    )
    .unwrap();
    fs::write(directory.path().join("plain.bin"), b"data").unwrap();
    assert!(
        be::encrypt_in(
            directory.path(),
            Path::new("plain.bin"),
            Path::new("cipher.age")
        )
        .is_err()
    );
}

#[test]
fn oversized_secret_key_file_is_rejected() {
    let directory = common::initialized_directory();
    common::replace_secret_key(
        &directory.path().join(be::SECRET_KEY_FILE),
        &vec![b'A'; 4097],
    );
    assert!(be::public_key_in(directory.path()).is_err());
}

#[test]
fn oversized_public_key_file_is_rejected() {
    let directory = common::initialized_directory();
    fs::write(directory.path().join(be::PUBLIC_KEY_FILE), vec![b'a'; 4097]).unwrap();
    fs::write(directory.path().join("plain.bin"), b"data").unwrap();
    assert!(
        be::encrypt_in(
            directory.path(),
            Path::new("plain.bin"),
            Path::new("cipher.age")
        )
        .is_err()
    );
}

#[test]
fn non_utf8_secret_key_is_rejected() {
    let directory = common::initialized_directory();
    common::replace_secret_key(
        &directory.path().join(be::SECRET_KEY_FILE),
        &[0xff, 0xfe, 0xfd],
    );
    assert!(be::public_key_in(directory.path()).is_err());
}

#[test]
fn non_utf8_public_key_is_rejected() {
    let directory = common::initialized_directory();
    fs::write(
        directory.path().join(be::PUBLIC_KEY_FILE),
        [0xff, 0xfe, 0xfd],
    )
    .unwrap();
    fs::write(directory.path().join("plain.bin"), b"data").unwrap();
    assert!(
        be::encrypt_in(
            directory.path(),
            Path::new("plain.bin"),
            Path::new("cipher.age")
        )
        .is_err()
    );
}

#[test]
fn missing_input_is_rejected() {
    let directory = common::initialized_directory();
    assert!(
        be::encrypt_in(
            directory.path(),
            Path::new("missing.bin"),
            Path::new("cipher.age")
        )
        .is_err()
    );
}

#[test]
fn directory_input_is_rejected() {
    let directory = common::initialized_directory();
    fs::create_dir(directory.path().join("folder")).unwrap();
    assert!(
        be::encrypt_in(
            directory.path(),
            Path::new("folder"),
            Path::new("cipher.age")
        )
        .is_err()
    );
}

#[test]
fn encryption_never_overwrites_output() {
    let directory = common::initialized_directory();
    fs::write(directory.path().join("plain.bin"), b"new data").unwrap();
    fs::write(directory.path().join("cipher.age"), b"keep this").unwrap();
    assert!(
        be::encrypt_in(
            directory.path(),
            Path::new("plain.bin"),
            Path::new("cipher.age")
        )
        .is_err()
    );
    assert_eq!(
        fs::read(directory.path().join("cipher.age")).unwrap(),
        b"keep this"
    );
}

#[test]
fn decryption_never_overwrites_output() {
    let directory = encrypted_fixture(b"new data");
    fs::write(directory.path().join("recovered.bin"), b"keep this").unwrap();
    assert!(
        be::decrypt_in(
            directory.path(),
            Path::new("cipher.age"),
            Path::new("recovered.bin")
        )
        .is_err()
    );
    assert_eq!(
        fs::read(directory.path().join("recovered.bin")).unwrap(),
        b"keep this"
    );
}

#[test]
fn same_input_and_output_name_is_rejected() {
    let directory = common::initialized_directory();
    fs::write(directory.path().join("same.bin"), b"keep this").unwrap();
    assert!(
        be::encrypt_in(
            directory.path(),
            Path::new("same.bin"),
            Path::new("same.bin")
        )
        .is_err()
    );
    assert_eq!(
        fs::read(directory.path().join("same.bin")).unwrap(),
        b"keep this"
    );
}

#[test]
fn case_only_input_output_difference_is_rejected() {
    let directory = common::initialized_directory();
    fs::write(directory.path().join("Same.bin"), b"keep this").unwrap();
    assert!(
        be::encrypt_in(
            directory.path(),
            Path::new("Same.bin"),
            Path::new("same.BIN")
        )
        .is_err()
    );
}

#[test]
fn path_components_are_rejected() {
    let directory = common::initialized_directory();
    fs::write(directory.path().join("plain.bin"), b"data").unwrap();
    for invalid in ["../plain.bin", "sub/plain.bin", ".", ""] {
        assert!(
            be::encrypt_in(
                directory.path(),
                Path::new(invalid),
                Path::new("cipher.age")
            )
            .is_err(),
            "accepted invalid path {invalid:?}"
        );
    }
}

#[test]
fn absolute_paths_are_rejected() {
    let directory = common::initialized_directory();
    fs::write(directory.path().join("plain.bin"), b"data").unwrap();
    assert!(
        be::encrypt_in(
            directory.path(),
            &directory.path().join("plain.bin"),
            Path::new("cipher.age")
        )
        .is_err()
    );
}

#[test]
fn key_files_are_rejected_as_data_files() {
    let directory = common::initialized_directory();
    for key_name in ["key.key", "KEY.KEY", "key.pub", "KEY.PUB"] {
        assert!(
            be::encrypt_in(
                directory.path(),
                Path::new(key_name),
                Path::new("cipher.age")
            )
            .is_err()
        );
        assert!(
            be::encrypt_in(
                directory.path(),
                Path::new("plain.bin"),
                Path::new(key_name)
            )
            .is_err()
        );
    }
}

#[test]
fn unicode_filenames_round_trip() {
    let directory = common::initialized_directory();
    fs::write(directory.path().join("秘密 🔐.txt"), "hello 世界").unwrap();
    be::encrypt_in(
        directory.path(),
        Path::new("秘密 🔐.txt"),
        Path::new("加密.age"),
    )
    .unwrap();
    be::decrypt_in(
        directory.path(),
        Path::new("加密.age"),
        Path::new("恢复.txt"),
    )
    .unwrap();
    assert_eq!(
        fs::read_to_string(directory.path().join("恢复.txt")).unwrap(),
        "hello 世界"
    );
}

#[test]
fn filenames_with_spaces_round_trip() {
    let directory = common::initialized_directory();
    fs::write(directory.path().join("plain file.bin"), b"spaces").unwrap();
    be::encrypt_in(
        directory.path(),
        Path::new("plain file.bin"),
        Path::new("cipher file.age"),
    )
    .unwrap();
    be::decrypt_in(
        directory.path(),
        Path::new("cipher file.age"),
        Path::new("recovered file.bin"),
    )
    .unwrap();
    assert_eq!(
        fs::read(directory.path().join("recovered file.bin")).unwrap(),
        b"spaces"
    );
}

#[test]
fn repeated_encryption_produces_distinct_ciphertexts() {
    let directory = common::initialized_directory();
    fs::write(directory.path().join("plain.bin"), b"same plaintext").unwrap();
    be::encrypt_in(
        directory.path(),
        Path::new("plain.bin"),
        Path::new("one.age"),
    )
    .unwrap();
    be::encrypt_in(
        directory.path(),
        Path::new("plain.bin"),
        Path::new("two.age"),
    )
    .unwrap();
    assert_ne!(
        fs::read(directory.path().join("one.age")).unwrap(),
        fs::read(directory.path().join("two.age")).unwrap()
    );
}

#[test]
fn header_tampering_is_rejected() {
    let directory = encrypted_fixture(b"header tampering");
    overwrite_cipher_byte(directory.path(), 0);
    assert_rejected_without_output(directory.path());
}

#[test]
fn middle_tampering_is_rejected() {
    let directory = encrypted_fixture(&common::data(200_000, 17));
    let length = fs::metadata(directory.path().join("cipher.age"))
        .unwrap()
        .len() as usize;
    overwrite_cipher_byte(directory.path(), length / 2);
    assert_rejected_without_output(directory.path());
}

#[test]
fn final_tag_tampering_is_rejected() {
    let directory = encrypted_fixture(b"final tag tampering");
    let length = fs::metadata(directory.path().join("cipher.age"))
        .unwrap()
        .len() as usize;
    overwrite_cipher_byte(directory.path(), length - 1);
    assert_rejected_without_output(directory.path());
}

#[test]
fn empty_ciphertext_is_rejected() {
    let directory = common::initialized_directory();
    fs::write(directory.path().join("cipher.age"), []).unwrap();
    assert_rejected_without_output(directory.path());
}

#[test]
fn truncated_header_is_rejected() {
    let directory = encrypted_fixture(b"truncated header");
    let bytes = fs::read(directory.path().join("cipher.age")).unwrap();
    fs::write(directory.path().join("cipher.age"), &bytes[..10]).unwrap();
    assert_rejected_without_output(directory.path());
}

#[test]
fn truncated_payload_is_rejected() {
    let directory = encrypted_fixture(&common::data(200_000, 41));
    let bytes = fs::read(directory.path().join("cipher.age")).unwrap();
    fs::write(
        directory.path().join("cipher.age"),
        &bytes[..bytes.len() / 2],
    )
    .unwrap();
    assert_rejected_without_output(directory.path());
}

#[test]
fn missing_final_byte_is_rejected() {
    let directory = encrypted_fixture(b"missing final byte");
    let mut bytes = fs::read(directory.path().join("cipher.age")).unwrap();
    bytes.pop();
    fs::write(directory.path().join("cipher.age"), bytes).unwrap();
    assert_rejected_without_output(directory.path());
}

#[test]
fn appended_byte_is_rejected() {
    let directory = encrypted_fixture(b"appended byte");
    OpenOptions::new()
        .append(true)
        .open(directory.path().join("cipher.age"))
        .unwrap()
        .write_all(&[0x42])
        .unwrap();
    assert_rejected_without_output(directory.path());
}

#[test]
fn appended_full_chunk_is_rejected() {
    let directory = encrypted_fixture(&common::data(65_536, 99));
    OpenOptions::new()
        .append(true)
        .open(directory.path().join("cipher.age"))
        .unwrap()
        .write_all(&vec![0x42; 65_552])
        .unwrap();
    assert_rejected_without_output(directory.path());
}

#[test]
fn verify_reports_plaintext_length() {
    let directory = encrypted_fixture(&common::data(123_456, 77));
    assert_eq!(
        be::verify_in(directory.path(), Path::new("cipher.age")).unwrap(),
        123_456
    );
}

#[test]
fn public_key_can_be_derived_when_key_pub_is_missing() {
    let directory = common::initialized_directory();
    let expected = fs::read_to_string(directory.path().join(be::PUBLIC_KEY_FILE))
        .unwrap()
        .trim()
        .to_owned();
    fs::remove_file(directory.path().join(be::PUBLIC_KEY_FILE)).unwrap();
    assert_eq!(be::public_key_in(directory.path()).unwrap(), expected);
}

#[test]
fn public_key_command_detects_mismatch() {
    let directory = common::initialized_directory();
    let other = common::initialized_directory();
    fs::copy(
        other.path().join(be::PUBLIC_KEY_FILE),
        directory.path().join(be::PUBLIC_KEY_FILE),
    )
    .unwrap();
    assert!(be::public_key_in(directory.path()).is_err());
}

#[test]
fn empty_file_round_trips() {
    common::roundtrip_case(0, 1);
}

#[test]
fn chunk_boundary_minus_one_round_trips() {
    common::roundtrip_case(65_535, 2);
}

#[test]
fn exact_chunk_boundary_round_trips() {
    common::roundtrip_case(65_536, 3);
}

#[test]
fn chunk_boundary_plus_one_round_trips() {
    common::roundtrip_case(65_537, 4);
}

#[test]
fn multiple_chunks_round_trip() {
    common::roundtrip_case(1_048_579, 5);
}

#[test]
fn invalid_base_directory_is_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let missing = directory.path().join("missing");
    assert!(be::keygen_in(&missing).is_err());
    assert!(be::encrypt_in(&missing, Path::new("in"), Path::new("out")).is_err());
}

#[cfg(unix)]
#[test]
fn broad_secret_key_permissions_are_rejected() {
    use std::os::unix::fs::PermissionsExt;

    let directory = common::initialized_directory();
    let path = directory.path().join(be::SECRET_KEY_FILE);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(be::public_key_in(directory.path()).is_err());
}

#[cfg(unix)]
#[test]
fn generated_secret_key_permissions_are_private() {
    use std::os::unix::fs::PermissionsExt;

    let directory = common::initialized_directory();
    let mode = fs::metadata(directory.path().join(be::SECRET_KEY_FILE))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o077, 0);
}

#[cfg(unix)]
#[test]
fn decrypted_output_permissions_are_private() {
    use std::os::unix::fs::PermissionsExt;

    let directory = encrypted_fixture(b"private output");
    be::decrypt_in(
        directory.path(),
        Path::new("cipher.age"),
        Path::new("recovered.bin"),
    )
    .unwrap();
    let mode = fs::metadata(directory.path().join("recovered.bin"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o077, 0);
}

#[cfg(unix)]
#[test]
fn secret_key_symlink_is_rejected() {
    use std::os::unix::fs::symlink;

    let directory = common::initialized_directory();
    let secret = fs::read(directory.path().join(be::SECRET_KEY_FILE)).unwrap();
    let real = directory.path().join("real-secret");
    common::replace_secret_key(&real, &secret);
    fs::remove_file(directory.path().join(be::SECRET_KEY_FILE)).unwrap();
    symlink(&real, directory.path().join(be::SECRET_KEY_FILE)).unwrap();
    assert!(be::public_key_in(directory.path()).is_err());
}
