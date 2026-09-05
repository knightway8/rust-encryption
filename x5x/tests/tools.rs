use std::ffi::OsStr;
use std::fs;
use x3x::{generate_random_key_in, make_deterministic_key_in, xor_file_in_place};

#[test]
fn keygen_writes_exact_size_and_refuses_overwrite() {
    let directory = tempfile::tempdir().unwrap();
    generate_random_key_in(directory.path(), 4097).unwrap();
    let path = directory.path().join("keygen.key");
    let original = fs::read(&path).unwrap();
    assert_eq!(original.len(), 4097);
    assert!(original.iter().any(|byte| *byte != 0));

    assert!(generate_random_key_in(directory.path(), 3).is_err());
    assert_eq!(fs::read(path).unwrap(), original);
}

#[test]
fn otp_streams_and_is_its_own_inverse() {
    let directory = tempfile::tempdir().unwrap();
    let original: Vec<u8> = (0_usize..2_100_123)
        .map(|index| u8::try_from(index % 239).expect("test byte fits in u8"))
        .collect();
    let key: Vec<u8> = (0..original.len())
        .map(|index| {
            u8::try_from(index % 256)
                .expect("test byte fits in u8")
                .wrapping_mul(73)
                .wrapping_add(19)
        })
        .collect();
    fs::write(directory.path().join("data.bin"), &original).unwrap();
    fs::write(directory.path().join("otp.key"), &key).unwrap();

    xor_file_in_place(
        directory.path(),
        OsStr::new("data.bin"),
        OsStr::new("otp.key"),
    )
    .unwrap();
    let transformed = fs::read(directory.path().join("data.bin")).unwrap();
    assert_ne!(transformed, original);
    assert!(
        transformed
            .iter()
            .zip(&original)
            .zip(&key)
            .all(|((actual, plain), mask)| *actual == (*plain ^ *mask))
    );

    xor_file_in_place(
        directory.path(),
        OsStr::new("data.bin"),
        OsStr::new("otp.key"),
    )
    .unwrap();
    assert_eq!(
        fs::read(directory.path().join("data.bin")).unwrap(),
        original
    );
}

#[test]
fn short_otp_key_fails_before_input_changes() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(directory.path().join("data"), b"unchanged").unwrap();
    fs::write(directory.path().join("key"), b"short").unwrap();

    assert!(xor_file_in_place(directory.path(), OsStr::new("data"), OsStr::new("key")).is_err());
    assert_eq!(
        fs::read(directory.path().join("data")).unwrap(),
        b"unchanged"
    );
}

#[test]
fn otp_refuses_to_use_the_input_as_its_key() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(directory.path().join("data"), b"contents").unwrap();
    assert!(xor_file_in_place(directory.path(), OsStr::new("data"), OsStr::new("data"),).is_err());
    assert_eq!(
        fs::read(directory.path().join("data")).unwrap(),
        b"contents"
    );
}

#[test]
fn otp_refuses_a_hard_link_alias_of_the_input() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(directory.path().join("data"), b"contents").unwrap();
    fs::hard_link(
        directory.path().join("data"),
        directory.path().join("key-alias"),
    )
    .unwrap();

    assert!(
        xor_file_in_place(
            directory.path(),
            OsStr::new("data"),
            OsStr::new("key-alias"),
        )
        .is_err()
    );
    assert_eq!(
        fs::read(directory.path().join("data")).unwrap(),
        b"contents"
    );
}

#[test]
#[ignore = "uses production 256 MiB Argon2id parameters twice"]
fn keymake_is_deterministic_and_not_a_repeated_short_block() {
    let first_directory = tempfile::tempdir().unwrap();
    let second_directory = tempfile::tempdir().unwrap();
    make_deterministic_key_in(first_directory.path(), 4096, b"a long test passphrase").unwrap();
    make_deterministic_key_in(second_directory.path(), 4096, b"a long test passphrase").unwrap();

    let first = fs::read(first_directory.path().join("keymake.key")).unwrap();
    let second = fs::read(second_directory.path().join("keymake.key")).unwrap();
    assert_eq!(first, second);
    let first_block = &first[..64];
    assert!(
        first[64..]
            .as_chunks::<64>()
            .0
            .iter()
            .any(|block| block != first_block)
    );
}
