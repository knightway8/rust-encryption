use std::ffi::OsStr;
use std::fs;
use x3x::{Algorithm, CHUNK_SIZE, Mode, process_file_in};

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

fn write_algorithm_key(directory: &std::path::Path, algorithm: Algorithm) {
    let key: Vec<u8> = (0..algorithm.key_len())
        .map(|index| {
            u8::try_from(index)
                .expect("test key index fits in u8")
                .wrapping_mul(29)
                .wrapping_add(7)
        })
        .collect();
    fs::write(directory.join(algorithm.key_filename()), key).unwrap();
}

#[test]
fn every_algorithm_round_trips_multiple_chunks() {
    let root = tempfile::tempdir().unwrap();
    let plaintext: Vec<u8> = (0..CHUNK_SIZE + 73)
        .map(|index| u8::try_from(index % 251).expect("test byte fits in u8"))
        .collect();

    for algorithm in ALGORITHMS {
        let directory = root.path().join(algorithm.command());
        fs::create_dir(&directory).unwrap();
        write_algorithm_key(&directory, algorithm);
        fs::write(directory.join("plain.bin"), &plaintext).unwrap();

        process_file_in(
            &directory,
            algorithm,
            Mode::Encrypt,
            OsStr::new("plain.bin"),
            OsStr::new("encrypted.bin"),
        )
        .unwrap_or_else(|error| panic!("{algorithm} encryption failed: {error:#}"));
        process_file_in(
            &directory,
            algorithm,
            Mode::Decrypt,
            OsStr::new("encrypted.bin"),
            OsStr::new("decrypted.bin"),
        )
        .unwrap_or_else(|error| panic!("{algorithm} decryption failed: {error:#}"));

        assert_eq!(
            fs::read(directory.join("decrypted.bin")).unwrap(),
            plaintext,
            "{algorithm} round trip differed"
        );
    }
}

#[test]
fn empty_file_is_authenticated_and_round_trips() {
    let directory = tempfile::tempdir().unwrap();
    let algorithm = Algorithm::Aes256GcmSiv;
    write_algorithm_key(directory.path(), algorithm);
    fs::write(directory.path().join("empty"), []).unwrap();

    process_file_in(
        directory.path(),
        algorithm,
        Mode::Encrypt,
        OsStr::new("empty"),
        OsStr::new("empty.enc"),
    )
    .unwrap();
    process_file_in(
        directory.path(),
        algorithm,
        Mode::Decrypt,
        OsStr::new("empty.enc"),
        OsStr::new("empty.out"),
    )
    .unwrap();

    assert!(
        fs::read(directory.path().join("empty.out"))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        fs::metadata(directory.path().join("empty.enc"))
            .unwrap()
            .len(),
        80
    );
}

#[test]
fn tampering_is_rejected_and_creates_no_output() {
    for algorithm in [Algorithm::XChaCha20Poly1305, Algorithm::Rabbit] {
        let directory = tempfile::tempdir().unwrap();
        write_algorithm_key(directory.path(), algorithm);
        fs::write(directory.path().join("message"), b"authenticated message").unwrap();
        process_file_in(
            directory.path(),
            algorithm,
            Mode::Encrypt,
            OsStr::new("message"),
            OsStr::new("message.enc"),
        )
        .unwrap();

        let encrypted_path = directory.path().join("message.enc");
        let mut encrypted = fs::read(&encrypted_path).unwrap();
        encrypted[64] ^= 0x80;
        fs::write(&encrypted_path, encrypted).unwrap();

        let result = process_file_in(
            directory.path(),
            algorithm,
            Mode::Decrypt,
            OsStr::new("message.enc"),
            OsStr::new("should-not-exist"),
        );
        assert!(result.is_err(), "{algorithm} accepted tampered data");
        assert!(!directory.path().join("should-not-exist").exists());
    }
}

#[test]
fn wrong_key_is_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let algorithm = Algorithm::Aegis256;
    write_algorithm_key(directory.path(), algorithm);
    fs::write(directory.path().join("message"), b"secret").unwrap();
    process_file_in(
        directory.path(),
        algorithm,
        Mode::Encrypt,
        OsStr::new("message"),
        OsStr::new("message.enc"),
    )
    .unwrap();

    fs::write(
        directory.path().join(algorithm.key_filename()),
        vec![0xA5; algorithm.key_len()],
    )
    .unwrap();
    assert!(
        process_file_in(
            directory.path(),
            algorithm,
            Mode::Decrypt,
            OsStr::new("message.enc"),
            OsStr::new("message.out"),
        )
        .is_err()
    );
    assert!(!directory.path().join("message.out").exists());
}

#[test]
fn existing_output_is_never_changed() {
    let directory = tempfile::tempdir().unwrap();
    let algorithm = Algorithm::AsconAead128;
    write_algorithm_key(directory.path(), algorithm);
    fs::write(directory.path().join("input"), b"plaintext").unwrap();
    fs::write(directory.path().join("existing"), b"keep this").unwrap();

    assert!(
        process_file_in(
            directory.path(),
            algorithm,
            Mode::Encrypt,
            OsStr::new("input"),
            OsStr::new("existing"),
        )
        .is_err()
    );
    assert_eq!(
        fs::read(directory.path().join("existing")).unwrap(),
        b"keep this"
    );
}

#[test]
fn fresh_nonces_make_encryptions_different() {
    let directory = tempfile::tempdir().unwrap();
    let algorithm = Algorithm::Aes256GcmSiv;
    write_algorithm_key(directory.path(), algorithm);
    fs::write(directory.path().join("input"), b"same plaintext").unwrap();

    for output in ["first.enc", "second.enc"] {
        process_file_in(
            directory.path(),
            algorithm,
            Mode::Encrypt,
            OsStr::new("input"),
            OsStr::new(output),
        )
        .unwrap();
    }
    assert_ne!(
        fs::read(directory.path().join("first.enc")).unwrap(),
        fs::read(directory.path().join("second.enc")).unwrap()
    );
}

#[test]
fn paths_and_active_key_input_are_refused() {
    let directory = tempfile::tempdir().unwrap();
    let algorithm = Algorithm::Aes256GcmSiv;
    write_algorithm_key(directory.path(), algorithm);
    fs::write(directory.path().join("input"), b"data").unwrap();

    assert!(
        process_file_in(
            directory.path(),
            algorithm,
            Mode::Encrypt,
            OsStr::new("subdir/input"),
            OsStr::new("output"),
        )
        .is_err()
    );
    for invalid_output in [
        "folder\\output",
        "file:stream",
        "has*asterisk",
        "has?question",
        "has\"quote",
        "has<less",
        "has>greater",
        "has|pipe",
        "has\u{1f}control",
        "NUL",
        "trailing.",
    ] {
        assert!(
            process_file_in(
                directory.path(),
                algorithm,
                Mode::Encrypt,
                OsStr::new("input"),
                OsStr::new(invalid_output),
            )
            .is_err(),
            "accepted nonportable filename {invalid_output}"
        );
    }
    assert!(
        process_file_in(
            directory.path(),
            algorithm,
            Mode::Encrypt,
            OsStr::new(algorithm.key_filename()),
            OsStr::new("output"),
        )
        .is_err()
    );
}

#[test]
fn hard_link_alias_of_active_key_is_refused() {
    let directory = tempfile::tempdir().unwrap();
    let algorithm = Algorithm::Aes256GcmSiv;
    write_algorithm_key(directory.path(), algorithm);
    fs::hard_link(
        directory.path().join(algorithm.key_filename()),
        directory.path().join("key-alias"),
    )
    .unwrap();

    let result = process_file_in(
        directory.path(),
        algorithm,
        Mode::Encrypt,
        OsStr::new("key-alias"),
        OsStr::new("output"),
    );
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("refusing to process the active key file as input")
    );
    assert!(!directory.path().join("output").exists());
}

#[cfg(windows)]
#[test]
fn case_alias_of_active_key_is_refused() {
    let directory = tempfile::tempdir().unwrap();
    let algorithm = Algorithm::Aes256GcmSiv;
    write_algorithm_key(directory.path(), algorithm);

    let result = process_file_in(
        directory.path(),
        algorithm,
        Mode::Encrypt,
        OsStr::new("AES.KEY"),
        OsStr::new("output"),
    );
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("refusing to process the active key file as input")
    );
    assert!(!directory.path().join("output").exists());
}
