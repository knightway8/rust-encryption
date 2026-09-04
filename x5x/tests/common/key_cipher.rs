#![allow(dead_code)]

mod process;

use process::{assert_failure_contains, assert_success, run, run_in, stdout};
use std::fs;
use std::path::Path;

#[derive(Clone, Copy)]
pub struct KeyCipherApp {
    pub command: &'static str,
    pub binary: &'static str,
    pub key_filename: &'static str,
    pub key_len: usize,
}

fn write_key(directory: &Path, app: KeyCipherApp) {
    let key: Vec<u8> = (0..app.key_len)
        .map(|index| {
            u8::try_from(index)
                .expect("test key index fits in u8")
                .wrapping_mul(37)
                .wrapping_add(11)
        })
        .collect();
    fs::write(directory.join(app.key_filename), key).expect("write cipher key");
}

pub fn reports_usage_for_wrong_argument_counts(app: KeyCipherApp) {
    let expected = format!("usage: {} [E or D] [filename] [output-file]", app.command);
    for arguments in [
        Vec::<&str>::new(),
        vec!["E"],
        vec!["E", "input"],
        vec!["E", "input", "output", "extra"],
    ] {
        assert_failure_contains(&run(app.binary, &arguments), &expected);
    }
}

pub fn rejects_invalid_operations(app: KeyCipherApp) {
    for operation in ["e", "d", "encrypt", "DECRYPT", "ED", "-"] {
        let output = run(app.binary, &[operation, "input", "output"]);
        assert_failure_contains(&output, "operation must be exactly E or D (uppercase)");
    }
}

pub fn round_trips_multiple_chunks(app: KeyCipherApp) {
    let directory = tempfile::tempdir().expect("create cipher test directory");
    write_key(directory.path(), app);
    let plaintext: Vec<u8> = (0..x3x::CHUNK_SIZE + 73)
        .map(|index| u8::try_from(index % 251).expect("test byte fits in u8"))
        .collect();
    fs::write(directory.path().join("plain.bin"), &plaintext).expect("write plaintext");

    let encrypted = run_in(
        app.binary,
        directory.path(),
        &["E", "plain.bin", "cipher.bin"],
    );
    assert_success(&encrypted);
    assert!(stdout(&encrypted).contains("encryption complete"));
    assert_ne!(
        fs::read(directory.path().join("cipher.bin")).expect("read ciphertext"),
        plaintext
    );

    let decrypted = run_in(
        app.binary,
        directory.path(),
        &["D", "cipher.bin", "plain.out"],
    );
    assert_success(&decrypted);
    assert!(stdout(&decrypted).contains("decryption complete"));
    assert_eq!(
        fs::read(directory.path().join("plain.out")).expect("read decrypted output"),
        plaintext
    );
}

pub fn round_trips_empty_files(app: KeyCipherApp) {
    let directory = tempfile::tempdir().expect("create cipher test directory");
    write_key(directory.path(), app);
    fs::write(directory.path().join("empty"), []).expect("write empty input");

    assert_success(&run_in(
        app.binary,
        directory.path(),
        &["E", "empty", "empty.enc"],
    ));
    assert_success(&run_in(
        app.binary,
        directory.path(),
        &["D", "empty.enc", "empty.out"],
    ));
    let expected_encrypted_len = if matches!(app.command, "ser" | "thf" | "rabbit") {
        128
    } else {
        80
    };
    assert_eq!(
        fs::metadata(directory.path().join("empty.enc"))
            .expect("inspect encrypted empty file")
            .len(),
        expected_encrypted_len
    );
    assert!(
        fs::read(directory.path().join("empty.out"))
            .expect("read empty output")
            .is_empty()
    );
}

pub fn produces_fresh_ciphertexts(app: KeyCipherApp) {
    let directory = tempfile::tempdir().expect("create cipher test directory");
    write_key(directory.path(), app);
    fs::write(directory.path().join("plain"), b"identical plaintext").expect("write plaintext");

    for output_name in ["first.enc", "second.enc"] {
        assert_success(&run_in(
            app.binary,
            directory.path(),
            &["E", "plain", output_name],
        ));
    }
    assert_ne!(
        fs::read(directory.path().join("first.enc")).expect("read first ciphertext"),
        fs::read(directory.path().join("second.enc")).expect("read second ciphertext")
    );
}

pub fn rejects_a_missing_key(app: KeyCipherApp) {
    let directory = tempfile::tempdir().expect("create cipher test directory");
    fs::write(directory.path().join("plain"), b"data").expect("write plaintext");
    let output = run_in(app.binary, directory.path(), &["E", "plain", "output"]);
    assert_failure_contains(&output, "required key");
    assert!(!directory.path().join("output").exists());
}

pub fn rejects_wrong_key_sizes(app: KeyCipherApp) {
    for size in [0, app.key_len - 1, app.key_len + 1] {
        let directory = tempfile::tempdir().expect("create cipher test directory");
        fs::write(directory.path().join(app.key_filename), vec![0x33; size])
            .expect("write malformed key");
        fs::write(directory.path().join("plain"), b"data").expect("write plaintext");
        let output = run_in(app.binary, directory.path(), &["E", "plain", "output"]);
        assert_failure_contains(
            &output,
            &format!("must contain exactly {} bytes", app.key_len),
        );
        assert!(!directory.path().join("output").exists());
    }
}

pub fn rejects_a_missing_input(app: KeyCipherApp) {
    let directory = tempfile::tempdir().expect("create cipher test directory");
    write_key(directory.path(), app);
    let output = run_in(app.binary, directory.path(), &["E", "missing", "output"]);
    assert_failure_contains(&output, "cannot open input file");
    assert!(!directory.path().join("output").exists());
}

pub fn preserves_an_existing_output(app: KeyCipherApp) {
    let directory = tempfile::tempdir().expect("create cipher test directory");
    write_key(directory.path(), app);
    fs::write(directory.path().join("plain"), b"secret").expect("write plaintext");
    fs::write(directory.path().join("output"), b"keep me").expect("write existing output");

    let output = run_in(app.binary, directory.path(), &["E", "plain", "output"]);
    assert_failure_contains(&output, "refusing to overwrite");
    assert_eq!(
        fs::read(directory.path().join("output")).expect("read preserved output"),
        b"keep me"
    );
}

pub fn rejects_nonportable_filenames(app: KeyCipherApp) {
    let directory = tempfile::tempdir().expect("create cipher test directory");
    write_key(directory.path(), app);
    fs::write(directory.path().join("plain"), b"data").expect("write plaintext");

    for invalid_input in ["folder/input", "folder\\input", "NUL", "trailing."] {
        let output = run_in(
            app.binary,
            directory.path(),
            &["E", invalid_input, "output"],
        );
        assert_failure_contains(&output, "error:");
        assert!(!directory.path().join("output").exists());
    }
    for invalid_output in ["folder/output", "folder\\output", "bad:name", "COM1"] {
        let output = run_in(
            app.binary,
            directory.path(),
            &["E", "plain", invalid_output],
        );
        assert_failure_contains(&output, "error:");
    }
}

pub fn protects_the_active_key_file(app: KeyCipherApp) {
    let directory = tempfile::tempdir().expect("create cipher test directory");
    write_key(directory.path(), app);
    fs::write(directory.path().join("plain"), b"data").expect("write plaintext");

    let input_result = run_in(
        app.binary,
        directory.path(),
        &["E", app.key_filename, "output"],
    );
    assert_failure_contains(
        &input_result,
        "refusing to process the active key file as input",
    );
    assert!(!directory.path().join("output").exists());

    let original_key = fs::read(directory.path().join(app.key_filename)).expect("read key");
    let output_result = run_in(
        app.binary,
        directory.path(),
        &["E", "plain", app.key_filename],
    );
    assert_failure_contains(
        &output_result,
        "refusing to use the active key filename as output",
    );
    assert_eq!(
        fs::read(directory.path().join(app.key_filename)).expect("read preserved key"),
        original_key
    );
}

pub fn rejects_damaged_ciphertext(app: KeyCipherApp) {
    let directory = tempfile::tempdir().expect("create cipher test directory");
    write_key(directory.path(), app);
    fs::write(directory.path().join("plain"), b"authenticated contents").expect("write plaintext");
    assert_success(&run_in(
        app.binary,
        directory.path(),
        &["E", "plain", "cipher"],
    ));

    let ciphertext_path = directory.path().join("cipher");
    let mut ciphertext = fs::read(&ciphertext_path).expect("read ciphertext");
    let last = ciphertext.last_mut().expect("ciphertext is not empty");
    *last ^= 0x80;
    fs::write(&ciphertext_path, ciphertext).expect("write damaged ciphertext");

    let output = run_in(app.binary, directory.path(), &["D", "cipher", "output"]);
    assert_failure_contains(&output, "authentication failed");
    assert!(!directory.path().join("output").exists());
}

pub fn rejects_a_wrong_key_without_output(app: KeyCipherApp) {
    let directory = tempfile::tempdir().expect("create cipher test directory");
    write_key(directory.path(), app);
    fs::write(directory.path().join("plain"), b"secret contents").expect("write plaintext");
    assert_success(&run_in(
        app.binary,
        directory.path(),
        &["E", "plain", "cipher"],
    ));
    fs::write(
        directory.path().join(app.key_filename),
        vec![0xA5; app.key_len],
    )
    .expect("replace key");

    let output = run_in(app.binary, directory.path(), &["D", "cipher", "output"]);
    assert_failure_contains(&output, "authentication failed");
    assert!(!directory.path().join("output").exists());
}

pub fn round_trips_exact_chunk_boundaries_without_modifying_inputs(app: KeyCipherApp) {
    for length in [x3x::CHUNK_SIZE - 1, x3x::CHUNK_SIZE, x3x::CHUNK_SIZE + 1] {
        let directory = tempfile::tempdir().expect("create boundary test directory");
        write_key(directory.path(), app);
        let plaintext: Vec<u8> = (0..length)
            .map(|index| u8::try_from(index % 251).expect("test byte fits in u8"))
            .collect();
        fs::write(directory.path().join("plain"), &plaintext).expect("write boundary plaintext");

        assert_success(&run_in(
            app.binary,
            directory.path(),
            &["E", "plain", "cipher"],
        ));
        assert_eq!(
            fs::read(directory.path().join("plain")).expect("read unchanged plaintext"),
            plaintext
        );
        let ciphertext = fs::read(directory.path().join("cipher")).expect("read ciphertext");

        assert_success(&run_in(
            app.binary,
            directory.path(),
            &["D", "cipher", "output"],
        ));
        assert_eq!(
            fs::read(directory.path().join("output")).expect("read boundary output"),
            plaintext
        );
        assert_eq!(
            fs::read(directory.path().join("cipher")).expect("read unchanged ciphertext"),
            ciphertext
        );
    }
}

pub fn rejects_truncated_and_trailing_data_without_artifacts(app: KeyCipherApp) {
    let directory = tempfile::tempdir().expect("create malformed-length test directory");
    write_key(directory.path(), app);
    fs::write(directory.path().join("plain"), b"authenticated contents").expect("write plaintext");
    assert_success(&run_in(
        app.binary,
        directory.path(),
        &["E", "plain", "cipher"],
    ));
    let ciphertext = fs::read(directory.path().join("cipher")).expect("read ciphertext");

    let mut truncated = ciphertext.clone();
    truncated.pop().expect("ciphertext is not empty");
    let mut trailing = ciphertext;
    trailing.push(0xA5);

    for (input_name, output_name, contents) in [
        ("truncated", "truncated.out", truncated),
        ("trailing", "trailing.out", trailing),
    ] {
        fs::write(directory.path().join(input_name), &contents)
            .expect("write malformed ciphertext");
        let output = run_in(
            app.binary,
            directory.path(),
            &["D", input_name, output_name],
        );
        assert_failure_contains(&output, "encrypted file has invalid length");
        assert!(!directory.path().join(output_name).exists());
        assert_eq!(
            fs::read(directory.path().join(input_name)).expect("read unchanged malformed input"),
            contents
        );
    }

    assert_eq!(
        fs::read_dir(directory.path())
            .expect("list malformed-length test directory")
            .count(),
        5,
        "failed decryptions left a temporary artifact"
    );
}

pub fn rejects_malformed_headers_without_output(app: KeyCipherApp) {
    let directory = tempfile::tempdir().expect("create malformed-header test directory");
    write_key(directory.path(), app);
    fs::write(directory.path().join("plain"), b"header validation").expect("write plaintext");
    assert_success(&run_in(
        app.binary,
        directory.path(),
        &["E", "plain", "cipher"],
    ));
    let ciphertext = fs::read(directory.path().join("cipher")).expect("read ciphertext");

    let mut variants = Vec::new();
    for offset in [0_usize, 8, 9, 10, 11, 12, 16, 56] {
        let mut malformed = ciphertext.clone();
        malformed[offset] ^= if offset == 8 || offset == 9 {
            0x7F
        } else {
            0x01
        };
        variants.push(malformed);
    }

    for (index, contents) in variants.into_iter().enumerate() {
        let input_name = format!("bad-header-{index}");
        let output_name = format!("bad-header-{index}.out");
        fs::write(directory.path().join(&input_name), contents).expect("write malformed header");
        let output = run_in(
            app.binary,
            directory.path(),
            &["D", &input_name, &output_name],
        );
        assert_failure_contains(&output, "error:");
        assert!(!directory.path().join(output_name).exists());
    }
}

pub fn authenticates_nonce_header_bytes(app: KeyCipherApp) {
    let directory = tempfile::tempdir().expect("create authenticated-header test directory");
    write_key(directory.path(), app);
    fs::write(directory.path().join("plain"), b"authenticated header").expect("write plaintext");
    assert_success(&run_in(
        app.binary,
        directory.path(),
        &["E", "plain", "cipher"],
    ));

    let damaged_path = directory.path().join("damaged-header");
    let mut damaged = fs::read(directory.path().join("cipher")).expect("read ciphertext");
    damaged[24] ^= 0x80;
    fs::write(&damaged_path, damaged).expect("write damaged header");

    let output = run_in(
        app.binary,
        directory.path(),
        &["D", "damaged-header", "output"],
    );
    assert_failure_contains(&output, "authentication failed");
    assert!(!directory.path().join("output").exists());
}

pub fn preserves_an_existing_decryption_output(app: KeyCipherApp) {
    let directory = tempfile::tempdir().expect("create decryption no-clobber test directory");
    write_key(directory.path(), app);
    fs::write(directory.path().join("plain"), b"secret").expect("write plaintext");
    assert_success(&run_in(
        app.binary,
        directory.path(),
        &["E", "plain", "cipher"],
    ));
    let ciphertext = fs::read(directory.path().join("cipher")).expect("read ciphertext");
    fs::write(directory.path().join("output"), b"preserve me").expect("write existing output");

    let result = run_in(app.binary, directory.path(), &["D", "cipher", "output"]);
    assert_failure_contains(&result, "refusing to overwrite");
    assert_eq!(
        fs::read(directory.path().join("output")).expect("read preserved output"),
        b"preserve me"
    );
    assert_eq!(
        fs::read(directory.path().join("cipher")).expect("read unchanged ciphertext"),
        ciphertext
    );
}
pub fn round_trips_single_byte(app: KeyCipherApp) {
    let directory = tempfile::tempdir().expect("create single-byte cipher test directory");
    write_key(directory.path(), app);
    fs::write(directory.path().join("plain"), [0xa5_u8]).expect("write plaintext");

    assert_success(&run_in(
        app.binary,
        directory.path(),
        &["E", "plain", "cipher"],
    ));
    assert_success(&run_in(
        app.binary,
        directory.path(),
        &["D", "cipher", "restored"],
    ));
    assert_eq!(
        fs::read(directory.path().join("restored")).expect("read restored plaintext"),
        [0xa5_u8]
    );
}

pub fn round_trips_every_byte_value(app: KeyCipherApp) {
    let directory = tempfile::tempdir().expect("create all-bytes cipher test directory");
    write_key(directory.path(), app);
    let plaintext: Vec<u8> = (0_u8..=u8::MAX).collect();
    fs::write(directory.path().join("plain"), &plaintext).expect("write plaintext");

    assert_success(&run_in(
        app.binary,
        directory.path(),
        &["E", "plain", "cipher"],
    ));
    assert_success(&run_in(
        app.binary,
        directory.path(),
        &["D", "cipher", "restored"],
    ));
    assert_eq!(
        fs::read(directory.path().join("restored")).expect("read restored plaintext"),
        plaintext
    );
}

pub fn successful_round_trip_leaves_only_named_files(app: KeyCipherApp) {
    let directory = tempfile::tempdir().expect("create artifact-cleanup cipher test directory");
    write_key(directory.path(), app);
    fs::write(directory.path().join("plain"), b"artifact audit").expect("write plaintext");

    assert_success(&run_in(
        app.binary,
        directory.path(),
        &["E", "plain", "cipher"],
    ));
    assert_success(&run_in(
        app.binary,
        directory.path(),
        &["D", "cipher", "restored"],
    ));

    let mut entries: Vec<_> = fs::read_dir(directory.path())
        .expect("list cipher directory")
        .map(|entry| entry.expect("read directory entry").file_name())
        .collect();
    entries.sort();
    let mut expected = vec![
        std::ffi::OsString::from(app.key_filename),
        std::ffi::OsString::from("cipher"),
        std::ffi::OsString::from("plain"),
        std::ffi::OsString::from("restored"),
    ];
    expected.sort();
    assert_eq!(entries, expected, "successful operations left an artifact");
}
macro_rules! define_key_cipher_tests {
    ($binary:expr, $command:literal, $key_filename:literal, $key_len:expr) => {
        const APP: $crate::common::KeyCipherApp = $crate::common::KeyCipherApp {
            command: $command,
            binary: $binary,
            key_filename: $key_filename,
            key_len: $key_len,
        };

        #[test]
        fn reports_usage_for_wrong_argument_counts() {
            $crate::common::reports_usage_for_wrong_argument_counts(APP);
        }

        #[test]
        fn rejects_invalid_operations() {
            $crate::common::rejects_invalid_operations(APP);
        }

        #[test]
        fn round_trips_multiple_chunks() {
            $crate::common::round_trips_multiple_chunks(APP);
        }

        #[test]
        fn round_trips_empty_files() {
            $crate::common::round_trips_empty_files(APP);
        }

        #[test]
        fn produces_fresh_ciphertexts() {
            $crate::common::produces_fresh_ciphertexts(APP);
        }

        #[test]
        fn rejects_a_missing_key() {
            $crate::common::rejects_a_missing_key(APP);
        }

        #[test]
        fn rejects_wrong_key_sizes() {
            $crate::common::rejects_wrong_key_sizes(APP);
        }

        #[test]
        fn rejects_a_missing_input() {
            $crate::common::rejects_a_missing_input(APP);
        }

        #[test]
        fn preserves_an_existing_output() {
            $crate::common::preserves_an_existing_output(APP);
        }

        #[test]
        fn rejects_nonportable_filenames() {
            $crate::common::rejects_nonportable_filenames(APP);
        }

        #[test]
        fn protects_the_active_key_file() {
            $crate::common::protects_the_active_key_file(APP);
        }

        #[test]
        fn rejects_damaged_ciphertext() {
            $crate::common::rejects_damaged_ciphertext(APP);
        }

        #[test]
        fn rejects_a_wrong_key_without_output() {
            $crate::common::rejects_a_wrong_key_without_output(APP);
        }
        #[test]
        fn round_trips_exact_chunk_boundaries_without_modifying_inputs() {
            $crate::common::round_trips_exact_chunk_boundaries_without_modifying_inputs(APP);
        }

        #[test]
        fn rejects_truncated_and_trailing_data_without_artifacts() {
            $crate::common::rejects_truncated_and_trailing_data_without_artifacts(APP);
        }

        #[test]
        fn rejects_malformed_headers_without_output() {
            $crate::common::rejects_malformed_headers_without_output(APP);
        }

        #[test]
        fn authenticates_nonce_header_bytes() {
            $crate::common::authenticates_nonce_header_bytes(APP);
        }

        #[test]
        fn preserves_an_existing_decryption_output() {
            $crate::common::preserves_an_existing_decryption_output(APP);
        }
        #[test]
        fn round_trips_single_byte() {
            $crate::common::round_trips_single_byte(APP);
        }

        #[test]
        fn round_trips_every_byte_value() {
            $crate::common::round_trips_every_byte_value(APP);
        }

        #[test]
        fn successful_round_trip_leaves_only_named_files() {
            $crate::common::successful_round_trip_leaves_only_named_files(APP);
        }
    };
}

pub(crate) use define_key_cipher_tests;
