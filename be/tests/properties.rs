mod common;

use std::fs;
use std::path::Path;

use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 32,
        max_shrink_iters: 2_000,
        .. ProptestConfig::default()
    })]

    #[test]
    fn arbitrary_binary_payloads_round_trip(payload in proptest::collection::vec(any::<u8>(), 0..131_073)) {
        let directory = common::initialized_directory();
        fs::write(directory.path().join("plain.bin"), &payload).unwrap();
        be::encrypt_in(directory.path(), Path::new("plain.bin"), Path::new("cipher.age")).unwrap();
        be::decrypt_in(directory.path(), Path::new("cipher.age"), Path::new("recovered.bin")).unwrap();
        prop_assert_eq!(fs::read(directory.path().join("recovered.bin")).unwrap(), payload);
        common::assert_no_temporary_files(directory.path());
    }

    #[test]
    fn arbitrary_single_byte_corruption_is_rejected(
        payload in proptest::collection::vec(any::<u8>(), 0..100_000),
        selector in any::<usize>(),
    ) {
        let directory = common::initialized_directory();
        fs::write(directory.path().join("plain.bin"), payload).unwrap();
        be::encrypt_in(directory.path(), Path::new("plain.bin"), Path::new("cipher.age")).unwrap();
        let path = directory.path().join("cipher.age");
        let mut ciphertext = fs::read(&path).unwrap();
        let index = selector % ciphertext.len();
        ciphertext[index] ^= 1;
        fs::write(path, ciphertext).unwrap();

        prop_assert!(be::verify_in(directory.path(), Path::new("cipher.age")).is_err());
        prop_assert!(be::decrypt_in(directory.path(), Path::new("cipher.age"), Path::new("out.bin")).is_err());
        prop_assert!(!directory.path().join("out.bin").exists());
        common::assert_no_temporary_files(directory.path());
    }

    #[test]
    fn arbitrary_truncation_is_rejected(
        payload in proptest::collection::vec(any::<u8>(), 0..100_000),
        selector in any::<usize>(),
    ) {
        let directory = common::initialized_directory();
        fs::write(directory.path().join("plain.bin"), payload).unwrap();
        be::encrypt_in(directory.path(), Path::new("plain.bin"), Path::new("cipher.age")).unwrap();
        let path = directory.path().join("cipher.age");
        let mut ciphertext = fs::read(&path).unwrap();
        let truncated_length = selector % ciphertext.len();
        ciphertext.truncate(truncated_length);
        fs::write(path, ciphertext).unwrap();

        prop_assert!(be::verify_in(directory.path(), Path::new("cipher.age")).is_err());
        prop_assert!(be::decrypt_in(directory.path(), Path::new("cipher.age"), Path::new("out.bin")).is_err());
        prop_assert!(!directory.path().join("out.bin").exists());
        common::assert_no_temporary_files(directory.path());
    }

    #[test]
    fn arbitrary_existing_outputs_are_preserved(
        plaintext in proptest::collection::vec(any::<u8>(), 0..10_000),
        existing in proptest::collection::vec(any::<u8>(), 0..10_000),
    ) {
        let directory = common::initialized_directory();
        fs::write(directory.path().join("plain.bin"), plaintext).unwrap();
        fs::write(directory.path().join("cipher.age"), &existing).unwrap();
        prop_assert!(be::encrypt_in(directory.path(), Path::new("plain.bin"), Path::new("cipher.age")).is_err());
        prop_assert_eq!(fs::read(directory.path().join("cipher.age")).unwrap(), existing);
        common::assert_no_temporary_files(directory.path());
    }
}
