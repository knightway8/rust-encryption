//! Independent age test vectors from C2SP/CCTV, as distributed in age 0.12.1.
use age::secrecy::SecretString;
use best::{Decryption, Operation, decrypt_stream};
use rstest::rstest;
use sha2::{Digest, Sha256};
use std::{fs, io::Read, path::PathBuf};

#[rstest]
fn cctv_conformance(#[files("tests/vectors/*")] path: PathBuf) {
    let data = fs::read(&path).unwrap();
    let split = data.windows(2).position(|w| w == b"\n\n").unwrap();
    let metadata = std::str::from_utf8(&data[..split]).unwrap();
    let fields: Vec<_> = metadata
        .lines()
        .map(|line| line.split_once(": ").unwrap())
        .collect();
    let field = |key: &str| fields.iter().find(|(k, _)| *k == key).map(|(_, v)| *v);
    let bytes = &data[split + 2..];
    let mut expanded = Vec::new();
    let encrypted = if field("compressed") == Some("zlib") {
        flate2::read::ZlibDecoder::new(bytes)
            .take(32 * 1024 * 1024)
            .read_to_end(&mut expanded)
            .unwrap();
        &expanded[..]
    } else {
        bytes
    };
    let method = if let Some(password) = field("passphrase") {
        Decryption::Password {
            password: SecretString::from(password.to_owned()),
            max_work_factor: 16,
        }
    } else {
        let mut identities: Vec<_> = fields
            .iter()
            .filter(|(k, _)| *k == "identity")
            .map(|(_, v)| v.parse::<age::x25519::Identity>().unwrap())
            .collect();
        if identities.is_empty() {
            identities.push(age::x25519::Identity::generate());
        }
        Decryption::Identities(identities)
    };
    let mut plaintext = Vec::new();
    let result = decrypt_stream(encrypted, &mut plaintext, method, &Operation::default());
    if field("armored") == Some("yes") {
        assert!(result.is_err(), "ASCII armor must be explicitly refused");
        return;
    }
    if field("expect") == Some("success") {
        assert!(result.is_ok(), "{path:?}: {result:?}");
        assert_eq!(
            format!("{:x}", Sha256::digest(&plaintext)),
            field("payload").unwrap(),
            "{path:?}"
        );
    } else {
        assert!(result.is_err(), "invalid vector accepted: {path:?}");
    }
}
