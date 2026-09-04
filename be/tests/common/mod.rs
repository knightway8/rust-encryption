#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};

pub fn initialized_directory() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    let public = be::keygen_in(directory.path()).unwrap();
    assert!(public.starts_with("age1"));
    directory
}

pub fn data(size: usize, seed: u64) -> Vec<u8> {
    let mut state = seed ^ 0x9e37_79b9_7f4a_7c15;
    (0..size)
        .map(|index| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state as u8) ^ (index as u8).wrapping_mul(31)
        })
        .collect()
}

pub fn roundtrip_case(size: usize, seed: u64) {
    let directory = initialized_directory();
    let plaintext = data(size, seed);
    fs::write(directory.path().join("plain.bin"), &plaintext).unwrap();

    assert_eq!(
        be::encrypt_in(
            directory.path(),
            Path::new("plain.bin"),
            Path::new("cipher.age")
        )
        .unwrap(),
        size as u64
    );
    assert_eq!(
        be::verify_in(directory.path(), Path::new("cipher.age")).unwrap(),
        size as u64
    );
    assert_eq!(
        be::decrypt_in(
            directory.path(),
            Path::new("cipher.age"),
            Path::new("recovered.bin")
        )
        .unwrap(),
        size as u64
    );
    assert_eq!(
        fs::read(directory.path().join("recovered.bin")).unwrap(),
        plaintext
    );
    assert!(
        fs::read(directory.path().join("cipher.age"))
            .unwrap()
            .starts_with(b"age-encryption.org/v1")
    );
    assert_no_temporary_files(directory.path());
}

pub fn assert_no_temporary_files(directory: &Path) {
    let leftovers: Vec<PathBuf> = fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(".be-")
        })
        .collect();
    assert!(
        leftovers.is_empty(),
        "temporary files remain: {leftovers:?}"
    );
}

pub fn replace_secret_key(path: &Path, contents: &[u8]) {
    fs::write(path, contents).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}
