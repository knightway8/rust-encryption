//! Password-based, streaming authenticated file encryption.
//!
//! The public API deliberately exposes only the production KDF settings. The
//! on-disk format stores bounded KDF parameters so future versions can migrate
//! without accepting attacker-controlled, unbounded resource costs.

mod crypto;
mod error;
mod format;
pub mod password;

use std::ffi::OsString;
use std::path::{Path, PathBuf};

pub use crypto::{decrypt_file, encrypt_file};
pub use error::Error;

pub const ENCRYPTED_EXTENSION: &str = "x4x";

/// Return the default non-destructive output name used by `encrypt`.
#[must_use]
pub fn default_encrypted_path(input: &Path) -> PathBuf {
    let mut name: OsString = input.as_os_str().to_owned();
    name.push(".");
    name.push(ENCRYPTED_EXTENSION);
    PathBuf::from(name)
}

/// Return the default output name used by `decrypt`.
#[must_use]
pub fn default_decrypted_path(input: &Path) -> PathBuf {
    if input
        .extension()
        .is_some_and(|ext| ext == ENCRYPTED_EXTENSION)
    {
        let mut output = input.to_owned();
        output.set_extension("");
        output
    } else {
        let mut name: OsString = input.as_os_str().to_owned();
        name.push(".dec");
        PathBuf::from(name)
    }
}

#[cfg(test)]
mod path_tests {
    use super::*;

    #[test]
    fn encrypted_default_appends_instead_of_replacing_extension() {
        assert_eq!(
            default_encrypted_path(Path::new("archive.tar")),
            PathBuf::from("archive.tar.x4x")
        );
    }

    #[test]
    fn decrypted_default_removes_x4x_extension() {
        assert_eq!(
            default_decrypted_path(Path::new("archive.tar.x4x")),
            PathBuf::from("archive.tar")
        );
    }

    #[test]
    fn decrypted_default_appends_dec_for_unknown_extension() {
        assert_eq!(
            default_decrypted_path(Path::new("archive.bin")),
            PathBuf::from("archive.bin.dec")
        );
    }

    #[test]
    fn encrypted_default_appends_to_extensionless_name() {
        assert_eq!(
            default_encrypted_path(Path::new("archive")),
            PathBuf::from("archive.x4x")
        );
    }

    #[test]
    fn decrypted_default_handles_multiple_dots() {
        assert_eq!(
            default_decrypted_path(Path::new("backup.2026.08.x4x")),
            PathBuf::from("backup.2026.08")
        );
    }

    #[test]
    fn decrypted_extension_match_is_intentionally_case_sensitive() {
        assert_eq!(
            default_decrypted_path(Path::new("archive.X4X")),
            PathBuf::from("archive.X4X.dec")
        );
    }

    #[test]
    fn extension_in_parent_directory_does_not_affect_file_name() {
        assert_eq!(
            default_decrypted_path(Path::new("vault.x4x/archive")),
            PathBuf::from("vault.x4x/archive.dec")
        );
    }

    #[test]
    fn encrypting_an_already_encrypted_name_still_never_replaces_it() {
        assert_eq!(
            default_encrypted_path(Path::new("archive.x4x")),
            PathBuf::from("archive.x4x.x4x")
        );
    }
}
