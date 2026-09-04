use std::io;

/// Errors intentionally avoid exposing keys, passwords, or unauthenticated plaintext.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("wrong password or corrupted file")]
    Authentication,
    #[error("invalid or unsupported encrypted-file format")]
    InvalidFormat,
    #[error("algorithm mismatch: file uses {found}, but this binary uses {expected}")]
    SuiteMismatch {
        expected: &'static str,
        found: &'static str,
    },
    #[error("output already exists (refusing to overwrite): {0}")]
    OutputExists(String),
    #[error("input and output must be different files")]
    SameFile,
    #[error("password must not be empty")]
    EmptyPassword,
    #[error("password is larger than the 1 MiB limit")]
    PasswordTooLong,
    #[error("password confirmation did not match")]
    PasswordMismatch,
    #[error("input changed while it was being read")]
    InputChanged,
    #[error("file is too large for this format")]
    FileTooLarge,
    #[error("cryptographic operation failed")]
    Crypto,
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
