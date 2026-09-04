use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Usage(String),

    #[error("unknown algorithm '{0}'")]
    UnknownAlgorithm(String),

    #[error("operation must be exactly uppercase E or D, got '{0}'")]
    InvalidOperation(String),

    #[error("cannot determine the directory containing the executable")]
    MissingExecutableDirectory,

    #[error("I/O error while {action} '{path}': {source}")]
    Io {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("input is not a regular file: '{0}'")]
    NotARegularFile(PathBuf),

    #[error("refusing to replace existing output: '{0}'")]
    OutputExists(PathBuf),

    #[error(
        "file was published at '{path}', but syncing its directory failed; verify durability: {source}"
    )]
    PublishedButNotDurable {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("key file appeared concurrently and was not replaced: '{0}'")]
    KeyAlreadyExists(PathBuf),

    #[error("key file is invalid for {algorithm}: {reason}")]
    InvalidKey {
        algorithm: crate::Algorithm,
        reason: &'static str,
    },

    #[error("refusing symbolic-link key file: '{0}'")]
    SymlinkKey(PathBuf),

    #[error("key file permissions are too broad (expected owner-only): '{0}'")]
    InsecureKeyPermissions(PathBuf),

    #[error("invalid encrypted file: {0}")]
    InvalidContainer(&'static str),

    #[error("requested {requested}, but the encrypted file uses {actual}")]
    AlgorithmMismatch {
        requested: crate::Algorithm,
        actual: crate::Algorithm,
    },

    #[error("authentication failed (wrong key or modified data)")]
    AuthenticationFailed,

    #[error("cryptographic operation failed: {0}")]
    Crypto(&'static str),

    #[error("the operating system random generator failed: {0}")]
    Random(String),

    #[error("input is too large to process safely on this platform")]
    InputTooLarge,

    #[error("not enough memory to process the file")]
    OutOfMemory,
}

impl Error {
    pub(crate) fn io(
        action: &'static str,
        path: impl Into<PathBuf>,
        source: std::io::Error,
    ) -> Self {
        Self::Io {
            action,
            path: path.into(),
            source,
        }
    }
}
