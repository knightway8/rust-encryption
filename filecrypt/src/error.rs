use std::io;
use std::path::PathBuf;

use thiserror::Error;

/// Errors returned by filecrypt operations.
#[derive(Debug, Error)]
pub enum FileCryptError {
    /// A filesystem operation failed.
    #[error("could not {action} '{}': {source}", path.display())]
    Io {
        /// Description of the attempted operation.
        action: &'static str,
        /// Path involved in the operation.
        path: PathBuf,
        /// Underlying operating-system error.
        #[source]
        source: io::Error,
    },

    /// The destination already exists; filecrypt never replaces it.
    #[error("refusing to overwrite existing destination '{}'; choose a new output path", .0.display())]
    OutputExists(PathBuf),

    /// The destination path cannot name a file.
    #[error("invalid output path '{}': it must include a file name", .0.display())]
    InvalidOutputPath(PathBuf),

    /// The operating system returned an executable path without a parent.
    #[error("could not determine the running executable's directory")]
    InvalidExecutablePath,

    /// The input is not a regular file.
    #[error("input '{}' is not a regular file", .0.display())]
    InputNotRegular(PathBuf),

    /// The required key is absent.
    #[error("key file not found at '{}'; create it with `filecrypt keygen`", .0.display())]
    KeyNotFound(PathBuf),

    /// The key path is not a regular file.
    #[error("key path '{}' is not a regular file", .0.display())]
    KeyNotRegular(PathBuf),

    /// The raw key file is not exactly 32 bytes.
    #[error("key file '{}' must contain exactly 32 raw bytes (found {actual})", path.display())]
    InvalidKeyLength {
        /// Key path.
        path: PathBuf,
        /// Observed byte length.
        actual: u64,
    },

    /// A Unix key file grants group or other access.
    #[error(
        "insecure key permissions on '{}': the key must be accessible only to the current user",
        .0.display()
    )]
    InsecureKeyPermissions(PathBuf),

    /// The encrypted input does not use a supported filecrypt format.
    #[error("invalid encrypted file: {0}")]
    InvalidFormat(&'static str),

    /// Authentication failed, or the encrypted stream is structurally corrupt.
    #[error("authentication failed: wrong key or corrupted encrypted input")]
    AuthenticationFailed,

    /// The input cannot be represented by this format's STREAM counter.
    #[error("input is too large; maximum supported plaintext size is {maximum} bytes")]
    FileTooLarge {
        /// Maximum supported plaintext length.
        maximum: u64,
    },

    /// The source length differed from its opening metadata while it was read.
    #[error("input changed while it was being encrypted; no output was created")]
    InputChanged,

    /// The operating system's cryptographically secure RNG failed.
    #[error("operating-system random number generator failed: {0}")]
    Random(String),

    /// Publication succeeded, but a late durability step reported failure.
    #[error(
        "'{}' was created without overwriting anything, but publication durability could not be confirmed; crash durability is uncertain: {source}",
        path.display()
    )]
    PublishedButDurabilityUncertain {
        /// Newly published path.
        path: PathBuf,
        /// Directory synchronization error.
        #[source]
        source: io::Error,
    },

    /// The protected staging path no longer refers to the open staging file.
    #[error("protected temporary file was replaced before publication; no output was created")]
    StagingFileReplaced,

    /// The final path does not refer to the file that was just published.
    #[error(
        "publication identity check failed for '{}'; the destination may have been tampered with",
        .0.display()
    )]
    PublicationIdentityMismatch(PathBuf),

    /// An internal cryptographic invariant failed.
    #[error("cryptographic operation failed")]
    Crypto,
}

impl FileCryptError {
    pub(crate) fn io(action: &'static str, path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::Io {
            action,
            path: path.into(),
            source,
        }
    }
}

/// Result type used by the filecrypt library.
pub type Result<T> = std::result::Result<T, FileCryptError>;
