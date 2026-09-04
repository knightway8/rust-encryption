use std::io;
use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("{operation} '{}': {source}", path.display())]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("invalid encrypted file: {0}")]
    InvalidFormat(&'static str),

    #[error("encrypted file version {0} is not supported")]
    UnsupportedVersion(u8),

    #[error("encrypted file requests unsafe resource parameters: {0}")]
    UnsafeParameters(&'static str),

    #[error("authentication failed: the password is wrong or the encrypted file was modified")]
    AuthenticationFailed,

    #[error("cryptographic operation failed")]
    CryptographicFailure,

    #[error("the output already exists: '{}'; refusing to overwrite it", .0.display())]
    OutputExists(PathBuf),

    #[error("input and output resolve to the same path")]
    SamePath,

    #[error("password must not be empty")]
    EmptyPassword,

    #[error("password exceeds the 1 MiB safety limit")]
    PasswordTooLarge,

    #[error("passwords do not match")]
    PasswordsDoNotMatch,

    #[error("the operating system random number generator failed: {0}")]
    Randomness(String),
}

impl Error {
    pub(crate) fn io(operation: &'static str, path: &std::path::Path, source: io::Error) -> Self {
        Self::Io {
            operation,
            path: path.to_owned(),
            source,
        }
    }
}
