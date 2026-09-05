use std::io;

/// Errors never contain passwords, private keys, or plaintext.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Invalid(&'static str),
    #[error("{action}: {source}")]
    Io {
        action: &'static str,
        source: io::Error,
    },
    #[error("encryption failed: {0}")]
    Encrypt(#[from] age::EncryptError),
    #[error("decryption failed: {}", decrypt_message(.0))]
    Decrypt(#[from] age::DecryptError),
    #[error("operation cancelled; destination was not published")]
    Cancelled,
    #[error("byte limit exceeded; destination was not published")]
    Limit,
}

pub type Result<T> = std::result::Result<T, Error>;

fn decrypt_message(error: &age::DecryptError) -> &'static str {
    // age 0.12.1's Display for ExcessiveWork performs unchecked arithmetic on
    // attacker-controlled work factors. Keep our CLI errors bounded and stable,
    // including when the configured cap is below age's calibrated target.
    match error {
        age::DecryptError::ExcessiveWork { .. } => {
            "scrypt cost exceeds the allowed work factor; only raise --max-work-factor for a trusted file"
        }
        age::DecryptError::DecryptionFailed | age::DecryptError::KeyDecryptionFailed => {
            "wrong password or damaged encrypted data"
        }
        age::DecryptError::NoMatchingKeys => "no supplied identity can decrypt this file",
        age::DecryptError::InvalidHeader | age::DecryptError::UnknownFormat => {
            "invalid or unsupported age header"
        }
        age::DecryptError::InvalidMac => "header authentication failed",
        age::DecryptError::Io(_) => "cannot read encrypted input",
        _ => "invalid encrypted data or unsupported recipient type",
    }
}

pub(crate) trait IoContext<T> {
    fn context(self, action: &'static str) -> Result<T>;
}

impl<T> IoContext<T> for io::Result<T> {
    fn context(self, action: &'static str) -> Result<T> {
        self.map_err(|source| Error::Io { action, source })
    }
}
