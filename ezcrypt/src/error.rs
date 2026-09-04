use std::error::Error as StdError;
use std::fmt;
use std::io;
use std::path::PathBuf;

/// Errors returned by ezcrypt.
#[derive(Debug)]
pub enum EzError {
    InvalidPath(&'static str),
    InputNotRegular(PathBuf),
    ReparsePoint(PathBuf),
    MultipleHardLinks {
        path: PathBuf,
        links: u32,
    },
    AlternateDataStream(PathBuf),
    UnsupportedFileSystem {
        path: PathBuf,
        name: String,
    },
    UnsupportedDrive(PathBuf),
    UnsupportedAttributes {
        path: PathBuf,
        attributes: u32,
    },
    DestinationExists(PathBuf),
    InvalidPassword(&'static str),
    PasswordPrompt(io::Error),
    InvalidFormat(FormatError),
    AuthenticationFailed,
    InputChanged(PathBuf),
    Io {
        action: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    Kdf,
    Randomness,
    VerificationFailed(PathBuf),
    PublishedButSourceRetained {
        output: PathBuf,
        source: io::Error,
    },
    CommittedButSourceRetained {
        input: PathBuf,
        output: PathBuf,
        source: io::Error,
    },
    CommittedSourceRemovalUnconfirmed {
        input: PathBuf,
        output: PathBuf,
        source: io::Error,
    },
}

impl EzError {
    pub(crate) fn io(action: &'static str, path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::Io {
            action,
            path: path.into(),
            source,
        }
    }
}

impl fmt::Display for EzError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPath(reason) => write!(f, "invalid input path: {reason}"),
            Self::InputNotRegular(path) => {
                write!(f, "input is not a regular file: {}", path.display())
            }
            Self::ReparsePoint(path) => write!(
                f,
                "refusing to transform a Windows reparse point: {}",
                path.display()
            ),
            Self::MultipleHardLinks { path, links } => write!(
                f,
                "refusing to transform {} because it has {links} hard links",
                path.display()
            ),
            Self::AlternateDataStream(path) => write!(
                f,
                "refusing a path that names an alternate data stream: {}",
                path.display()
            ),
            Self::UnsupportedFileSystem { path, name } => write!(
                f,
                "refusing to transform {} on unsupported filesystem {name}; local NTFS is required",
                path.display()
            ),
            Self::UnsupportedDrive(path) => write!(
                f,
                "refusing to transform {} because it is not on a local fixed drive",
                path.display()
            ),
            Self::UnsupportedAttributes { path, attributes } => write!(
                f,
                "refusing to transform {} because unsupported Windows storage attributes are set (0x{attributes:08x})",
                path.display()
            ),
            Self::DestinationExists(path) => write!(
                f,
                "destination already exists; nothing was changed: {}",
                path.display()
            ),
            Self::InvalidPassword(reason) => write!(f, "invalid password: {reason}"),
            Self::PasswordPrompt(source) => write!(f, "could not read password securely: {source}"),
            Self::InvalidFormat(reason) => write!(f, "invalid ezcrypt file: {reason}"),
            Self::AuthenticationFailed => {
                f.write_str("wrong password or encrypted file is damaged")
            }
            Self::InputChanged(path) => write!(
                f,
                "input changed while it was being processed; nothing was committed: {}",
                path.display()
            ),
            Self::Io {
                action,
                path,
                source,
            } => write!(f, "could not {action} {}: {source}", path.display()),
            Self::Kdf => f.write_str("password key derivation failed"),
            Self::Randomness => f.write_str("Windows secure random-number generation failed"),
            Self::VerificationFailed(path) => write!(
                f,
                "read-back verification failed for temporary output: {}",
                path.display()
            ),
            Self::PublishedButSourceRetained { output, source } => write!(
                f,
                "output was published as {}, but its final durability flush failed ({source}); the original source was retained",
                output.display()
            ),
            Self::CommittedButSourceRetained {
                input,
                output,
                source,
            } => write!(
                f,
                "output was safely committed to {}, but the original {} was retained because it could not be removed ({source})",
                output.display(),
                input.display()
            ),
            Self::CommittedSourceRemovalUnconfirmed {
                input,
                output,
                source,
            } => write!(
                f,
                "output was safely committed to {}, but removal of the original {} could not be confirmed ({source}); inspect the original path before retrying",
                output.display(),
                input.display()
            ),
        }
    }
}

impl StdError for EzError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Io { source, .. }
            | Self::CommittedButSourceRetained { source, .. }
            | Self::CommittedSourceRemovalUnconfirmed { source, .. }
            | Self::PublishedButSourceRetained { source, .. }
            | Self::PasswordPrompt(source) => Some(source),
            Self::InvalidFormat(source) => Some(source),
            _ => None,
        }
    }
}

impl From<FormatError> for EzError {
    fn from(value: FormatError) -> Self {
        Self::InvalidFormat(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FormatError {
    TruncatedHeader,
    BadMagic,
    UnsupportedVersion,
    BadHeaderLength,
    UnsupportedFlags,
    ReservedBytes,
    InvalidChunkSize,
    InvalidKdfParameters,
    InvalidSalt,
    InvalidNonce,
    SizeOverflow,
    LengthMismatch,
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::TruncatedHeader => "header is truncated",
            Self::BadMagic => "magic bytes do not match",
            Self::UnsupportedVersion => "format version is not supported",
            Self::BadHeaderLength => "header length is invalid",
            Self::UnsupportedFlags => "unsupported format flags are set",
            Self::ReservedBytes => "reserved header bytes are nonzero",
            Self::InvalidChunkSize => "chunk size is outside the supported range",
            Self::InvalidKdfParameters => "Argon2id parameters are outside safe limits",
            Self::InvalidSalt => "salt is invalid",
            Self::InvalidNonce => "nonce prefix is invalid",
            Self::SizeOverflow => "declared size cannot be represented safely",
            Self::LengthMismatch => "physical file length does not match its header",
        };
        f.write_str(message)
    }
}

impl StdError for FormatError {}
