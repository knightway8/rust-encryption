use std::{io, path::PathBuf};

use thiserror::Error;

/// Every failure the `secure` library can report.
#[derive(Debug, Error)]
pub enum Error {
    #[error("expected exactly an uppercase operation (E or D), an input file, and an output file")]
    InvalidArguments,

    #[error("operation must be uppercase E (encrypt) or D (decrypt)")]
    InvalidOperation,

    #[error("cannot disable process dumps before reading the password: {0}")]
    ProcessHardening(#[source] io::Error),

    #[error("cannot install safe termination-signal handlers: {0}")]
    SignalHandler(#[source] io::Error),

    #[error("operation interrupted; the output was not created")]
    Interrupted,

    #[error("could not read the password from the terminal: {0}")]
    PasswordInput(#[source] io::Error),

    #[error("passwords do not match")]
    PasswordMismatch,

    #[error("new passwords must contain at least {minimum} characters")]
    PasswordTooShort { minimum: usize },

    #[error("password is too long (maximum {maximum} bytes)")]
    PasswordTooLong { maximum: usize },

    #[error("cannot open input {path:?}: {source}")]
    OpenInput {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error(
        "input must be a regular file (symlinks, directories, devices, sockets, and FIFOs are refused): {0:?}"
    )]
    InputNotRegular(PathBuf),

    #[error("invalid output path: {0:?}")]
    InvalidOutputPath(PathBuf),

    #[error("cannot open output directory {path:?}: {source}")]
    OpenOutputDirectory {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("refusing to overwrite existing output {0:?}")]
    OutputExists(PathBuf),

    #[error("cannot create a private temporary output beside {path:?}: {source}")]
    CreateTemporaryOutput {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("encryption failed; the output was not created: {0}")]
    EncryptionIo(#[source] io::Error),

    #[error("encryption setup failed; the output was not created")]
    EncryptionFailed,

    #[error(
        "decryption failed (wrong password, damaged data, unsupported input, or I/O failure); the output was not created"
    )]
    DecryptionFailed,

    #[error("input changed while it was being encrypted; the output was discarded: {0:?}")]
    InputChanged(PathBuf),

    #[error("cannot durably publish output {path:?}: {source}")]
    PublishOutput {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error(
        "output {path:?} is complete, but syncing its directory failed; crash durability is uncertain: {source}"
    )]
    DirectorySyncAfterPublish {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}
