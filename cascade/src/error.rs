use std::{ffi::OsString, path::PathBuf};

use thiserror::Error;

/// Operational and cryptographic failures surfaced by the application.
#[derive(Debug, Error)]
pub enum AppError {
    #[error("could not locate the executable: {0}")]
    Executable(#[source] std::io::Error),

    #[error("the executable path has no parent directory")]
    ExecutableDirectory,

    #[error("could not open {path:?}: {source}")]
    Open {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("could not read {path:?}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("could not inspect {path:?}: {source}")]
    Metadata {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("{0:?} is not a regular file")]
    NotRegularFile(PathBuf),

    #[error("{0:?} is not a directory")]
    NotDirectory(PathBuf),

    #[error("{0:?} changed while it was being opened")]
    FileChangedDuringOpen(PathBuf),

    #[error("refusing symbolic-link key file {0:?}")]
    SymlinkKey(PathBuf),

    #[error("refusing symbolic-link input file {0:?}")]
    SymlinkInput(PathBuf),

    #[error("key file {path:?} must be exactly {expected} bytes (found {actual})")]
    KeyLength {
        path: PathBuf,
        expected: usize,
        actual: u64,
    },

    #[cfg(unix)]
    #[error(
        "key file {path:?} is accessible by group or other users (mode {mode:04o}); restrict it to mode 600"
    )]
    InsecureKeyPermissions { path: PathBuf, mode: u32 },

    #[cfg(unix)]
    #[error("key directory {path:?} is writable by group or other users (mode {mode:04o})")]
    InsecureKeyDirectory { path: PathBuf, mode: u32 },

    #[cfg(unix)]
    #[error("key directory {path:?} is owned by uid {actual}, but the effective uid is {expected}")]
    WrongKeyDirectoryOwner {
        path: PathBuf,
        expected: u32,
        actual: u32,
    },

    #[cfg(unix)]
    #[error("key file {path:?} is owned by uid {actual}, but the effective uid is {expected}")]
    WrongKeyOwner {
        path: PathBuf,
        expected: u32,
        actual: u32,
    },

    #[cfg(unix)]
    #[error("output directory {path:?} is writable by group or other users (mode {mode:04o})")]
    InsecureOutputDirectory { path: PathBuf, mode: u32 },

    #[cfg(unix)]
    #[error(
        "output directory {path:?} is owned by uid {actual}, but the effective uid is {expected}"
    )]
    WrongOutputDirectoryOwner {
        path: PathBuf,
        expected: u32,
        actual: u32,
    },

    #[error(
        "secure key and output permissions are not implemented on this platform; file operations are supported only on Unix"
    )]
    UnsupportedPlatform,

    #[error("key generation refused because {0:?} already exists")]
    KeyExists(PathBuf),

    #[error("secure random number generation failed")]
    Random,

    #[error("input is too large for this in-memory build")]
    InputTooLarge,

    #[error("not enough memory to process the input")]
    Allocation,

    #[error("invalid encrypted file")]
    InvalidFormat,

    #[error("unsupported encrypted-file version {0}")]
    UnsupportedVersion(u8),

    #[error("selected {selected}, but the encrypted file contains {actual}")]
    AlgorithmMismatch {
        selected: &'static str,
        actual: &'static str,
    },

    #[error("decryption failed: wrong key or corrupted ciphertext")]
    DecryptionFailed,

    #[error("encryption failed")]
    EncryptionFailed,

    #[error("output file already exists: {0:?}")]
    OutputExists(PathBuf),

    #[error("invalid output path {0:?}")]
    InvalidOutputPath(PathBuf),

    #[error("could not create output in {path:?}: {source}")]
    CreateOutput {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("could not write output {path:?}: {source}")]
    WriteOutput {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("could not commit output {path:?}: {source}")]
    CommitOutput {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error(
        "output operation for {path:?} failed ({primary}); additionally, temporary entry {temporary_name:?} remains in the bound directory because cleanup failed: {cleanup_source}"
    )]
    OutputTemporaryCleanupFailed {
        path: PathBuf,
        temporary_name: OsString,
        primary: String,
        #[source]
        cleanup_source: std::io::Error,
    },

    #[error(
        "output {path:?} was installed in its bound directory, but temporary entry {temporary_name:?} in that directory could not be removed; directory sync was not attempted: {source}"
    )]
    OutputInstalledButTemporaryRemains {
        path: PathBuf,
        temporary_name: OsString,
        #[source]
        source: std::io::Error,
    },

    #[error(
        "output {path:?} was installed, but its directory could not be synced; verify the output before retrying: {source}"
    )]
    OutputInstalledButNotSynced {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("could not generate keys in {path:?}: {source}")]
    KeyGeneration {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error(
        "key operation in {path:?} failed ({primary}); additionally, temporary entry {temporary_name:?} remains in the bound directory because cleanup failed: {cleanup_source}"
    )]
    KeyTemporaryCleanupFailed {
        path: PathBuf,
        temporary_name: OsString,
        primary: String,
        #[source]
        cleanup_source: std::io::Error,
    },

    #[error(
        "key {path:?} was installed in its bound directory, but temporary entry {temporary_name:?} in that directory could not be removed; the key set may be partial: {source}"
    )]
    KeyInstalledButTemporaryRemains {
        path: PathBuf,
        temporary_name: OsString,
        #[source]
        source: std::io::Error,
    },

    #[error(
        "key generation failed and rollback in {path:?} could not be completed or durably synced; inspect the key set before retrying: {source}"
    )]
    KeyRollbackIncomplete {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error(
        "all key files were installed in {path:?}, but the directory could not be synced; verify the keys before retrying: {source}"
    )]
    KeysInstalledButNotSynced {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}
