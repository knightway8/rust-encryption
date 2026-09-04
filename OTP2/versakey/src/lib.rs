//! Deterministic key-file generation for the VersaKey CLI family.
//!
//! Each suite stretches a password into a 256-bit stream key, then expands it
//! incrementally so even the maximum output size uses bounded memory.

#[cfg(not(target_os = "linux"))]
compile_error!("VersaKey supports Linux only");

use aes::Aes256;
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20::ChaCha20;
use ctr::cipher::{KeyIvInit, StreamCipher};
use pbkdf2::{pbkdf2_hmac, sha2::Sha256};
use scrypt::{Params as ScryptParams, scrypt};
use std::error::Error;
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::mem::size_of;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tempfile::Builder;
use zeroize::Zeroizing;

pub mod cli;

/// Twenty decimal gigabytes, expressed only in bytes at the CLI.
pub const MAX_KEY_BYTES: u64 = 20_000_000_000;
pub const OUTPUT_FILENAME: &str = "key.key";

const STREAM_BUFFER_BYTES: usize = 1024 * 1024;
const OUTPUT_FILE_MODE: u32 = 0o600;
const AES_BLOCK_BYTES: u64 = 16;
const CHACHA_NONCE_BYTES: usize = 12;
const ARGON2_MEMORY_KIB: u32 = 64 * 1024;
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_LANES: u32 = 1;
const SCRYPT_LOG_N: u8 = 16;
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;
const PBKDF2_ITERATIONS: u32 = 600_000;
const DERIVED_KEY_BYTES: usize = 32;
const SALT_FORMAT_TAG: &[u8] = b"versakey/effective-salt/v1";
const PEPPERED_SALT_FORMAT_TAG: &[u8] = b"versakey/effective-salt-with-pepper/v1";
const BLAKE3_XOF_FORMAT_TAG: &[u8] = b"versakey/blake3-keyed-xof-stream/v1";

type Aes256Ctr = ctr::Ctr128BE<Aes256>;

/// Build-specific values that deliberately separate one compiled application
/// from another. Changing any field changes the generated key material.
///
/// Give each generator suite a distinct domain. The suite enum is not itself
/// folded into the KDF so the original suite can retain byte-for-byte
/// compatibility; the shipped binaries therefore use separate versioned
/// domains.
#[derive(Clone, Copy)]
pub struct GeneratorConfig<'a> {
    pub application_salt: &'a [u8],
    pub application_pepper: &'a [u8],
    pub domain: &'a [u8],
}

/// A complete, versioned password-KDF and stream-expansion construction.
///
/// The original Argon2idAes256Ctr suite remains the default used by
/// generate_key_file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GeneratorSuite {
    Argon2idAes256Ctr,
    ScryptAes256Ctr,
    Pbkdf2Sha256Aes256Ctr,
    Argon2idChaCha20,
    Argon2idBlake3Xof,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StreamGenerator {
    Aes256Ctr,
    ChaCha20,
    Blake3Xof,
}

impl GeneratorSuite {
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::Argon2idAes256Ctr => "Argon2id + AES-256-CTR",
            Self::ScryptAes256Ctr => "scrypt + AES-256-CTR",
            Self::Pbkdf2Sha256Aes256Ctr => "PBKDF2-HMAC-SHA-256 + AES-256-CTR",
            Self::Argon2idChaCha20 => "Argon2id + ChaCha20",
            Self::Argon2idBlake3Xof => "Argon2id + keyed BLAKE3 XOF",
        }
    }

    fn stream_generator(self) -> StreamGenerator {
        match self {
            Self::Argon2idAes256Ctr | Self::ScryptAes256Ctr | Self::Pbkdf2Sha256Aes256Ctr => {
                StreamGenerator::Aes256Ctr
            }
            Self::Argon2idChaCha20 => StreamGenerator::ChaCha20,
            Self::Argon2idBlake3Xof => StreamGenerator::Blake3Xof,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SizeError {
    Empty,
    NotDecimal,
    OutOfRange,
}

impl Error for SizeError {}

// Size errors are safe to display to CLI users.

impl fmt::Display for SizeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(formatter, "key size cannot be empty"),
            Self::NotDecimal => write!(
                formatter,
                "key size must contain decimal digits only (bytes, with no unit suffix)"
            ),
            Self::OutOfRange => write!(
                formatter,
                "key size must be between 1 and {MAX_KEY_BYTES} bytes"
            ),
        }
    }
}

#[derive(Debug)]
pub enum GenerateError {
    InvalidSize(SizeError),
    InvalidConfiguration(&'static str),
    EmptyPassword,
    KeyDerivation(argon2::Error),
    ScryptParameters(scrypt::errors::InvalidParams),
    ScryptKeyDerivation(scrypt::errors::InvalidOutputLen),
    CounterExhausted,
    Io(io::Error),
    ReplacementOutcomeUncertain {
        error: io::Error,
        recovery_path: PathBuf,
    },
    CommittedButDirectorySyncFailed(io::Error),
}

impl fmt::Display for GenerateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSize(error) => error.fmt(formatter),
            Self::InvalidConfiguration(message) => {
                write!(formatter, "invalid generator configuration: {message}")
            }
            Self::EmptyPassword => write!(formatter, "password cannot be empty"),
            Self::KeyDerivation(_) | Self::ScryptParameters(_) | Self::ScryptKeyDerivation(_) => {
                write!(formatter, "password key derivation failed")
            }
            Self::CounterExhausted => {
                write!(formatter, "stream cipher counter capacity was exhausted")
            }
            Self::Io(error) => write!(formatter, "file operation failed: {error}"),
            Self::ReplacementOutcomeUncertain {
                error,
                recovery_path,
            } => write!(
                formatter,
                "could not confirm whether key.key was replaced: {error}; inspect key.key and retained recovery path {} before retrying",
                recovery_path.display()
            ),
            Self::CommittedButDirectorySyncFailed(error) => write!(
                formatter,
                "key.key was replaced, but synchronizing its directory failed: {error}"
            ),
        }
    }
}

impl Error for GenerateError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidSize(error) => Some(error),
            Self::KeyDerivation(_) | Self::ScryptParameters(_) | Self::ScryptKeyDerivation(_) => {
                None
            }
            Self::Io(error) => Some(error),
            Self::ReplacementOutcomeUncertain { error, .. } => Some(error),
            Self::CommittedButDirectorySyncFailed(error) => Some(error),
            Self::InvalidConfiguration(_) | Self::EmptyPassword | Self::CounterExhausted => None,
        }
    }
}

impl From<SizeError> for GenerateError {
    fn from(error: SizeError) -> Self {
        Self::InvalidSize(error)
    }
}

impl From<io::Error> for GenerateError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Parse a decimal byte count. Surrounding console whitespace is ignored, but
/// signs, separators, fractions, exponents, and unit suffixes are rejected.
pub fn parse_size(input: &str) -> Result<u64, SizeError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(SizeError::Empty);
    }
    if !trimmed.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(SizeError::NotDecimal);
    }

    let size = trimmed.parse::<u64>().map_err(|_| SizeError::OutOfRange)?;
    validate_size(size)?;
    Ok(size)
}

pub fn validate_size(size: u64) -> Result<(), SizeError> {
    if (1..=MAX_KEY_BYTES).contains(&size) {
        Ok(())
    } else {
        Err(SizeError::OutOfRange)
    }
}

/// Generate `key.key` in `directory`, replacing an existing file only after a
/// complete temporary file has been flushed and synchronized.
pub fn generate_key_file(
    directory: &Path,
    password: Zeroizing<String>,
    size: u64,
    config: GeneratorConfig<'_>,
) -> Result<PathBuf, GenerateError> {
    generate_key_file_with_suite(
        directory,
        password,
        size,
        config,
        GeneratorSuite::Argon2idAes256Ctr,
    )
}

/// Generate key.key with an explicitly selected construction.
///
/// Each suite is deterministic for the password, size, configuration, suite,
/// and pinned algorithm parameters. Suites are intentionally not
/// interchangeable. Callers must use a distinct configuration domain for each
/// suite, as the supplied binaries do.
pub fn generate_key_file_with_suite(
    directory: &Path,
    password: Zeroizing<String>,
    size: u64,
    config: GeneratorConfig<'_>,
    suite: GeneratorSuite,
) -> Result<PathBuf, GenerateError> {
    validate_size(size)?;
    validate_config(config)?;
    let stream_key = derive_production_stream_key(password.as_str(), size, config, suite)?;

    // The potentially long file write no longer needs either password copy.
    drop(password);
    write_key_file_from_stream_key(directory, size, &stream_key, suite.stream_generator())
}

#[cfg(test)]
fn generate_key_file_with_params(
    directory: &Path,
    password: &str,
    size: u64,
    config: GeneratorConfig<'_>,
    params: Params,
) -> Result<PathBuf, GenerateError> {
    validate_size(size)?;
    validate_config(config)?;
    let stream_key = derive_stream_key_with_params(password, size, config, params)?;
    write_key_file_from_stream_key(directory, size, &stream_key, StreamGenerator::Aes256Ctr)
}

fn write_key_file_from_stream_key(
    directory: &Path,
    size: u64,
    stream_key: &[u8; DERIVED_KEY_BYTES],
    stream_generator: StreamGenerator,
) -> Result<PathBuf, GenerateError> {
    let output_path = directory.join(OUTPUT_FILENAME);

    write_atomically(directory, &output_path, |file| {
        write_stream_with_generator(
            file,
            stream_key,
            size,
            STREAM_BUFFER_BYTES,
            stream_generator,
        )
    })?;
    Ok(output_path)
}

fn validate_config(config: GeneratorConfig<'_>) -> Result<(), GenerateError> {
    if config.application_salt.is_empty() {
        return Err(GenerateError::InvalidConfiguration(
            "application salt cannot be empty",
        ));
    }
    if config.application_pepper.is_empty() {
        return Err(GenerateError::InvalidConfiguration(
            "application pepper cannot be empty",
        ));
    }
    if config.domain.is_empty() {
        return Err(GenerateError::InvalidConfiguration(
            "domain cannot be empty",
        ));
    }
    Ok(())
}

fn production_params() -> Result<Params, GenerateError> {
    Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_LANES,
        Some(DERIVED_KEY_BYTES),
    )
    .map_err(GenerateError::KeyDerivation)
}

fn production_scrypt_params() -> Result<ScryptParams, GenerateError> {
    ScryptParams::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P).map_err(GenerateError::ScryptParameters)
}

fn derive_production_stream_key(
    password: &str,
    size: u64,
    config: GeneratorConfig<'_>,
    suite: GeneratorSuite,
) -> Result<Zeroizing<[u8; DERIVED_KEY_BYTES]>, GenerateError> {
    match suite {
        GeneratorSuite::Argon2idAes256Ctr
        | GeneratorSuite::Argon2idChaCha20
        | GeneratorSuite::Argon2idBlake3Xof => {
            derive_stream_key_with_params(password, size, config, production_params()?)
        }
        GeneratorSuite::ScryptAes256Ctr => derive_scrypt_stream_key_with_params(
            password,
            size,
            config,
            production_scrypt_params()?,
        ),
        GeneratorSuite::Pbkdf2Sha256Aes256Ctr => {
            derive_pbkdf2_stream_key_with_rounds(password, size, config, PBKDF2_ITERATIONS)
        }
    }
}

fn derive_stream_key_with_params(
    password: &str,
    size: u64,
    config: GeneratorConfig<'_>,
    params: Params,
) -> Result<Zeroizing<[u8; DERIVED_KEY_BYTES]>, GenerateError> {
    validate_size(size)?;
    validate_config(config)?;
    if password.is_empty() {
        return Err(GenerateError::EmptyPassword);
    }

    let effective_salt = build_effective_salt(config, size)?;
    derive_argon2_key_with_effective_salt(password, config, params, effective_salt)
}

fn derive_argon2_key_with_effective_salt(
    password: &str,
    config: GeneratorConfig<'_>,
    params: Params,
    effective_salt: Vec<u8>,
) -> Result<Zeroizing<[u8; DERIVED_KEY_BYTES]>, GenerateError> {
    let effective_salt = Zeroizing::new(effective_salt);
    let memory_block_count = params.block_count();
    let argon2 = Argon2::new_with_secret(
        config.application_pepper,
        Algorithm::Argon2id,
        Version::V0x13,
        params,
    )
    .map_err(GenerateError::KeyDerivation)?;

    let mut key = Zeroizing::new([0_u8; DERIVED_KEY_BYTES]);
    let mut memory = Zeroizing::new(vec![argon2::Block::default(); memory_block_count]);
    argon2
        .hash_password_into_with_memory(
            password.as_bytes(),
            &effective_salt,
            key.as_mut(),
            memory.as_mut_slice(),
        )
        .map_err(GenerateError::KeyDerivation)?;
    Ok(key)
}

fn derive_scrypt_stream_key_with_params(
    password: &str,
    size: u64,
    config: GeneratorConfig<'_>,
    params: ScryptParams,
) -> Result<Zeroizing<[u8; DERIVED_KEY_BYTES]>, GenerateError> {
    validate_size(size)?;
    validate_config(config)?;
    if password.is_empty() {
        return Err(GenerateError::EmptyPassword);
    }

    let effective_salt = Zeroizing::new(build_peppered_effective_salt(config, size)?);
    let mut key = Zeroizing::new([0_u8; DERIVED_KEY_BYTES]);
    scrypt(password.as_bytes(), &effective_salt, &params, key.as_mut())
        .map_err(GenerateError::ScryptKeyDerivation)?;
    Ok(key)
}

fn derive_pbkdf2_stream_key_with_rounds(
    password: &str,
    size: u64,
    config: GeneratorConfig<'_>,
    rounds: u32,
) -> Result<Zeroizing<[u8; DERIVED_KEY_BYTES]>, GenerateError> {
    validate_size(size)?;
    validate_config(config)?;
    if password.is_empty() {
        return Err(GenerateError::EmptyPassword);
    }
    if rounds == 0 {
        return Err(GenerateError::InvalidConfiguration(
            "PBKDF2 iteration count cannot be zero",
        ));
    }

    let effective_salt = Zeroizing::new(build_peppered_effective_salt(config, size)?);
    let mut key = Zeroizing::new([0_u8; DERIVED_KEY_BYTES]);
    pbkdf2_hmac::<Sha256>(password.as_bytes(), &effective_salt, rounds, key.as_mut());
    Ok(key)
}

fn build_effective_salt(config: GeneratorConfig<'_>, size: u64) -> Result<Vec<u8>, GenerateError> {
    let fields = [SALT_FORMAT_TAG, config.domain, config.application_salt];
    let mut salt = allocate_framed_salt(&fields, size.to_be_bytes().len())?;
    append_length_prefixed(&mut salt, SALT_FORMAT_TAG)?;
    append_length_prefixed(&mut salt, config.domain)?;
    append_length_prefixed(&mut salt, config.application_salt)?;
    salt.extend_from_slice(&size.to_be_bytes());
    Ok(salt)
}

fn build_peppered_effective_salt(
    config: GeneratorConfig<'_>,
    size: u64,
) -> Result<Vec<u8>, GenerateError> {
    let fields = [
        PEPPERED_SALT_FORMAT_TAG,
        config.domain,
        config.application_salt,
        config.application_pepper,
    ];
    let mut salt = allocate_framed_salt(&fields, size.to_be_bytes().len())?;
    for field in fields {
        append_length_prefixed(&mut salt, field)?;
    }
    salt.extend_from_slice(&size.to_be_bytes());
    Ok(salt)
}

fn allocate_framed_salt(fields: &[&[u8]], trailing_bytes: usize) -> Result<Vec<u8>, GenerateError> {
    let capacity = fields
        .iter()
        .try_fold(trailing_bytes, |total, field| {
            total
                .checked_add(size_of::<u64>())
                .and_then(|total| total.checked_add(field.len()))
        })
        .ok_or(GenerateError::InvalidConfiguration(
            "configuration values are too large",
        ))?;
    let mut salt = Vec::new();
    salt.try_reserve_exact(capacity)
        .map_err(|_| GenerateError::InvalidConfiguration("configuration values are too large"))?;
    Ok(salt)
}

fn append_length_prefixed(target: &mut Vec<u8>, value: &[u8]) -> Result<(), GenerateError> {
    let length = u64::try_from(value.len())
        .map_err(|_| GenerateError::InvalidConfiguration("configuration value is too large"))?;
    target.extend_from_slice(&length.to_be_bytes());
    target.extend_from_slice(value);
    Ok(())
}

fn write_stream_with_buffer<W: Write>(
    writer: &mut W,
    key: &[u8; DERIVED_KEY_BYTES],
    size: u64,
    buffer_size: usize,
) -> Result<(), GenerateError> {
    let iv = [0_u8; AES_BLOCK_BYTES as usize];
    let cipher = Aes256Ctr::new(key.into(), &iv.into());
    write_cipher_stream_with_buffer(writer, cipher, size, buffer_size)
}

fn write_stream_with_generator<W: Write>(
    writer: &mut W,
    key: &[u8; DERIVED_KEY_BYTES],
    size: u64,
    buffer_size: usize,
    stream_generator: StreamGenerator,
) -> Result<(), GenerateError> {
    match stream_generator {
        StreamGenerator::Aes256Ctr => write_stream_with_buffer(writer, key, size, buffer_size),
        StreamGenerator::ChaCha20 => {
            write_chacha20_stream_with_buffer(writer, key, size, buffer_size)
        }
        StreamGenerator::Blake3Xof => write_blake3_xof_with_buffer(writer, key, size, buffer_size),
    }
}

fn write_chacha20_stream_with_buffer<W: Write>(
    writer: &mut W,
    key: &[u8; DERIVED_KEY_BYTES],
    size: u64,
    buffer_size: usize,
) -> Result<(), GenerateError> {
    let nonce = [0_u8; CHACHA_NONCE_BYTES];
    let cipher = ChaCha20::new(key.into(), &nonce.into());
    write_cipher_stream_with_buffer(writer, cipher, size, buffer_size)
}

fn write_cipher_stream_with_buffer<W, C>(
    writer: &mut W,
    mut cipher: C,
    size: u64,
    buffer_size: usize,
) -> Result<(), GenerateError>
where
    W: Write,
    C: StreamCipher,
{
    validate_size(size)?;
    if buffer_size == 0 {
        return Err(GenerateError::InvalidConfiguration(
            "stream buffer size cannot be zero",
        ));
    }

    let allocation = usize::try_from(size.min(buffer_size as u64))
        .expect("the selected buffer length always fits usize");
    let mut buffer = Zeroizing::new(vec![0_u8; allocation]);
    let mut remaining = size;

    while remaining != 0 {
        let count = usize::try_from(remaining.min(buffer.len() as u64))
            .expect("the selected chunk length always fits usize");
        buffer[..count].fill(0);
        cipher
            .try_apply_keystream(&mut buffer[..count])
            .map_err(|_| GenerateError::CounterExhausted)?;
        writer.write_all(&buffer[..count])?;
        remaining -= count as u64;
    }
    Ok(())
}

fn write_blake3_xof_with_buffer<W: Write>(
    writer: &mut W,
    key: &[u8; DERIVED_KEY_BYTES],
    size: u64,
    buffer_size: usize,
) -> Result<(), GenerateError> {
    validate_size(size)?;
    if buffer_size == 0 {
        return Err(GenerateError::InvalidConfiguration(
            "stream buffer size cannot be zero",
        ));
    }

    let allocation = usize::try_from(size.min(buffer_size as u64))
        .expect("the selected buffer length always fits usize");
    let mut buffer = Zeroizing::new(vec![0_u8; allocation]);
    let mut hasher = Zeroizing::new(blake3::Hasher::new_keyed(key));
    hasher.update(BLAKE3_XOF_FORMAT_TAG);
    let mut output_reader = Zeroizing::new(hasher.finalize_xof());
    drop(hasher);
    let mut remaining = size;

    while remaining != 0 {
        let count = usize::try_from(remaining.min(buffer.len() as u64))
            .expect("the selected chunk length always fits usize");
        output_reader.fill(&mut buffer[..count]);
        writer.write_all(&buffer[..count])?;
        remaining -= count as u64;
    }
    Ok(())
}

fn write_atomically<F>(directory: &Path, output_path: &Path, write: F) -> Result<(), GenerateError>
where
    F: FnOnce(&mut fs::File) -> Result<(), GenerateError>,
{
    let mut temporary = Builder::new()
        .prefix(".key.key.")
        .permissions(fs::Permissions::from_mode(OUTPUT_FILE_MODE))
        .tempfile_in(directory)?;

    // Linux applies the process umask to the creation mode. Restore the exact
    // owner-only contract while the temporary file is still empty; a chmod
    // failure drops the temporary file without touching the destination.
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(OUTPUT_FILE_MODE))?;

    write(temporary.as_file_mut())?;
    temporary.as_file_mut().flush()?;
    temporary.as_file().sync_all()?;

    if let Err(mut persist_error) = temporary.persist(output_path) {
        // A remote/userspace filesystem can apply a rename yet return an
        // error. Never let TempPath's pathname-based Drop cleanup unlink
        // either recovery data or a new file created at the old path.
        persist_error.file.disable_cleanup(true);
        let recovery_path = persist_error.file.path().to_path_buf();
        return Err(GenerateError::ReplacementOutcomeUncertain {
            error: persist_error.error,
            recovery_path,
        });
    }
    sync_directory(directory).map_err(GenerateError::CommittedButDirectorySyncFailed)?;
    Ok(())
}

fn sync_directory(directory: &Path) -> io::Result<()> {
    fs::File::open(directory)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests;
