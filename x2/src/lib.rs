#![forbid(unsafe_code)]

use aes_gcm_siv::{
    Aes256GcmSiv, Nonce as AesNonce, Tag as AesTag,
    aead::{AeadInOut, KeyInit},
};
use argon2::{Algorithm as ArgonAlgorithm, Argon2, Block, Params, Version};
use chacha20poly1305::{Tag as XChaTag, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;
use std::{
    error::Error as StdError,
    ffi::{OsStr, OsString},
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};
use tempfile::{NamedTempFile, TempPath};
use zeroize::Zeroizing;

pub const HELP: &str = "x2 - authenticated file encryption\n\nUSAGE:\n    x2 E AES  <INPUT> <OUTPUT>\n    x2 E XCHA <INPUT> <OUTPUT>\n    x2 D AES  <INPUT> <OUTPUT>\n    x2 D XCHA <INPUT> <OUTPUT>\n\nE encrypts and prompts for the password twice.\nD decrypts and prompts once. Existing output files are never overwritten.\n";

const MAGIC: [u8; 8] = *b"X2ENC\r\n\x1a";
const FORMAT_VERSION: u16 = 1;
const HEADER_LEN: usize = 80;
const HEADER_LEN_U16: u16 = 80;
const KDF_ARGON2ID: u8 = 1;
const ARGON2_VERSION_13: u8 = 0x13;
const SALT_LEN: usize = 16;
const NONCE_STORAGE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const RECORD_PREFIX_LEN: usize = 8;
const RECORD_DATA: u8 = 0;
const RECORD_FINAL: u8 = 1;
const RECORD_DOMAIN: [u8; 15] = *b"X2ENC RECORD V1";
const AAD_LEN: usize = RECORD_DOMAIN.len() + HEADER_LEN + 8 + RECORD_PREFIX_LEN;
const MIN_CONTAINER_LEN: u64 = (HEADER_LEN + RECORD_PREFIX_LEN + TAG_LEN) as u64;
const MAX_RECORDS: u64 = u32::MAX as u64;
const KEY_DOMAIN: &[u8] = b"X2ENC AEAD KEY V1";
const TEMP_RANDOM_BYTES: usize = 16;
const TEMP_CREATE_ATTEMPTS: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    Encrypt,
    Decrypt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncryptionAlgorithm {
    Aes256GcmSiv,
    XChaCha20Poly1305,
}

impl EncryptionAlgorithm {
    const fn id(self) -> u8 {
        match self {
            Self::Aes256GcmSiv => 1,
            Self::XChaCha20Poly1305 => 2,
        }
    }

    fn from_id(id: u8) -> Result<Self, CryptoError> {
        match id {
            1 => Ok(Self::Aes256GcmSiv),
            2 => Ok(Self::XChaCha20Poly1305),
            _ => Err(CryptoError::InvalidFormat("unknown encryption algorithm")),
        }
    }
}

impl fmt::Display for EncryptionAlgorithm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Aes256GcmSiv => formatter.write_str("AES"),
            Self::XChaCha20Poly1305 => formatter.write_str("XCHA"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Command {
    pub operation: Operation,
    pub algorithm: EncryptionAlgorithm,
    pub input: PathBuf,
    pub output: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParsedCommand {
    Run(Command),
    Help,
    Version,
}

/// An input file opened and validated before an interactive password prompt.
///
/// Keeping this handle prevents a pathname swap while the user is typing. The
/// operation consumes the value, so it cannot accidentally reuse a file cursor.
pub struct PreparedFileOperation {
    operation: Operation,
    algorithm: EncryptionAlgorithm,
    input: File,
    input_len: u64,
    output_path: PathBuf,
    output_parent: PathBuf,
    profile: Profile,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UsageError(&'static str);

impl fmt::Display for UsageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl StdError for UsageError {}

pub fn parse_cli_args<I, S>(args: I) -> Result<ParsedCommand, UsageError>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let mut iterator = args.into_iter().map(Into::into);
    let mut args = Vec::with_capacity(5);
    for _ in 0..5 {
        let Some(argument) = iterator.next() else {
            break;
        };
        args.push(argument);
    }

    if args.len() == 1 {
        if args[0] == OsStr::new("-h") || args[0] == OsStr::new("--help") {
            return Ok(ParsedCommand::Help);
        }
        if args[0] == OsStr::new("-V") || args[0] == OsStr::new("--version") {
            return Ok(ParsedCommand::Version);
        }
    }

    if args.len() != 4 {
        return Err(UsageError("expected: x2 <E|D> <AES|XCHA> <INPUT> <OUTPUT>"));
    }

    let operation = match args[0].as_os_str() {
        value if value == OsStr::new("E") => Operation::Encrypt,
        value if value == OsStr::new("D") => Operation::Decrypt,
        _ => return Err(UsageError("operation must be E or D")),
    };
    let algorithm = match args[1].as_os_str() {
        value if value == OsStr::new("AES") => EncryptionAlgorithm::Aes256GcmSiv,
        value if value == OsStr::new("XCHA") => EncryptionAlgorithm::XChaCha20Poly1305,
        _ => return Err(UsageError("algorithm must be AES or XCHA")),
    };

    Ok(ParsedCommand::Run(Command {
        operation,
        algorithm,
        input: PathBuf::from(&args[2]),
        output: PathBuf::from(&args[3]),
    }))
}

#[derive(Debug)]
pub enum CryptoError {
    AuthenticationFailed,
    EmptyPassword,
    AlgorithmMismatch {
        expected: EncryptionAlgorithm,
        found: EncryptionAlgorithm,
    },
    InvalidFormat(&'static str),
    InputChanged,
    InputNotRegular(PathBuf),
    InvalidOutputParent(PathBuf),
    InvalidOutputPath(PathBuf),
    OutputExists(PathBuf),
    FileTooLarge,
    ResourceLimit,
    EntropyFailure,
    TemporaryNameExhausted(PathBuf),
    KeyDerivationFailed,
    CryptographicFailure,
    PathIo {
        context: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    StreamIo {
        context: &'static str,
        source: io::Error,
    },
    CleanupFailed {
        temporary_path: PathBuf,
        operation: Box<CryptoError>,
        source: io::Error,
    },
}

impl fmt::Display for CryptoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthenticationFailed => formatter.write_str(
                "authentication failed: the password is wrong or the input is corrupted",
            ),
            Self::EmptyPassword => formatter.write_str("password must not be empty"),
            Self::AlgorithmMismatch { expected, found } => write!(
                formatter,
                "algorithm mismatch: command selected {expected}, encrypted file uses {found}"
            ),
            Self::InvalidFormat(reason) => write!(formatter, "invalid encrypted file: {reason}"),
            Self::InputChanged => {
                formatter.write_str("input file changed size while it was being encrypted")
            }
            Self::InputNotRegular(path) => {
                write!(formatter, "input is not a regular file: {path:?}")
            }
            Self::InvalidOutputParent(path) => {
                write!(formatter, "output parent is not a directory: {path:?}")
            }
            Self::InvalidOutputPath(path) => write!(
                formatter,
                "output must name a file without a trailing separator: {path:?}"
            ),
            Self::OutputExists(path) => {
                write!(formatter, "refusing to overwrite existing output: {path:?}")
            }
            Self::FileTooLarge => formatter.write_str("file is too large for the v1 format"),
            Self::ResourceLimit => {
                formatter.write_str("unable to allocate bounded cryptographic memory")
            }
            Self::EntropyFailure => {
                formatter.write_str("operating-system random number generation failed")
            }
            Self::TemporaryNameExhausted(path) => write!(
                formatter,
                "cannot create a unique temporary output name for {path:?}"
            ),
            Self::KeyDerivationFailed => formatter.write_str("Argon2id key derivation failed"),
            Self::CryptographicFailure => formatter.write_str("encryption operation failed"),
            Self::PathIo {
                context,
                path,
                source,
            } => write!(formatter, "{context} {path:?}: {source}"),
            Self::StreamIo { context, source } => write!(formatter, "{context}: {source}"),
            Self::CleanupFailed {
                temporary_path,
                operation,
                source,
            } => write!(
                formatter,
                "{operation}; additionally cannot remove sensitive temporary file \
                 {temporary_path:?}: {source}"
            ),
        }
    }
}

impl StdError for CryptoError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::PathIo { source, .. }
            | Self::StreamIo { source, .. }
            | Self::CleanupFailed { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Profile {
    chunk_size: u32,
    memory_kib: u32,
    passes: u32,
    lanes: u32,
}

const PRODUCTION_PROFILE: Profile = Profile {
    chunk_size: 1_048_576,
    memory_kib: 65_536,
    passes: 3,
    lanes: 4,
};

#[derive(Clone)]
struct Header {
    raw: [u8; HEADER_LEN],
    algorithm: EncryptionAlgorithm,
    plaintext_len: u64,
    salt: [u8; SALT_LEN],
    base_nonce: [u8; NONCE_STORAGE_LEN],
    profile: Profile,
}

impl Header {
    fn generate(
        algorithm: EncryptionAlgorithm,
        plaintext_len: u64,
        profile: Profile,
    ) -> Result<Self, CryptoError> {
        validate_profile(profile)?;
        validate_plaintext_len(plaintext_len, profile.chunk_size)?;

        let mut salt = [0_u8; SALT_LEN];
        getrandom::fill(&mut salt).map_err(|_| CryptoError::EntropyFailure)?;

        let mut base_nonce = [0_u8; NONCE_STORAGE_LEN];
        let random_nonce_len = match algorithm {
            EncryptionAlgorithm::Aes256GcmSiv => 12,
            EncryptionAlgorithm::XChaCha20Poly1305 => 24,
        };
        getrandom::fill(&mut base_nonce[..random_nonce_len])
            .map_err(|_| CryptoError::EntropyFailure)?;

        Self::from_material(algorithm, plaintext_len, profile, salt, base_nonce)
    }

    fn from_material(
        algorithm: EncryptionAlgorithm,
        plaintext_len: u64,
        profile: Profile,
        salt: [u8; SALT_LEN],
        base_nonce: [u8; NONCE_STORAGE_LEN],
    ) -> Result<Self, CryptoError> {
        validate_profile(profile)?;
        validate_plaintext_len(plaintext_len, profile.chunk_size)?;
        if algorithm == EncryptionAlgorithm::Aes256GcmSiv
            && base_nonce[12..].iter().any(|byte| *byte != 0)
        {
            return Err(CryptoError::InvalidFormat("AES nonce padding must be zero"));
        }

        let mut header = Self {
            raw: [0_u8; HEADER_LEN],
            algorithm,
            plaintext_len,
            salt,
            base_nonce,
            profile,
        };
        header.raw = header.encode();
        Ok(header)
    }

    fn encode(&self) -> [u8; HEADER_LEN] {
        let mut raw = [0_u8; HEADER_LEN];
        raw[..8].copy_from_slice(&MAGIC);
        raw[8..10].copy_from_slice(&FORMAT_VERSION.to_be_bytes());
        raw[10..12].copy_from_slice(&HEADER_LEN_U16.to_be_bytes());
        raw[12] = self.algorithm.id();
        raw[13] = KDF_ARGON2ID;
        raw[14] = ARGON2_VERSION_13;
        raw[15] = 0;
        raw[16..20].copy_from_slice(&self.profile.chunk_size.to_be_bytes());
        raw[20..24].copy_from_slice(&self.profile.memory_kib.to_be_bytes());
        raw[24..28].copy_from_slice(&self.profile.passes.to_be_bytes());
        raw[28..32].copy_from_slice(&self.profile.lanes.to_be_bytes());
        raw[32..40].copy_from_slice(&self.plaintext_len.to_be_bytes());
        raw[40..56].copy_from_slice(&self.salt);
        raw[56..80].copy_from_slice(&self.base_nonce);
        raw
    }

    fn decode(raw: [u8; HEADER_LEN], allowed_profile: Profile) -> Result<Self, CryptoError> {
        if raw[..8] != MAGIC {
            return Err(CryptoError::InvalidFormat("bad magic"));
        }
        if u16::from_be_bytes([raw[8], raw[9]]) != FORMAT_VERSION {
            return Err(CryptoError::InvalidFormat("unsupported format version"));
        }
        if u16::from_be_bytes([raw[10], raw[11]]) != HEADER_LEN_U16 {
            return Err(CryptoError::InvalidFormat("unsupported header length"));
        }
        let algorithm = EncryptionAlgorithm::from_id(raw[12])?;
        if raw[13] != KDF_ARGON2ID {
            return Err(CryptoError::InvalidFormat(
                "unsupported key derivation function",
            ));
        }
        if raw[14] != ARGON2_VERSION_13 {
            return Err(CryptoError::InvalidFormat("unsupported Argon2 version"));
        }
        if raw[15] != 0 {
            return Err(CryptoError::InvalidFormat("unknown header flags"));
        }

        let profile = Profile {
            chunk_size: u32::from_be_bytes([raw[16], raw[17], raw[18], raw[19]]),
            memory_kib: u32::from_be_bytes([raw[20], raw[21], raw[22], raw[23]]),
            passes: u32::from_be_bytes([raw[24], raw[25], raw[26], raw[27]]),
            lanes: u32::from_be_bytes([raw[28], raw[29], raw[30], raw[31]]),
        };
        if profile != allowed_profile {
            return Err(CryptoError::InvalidFormat("unsupported encryption profile"));
        }
        validate_profile(profile)?;

        let plaintext_len = u64::from_be_bytes([
            raw[32], raw[33], raw[34], raw[35], raw[36], raw[37], raw[38], raw[39],
        ]);
        validate_plaintext_len(plaintext_len, profile.chunk_size)?;

        let mut salt = [0_u8; SALT_LEN];
        salt.copy_from_slice(&raw[40..56]);
        let mut base_nonce = [0_u8; NONCE_STORAGE_LEN];
        base_nonce.copy_from_slice(&raw[56..80]);
        if algorithm == EncryptionAlgorithm::Aes256GcmSiv
            && base_nonce[12..].iter().any(|byte| *byte != 0)
        {
            return Err(CryptoError::InvalidFormat("AES nonce padding must be zero"));
        }

        Ok(Self {
            raw,
            algorithm,
            plaintext_len,
            salt,
            base_nonce,
            profile,
        })
    }
}

fn validate_profile(profile: Profile) -> Result<(), CryptoError> {
    if profile.chunk_size == 0 || profile.chunk_size > 16 * 1_048_576 {
        return Err(CryptoError::InvalidFormat("invalid chunk size"));
    }
    Params::new(profile.memory_kib, profile.passes, profile.lanes, Some(32))
        .map(|_| ())
        .map_err(|_| CryptoError::InvalidFormat("invalid Argon2 parameters"))
}

fn validate_plaintext_len(plaintext_len: u64, chunk_size: u32) -> Result<(), CryptoError> {
    let data_records = data_record_count(plaintext_len, chunk_size)?;
    if data_records >= MAX_RECORDS {
        return Err(CryptoError::FileTooLarge);
    }
    Ok(())
}

const fn data_record_count(plaintext_len: u64, chunk_size: u32) -> Result<u64, CryptoError> {
    if chunk_size == 0 {
        return Err(CryptoError::InvalidFormat("invalid chunk size"));
    }
    if plaintext_len == 0 {
        Ok(0)
    } else {
        Ok(1 + (plaintext_len - 1) / chunk_size as u64)
    }
}

fn encrypted_container_len(plaintext_len: u64, chunk_size: u32) -> Result<u64, CryptoError> {
    validate_plaintext_len(plaintext_len, chunk_size)?;
    let records = data_record_count(plaintext_len, chunk_size)?
        .checked_add(1)
        .ok_or(CryptoError::FileTooLarge)?;
    let framing = records
        .checked_mul((RECORD_PREFIX_LEN + TAG_LEN) as u64)
        .ok_or(CryptoError::FileTooLarge)?;
    (HEADER_LEN as u64)
        .checked_add(plaintext_len)
        .and_then(|length| length.checked_add(framing))
        .ok_or(CryptoError::FileTooLarge)
}

#[allow(
    clippy::large_enum_variant,
    reason = "keeping the expanded cipher key inline avoids an additional secret heap allocation"
)]
enum Cipher {
    Aes(Aes256GcmSiv),
    XCha(XChaCha20Poly1305),
}

impl Cipher {
    fn new(header: &Header, password: &[u8]) -> Result<Self, CryptoError> {
        if password.is_empty() {
            return Err(CryptoError::EmptyPassword);
        }

        let params = Params::new(
            header.profile.memory_kib,
            header.profile.passes,
            header.profile.lanes,
            Some(32),
        )
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
        let block_count = params.block_count();
        let mut memory = Vec::new();
        memory
            .try_reserve_exact(block_count)
            .map_err(|_| CryptoError::ResourceLimit)?;
        memory.resize_with(block_count, Block::default);
        let mut memory = Zeroizing::new(memory);
        let mut root_key = Zeroizing::new([0_u8; 32]);
        let argon2 = Argon2::new(ArgonAlgorithm::Argon2id, Version::V0x13, params);
        argon2
            .hash_password_into_with_memory(
                password,
                &header.salt,
                &mut *root_key,
                memory.as_mut_slice(),
            )
            .map_err(|_| CryptoError::KeyDerivationFailed)?;

        let hkdf =
            Hkdf::<Sha256>::from_prk(&*root_key).map_err(|_| CryptoError::KeyDerivationFailed)?;
        let mut aead_key = Zeroizing::new([0_u8; 32]);
        hkdf.expand_multi_info(&[KEY_DOMAIN, &header.raw], &mut *aead_key)
            .map_err(|_| CryptoError::KeyDerivationFailed)?;

        match header.algorithm {
            EncryptionAlgorithm::Aes256GcmSiv => Aes256GcmSiv::new_from_slice(&*aead_key)
                .map(Self::Aes)
                .map_err(|_| CryptoError::CryptographicFailure),
            EncryptionAlgorithm::XChaCha20Poly1305 => XChaCha20Poly1305::new_from_slice(&*aead_key)
                .map(Self::XCha)
                .map_err(|_| CryptoError::CryptographicFailure),
        }
    }

    fn encrypt(
        &self,
        header: &Header,
        counter: u64,
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Result<[u8; TAG_LEN], CryptoError> {
        match self {
            Self::Aes(cipher) => {
                let nonce = AesNonce::from(aes_nonce(header, counter));
                cipher
                    .encrypt_inout_detached(&nonce, aad, buffer.into())
                    .map(Into::into)
                    .map_err(|_| CryptoError::CryptographicFailure)
            }
            Self::XCha(cipher) => {
                let nonce = XNonce::from(xcha_nonce(header, counter));
                cipher
                    .encrypt_inout_detached(&nonce, aad, buffer.into())
                    .map(Into::into)
                    .map_err(|_| CryptoError::CryptographicFailure)
            }
        }
    }

    fn decrypt(
        &self,
        header: &Header,
        counter: u64,
        aad: &[u8],
        buffer: &mut [u8],
        tag: [u8; TAG_LEN],
    ) -> Result<(), CryptoError> {
        match self {
            Self::Aes(cipher) => {
                let nonce = AesNonce::from(aes_nonce(header, counter));
                let tag = AesTag::from(tag);
                cipher
                    .decrypt_inout_detached(&nonce, aad, buffer.into(), &tag)
                    .map_err(|_| CryptoError::AuthenticationFailed)
            }
            Self::XCha(cipher) => {
                let nonce = XNonce::from(xcha_nonce(header, counter));
                let tag = XChaTag::from(tag);
                cipher
                    .decrypt_inout_detached(&nonce, aad, buffer.into(), &tag)
                    .map_err(|_| CryptoError::AuthenticationFailed)
            }
        }
    }
}

fn aes_nonce(header: &Header, counter: u64) -> [u8; 12] {
    let mut nonce = [0_u8; 12];
    nonce.copy_from_slice(&header.base_nonce[..12]);
    let counter = counter.to_be_bytes();
    for (nonce_byte, counter_byte) in nonce[4..].iter_mut().zip(counter) {
        *nonce_byte ^= counter_byte;
    }
    nonce
}

fn xcha_nonce(header: &Header, counter: u64) -> [u8; 24] {
    let mut nonce = header.base_nonce;
    let counter = counter.to_be_bytes();
    for (nonce_byte, counter_byte) in nonce[16..].iter_mut().zip(counter) {
        *nonce_byte ^= counter_byte;
    }
    nonce
}

fn record_prefix(kind: u8, plaintext_len: u32) -> [u8; RECORD_PREFIX_LEN] {
    let mut prefix = [0_u8; RECORD_PREFIX_LEN];
    prefix[0] = kind;
    prefix[4..].copy_from_slice(&plaintext_len.to_be_bytes());
    prefix
}

fn record_aad(header: &Header, counter: u64, prefix: &[u8; RECORD_PREFIX_LEN]) -> [u8; AAD_LEN] {
    let mut aad = [0_u8; AAD_LEN];
    let mut offset = 0;
    aad[offset..offset + RECORD_DOMAIN.len()].copy_from_slice(&RECORD_DOMAIN);
    offset += RECORD_DOMAIN.len();
    aad[offset..offset + HEADER_LEN].copy_from_slice(&header.raw);
    offset += HEADER_LEN;
    aad[offset..offset + 8].copy_from_slice(&counter.to_be_bytes());
    offset += 8;
    aad[offset..].copy_from_slice(prefix);
    aad
}

pub fn encrypt_file(
    input_path: &Path,
    output_path: &Path,
    password: &[u8],
    algorithm: EncryptionAlgorithm,
) -> Result<(), CryptoError> {
    encrypt_file_with_profile(
        input_path,
        output_path,
        password,
        algorithm,
        PRODUCTION_PROFILE,
    )
}

pub fn decrypt_file(
    input_path: &Path,
    output_path: &Path,
    password: &[u8],
    expected_algorithm: EncryptionAlgorithm,
) -> Result<(), CryptoError> {
    decrypt_file_with_profile(
        input_path,
        output_path,
        password,
        expected_algorithm,
        PRODUCTION_PROFILE,
    )
}

/// Opens and validates the selected input before an interactive prompt.
pub fn prepare_file_operation(command: Command) -> Result<PreparedFileOperation, CryptoError> {
    prepare_file_operation_with_profile(command, PRODUCTION_PROFILE)
}

/// Executes an operation prepared by [`prepare_file_operation`].
pub fn execute_prepared_file_operation(
    prepared: PreparedFileOperation,
    password: &[u8],
) -> Result<(), CryptoError> {
    execute_prepared_file_operation_inner(prepared, password)
}

fn encrypt_file_with_profile(
    input_path: &Path,
    output_path: &Path,
    password: &[u8],
    algorithm: EncryptionAlgorithm,
    profile: Profile,
) -> Result<(), CryptoError> {
    if password.is_empty() {
        return Err(CryptoError::EmptyPassword);
    }
    let prepared = prepare_file_operation_with_profile(
        Command {
            operation: Operation::Encrypt,
            algorithm,
            input: input_path.to_path_buf(),
            output: output_path.to_path_buf(),
        },
        profile,
    )?;
    execute_prepared_file_operation_inner(prepared, password)
}

fn decrypt_file_with_profile(
    input_path: &Path,
    output_path: &Path,
    password: &[u8],
    expected_algorithm: EncryptionAlgorithm,
    allowed_profile: Profile,
) -> Result<(), CryptoError> {
    if password.is_empty() {
        return Err(CryptoError::EmptyPassword);
    }
    let prepared = prepare_file_operation_with_profile(
        Command {
            operation: Operation::Decrypt,
            algorithm: expected_algorithm,
            input: input_path.to_path_buf(),
            output: output_path.to_path_buf(),
        },
        allowed_profile,
    )?;
    execute_prepared_file_operation_inner(prepared, password)
}

fn prepare_file_operation_with_profile(
    command: Command,
    profile: Profile,
) -> Result<PreparedFileOperation, CryptoError> {
    validate_profile(profile)?;
    let (input, input_len) = open_regular_input(&command.input)?;
    match command.operation {
        Operation::Encrypt => validate_plaintext_len(input_len, profile.chunk_size)?,
        Operation::Decrypt if input_len < MIN_CONTAINER_LEN => {
            return Err(CryptoError::InvalidFormat("container is too short"));
        }
        Operation::Decrypt => {}
    }
    let (output_path, output_parent) = validate_output_path(&command.output)?;
    Ok(PreparedFileOperation {
        operation: command.operation,
        algorithm: command.algorithm,
        input,
        input_len,
        output_path,
        output_parent,
        profile,
    })
}

fn execute_prepared_file_operation_inner(
    mut prepared: PreparedFileOperation,
    password: &[u8],
) -> Result<(), CryptoError> {
    if password.is_empty() {
        return Err(CryptoError::EmptyPassword);
    }

    match prepared.operation {
        Operation::Encrypt => {
            let header =
                Header::generate(prepared.algorithm, prepared.input_len, prepared.profile)?;
            let cipher = Cipher::new(&header, password)?;
            let mut temporary =
                create_temporary_output(&prepared.output_parent, &prepared.output_path)?;
            if let Err(error) =
                write_encrypted_container(&mut prepared.input, &mut temporary, &header, &cipher)
            {
                return Err(error_after_cleanup(temporary, error));
            }
            commit_output(temporary, &prepared.output_path)
        }
        Operation::Decrypt => {
            let raw_header = read_header(&mut prepared.input)?;
            let header = Header::decode(raw_header, prepared.profile)?;
            if encrypted_container_len(header.plaintext_len, header.profile.chunk_size)?
                != prepared.input_len
            {
                return Err(CryptoError::InvalidFormat(
                    "container length does not match its header",
                ));
            }
            if header.algorithm != prepared.algorithm {
                return Err(CryptoError::AlgorithmMismatch {
                    expected: prepared.algorithm,
                    found: header.algorithm,
                });
            }
            let cipher = Cipher::new(&header, password)?;
            let mut temporary =
                create_temporary_output(&prepared.output_parent, &prepared.output_path)?;
            if let Err(error) =
                read_encrypted_records(&mut prepared.input, &mut temporary, &header, &cipher)
            {
                return Err(error_after_cleanup(temporary, error));
            }
            commit_output(temporary, &prepared.output_path)
        }
    }
}

fn open_regular_input(path: &Path) -> Result<(File, u64), CryptoError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_FLAG_BACKUP_SEMANTICS permits directory handles, allowing the
        // metadata check below to return InputNotRegular instead of AccessDenied.
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        options.custom_flags(FILE_FLAG_BACKUP_SEMANTICS);
    }
    let file = options
        .open(path)
        .map_err(|source| path_io("cannot open input", path, source))?;
    let metadata = file
        .metadata()
        .map_err(|source| path_io("cannot inspect input", path, source))?;
    if !metadata.is_file() {
        return Err(CryptoError::InputNotRegular(path.to_path_buf()));
    }
    Ok((file, metadata.len()))
}

fn validate_output_path(path: &Path) -> Result<(PathBuf, PathBuf), CryptoError> {
    if has_trailing_separator(path) {
        return Err(CryptoError::InvalidOutputPath(path.to_path_buf()));
    }
    match fs::symlink_metadata(path) {
        Ok(_) => return Err(CryptoError::OutputExists(path.to_path_buf())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(source) => return Err(path_io("cannot inspect output", path, source)),
    }
    let file_name = path
        .file_name()
        .ok_or_else(|| CryptoError::InvalidOutputParent(path.to_path_buf()))?;
    let requested_parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        Some(_) => PathBuf::from("."),
        None => return Err(CryptoError::InvalidOutputParent(path.to_path_buf())),
    };
    let parent = fs::canonicalize(&requested_parent)
        .map_err(|source| path_io("cannot resolve output directory", &requested_parent, source))?;
    let metadata = fs::metadata(&parent)
        .map_err(|source| path_io("cannot inspect output directory", &parent, source))?;
    if !metadata.is_dir() {
        return Err(CryptoError::InvalidOutputParent(parent));
    }
    let output = parent.join(file_name);
    match fs::symlink_metadata(&output) {
        Ok(_) => return Err(CryptoError::OutputExists(path.to_path_buf())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(source) => return Err(path_io("cannot inspect output", path, source)),
    }
    Ok((output, parent))
}

#[cfg(unix)]
fn has_trailing_separator(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;

    path.as_os_str().as_bytes().last() == Some(&b'/')
}

#[cfg(windows)]
fn has_trailing_separator(path: &Path) -> bool {
    use std::os::windows::ffi::OsStrExt;

    path.as_os_str()
        .encode_wide()
        .last()
        .is_some_and(|unit| unit == u16::from(b'/') || unit == u16::from(b'\\'))
}

#[cfg(not(any(unix, windows)))]
fn has_trailing_separator(path: &Path) -> bool {
    path.as_os_str()
        .to_string_lossy()
        .ends_with(std::path::MAIN_SEPARATOR)
}

fn create_temporary_output(parent: &Path, output: &Path) -> Result<NamedTempFile, CryptoError> {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    for _ in 0..TEMP_CREATE_ATTEMPTS {
        let mut random = [0_u8; TEMP_RANDOM_BYTES];
        getrandom::fill(&mut random).map_err(|_| CryptoError::EntropyFailure)?;
        let mut name = String::from(".x2-");
        for byte in random {
            name.push(char::from(HEX[usize::from(byte >> 4)]));
            name.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        let temporary_path = parent.join(name);

        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }

        match options.open(&temporary_path) {
            Ok(file) => {
                let temp_path = match TempPath::try_from_path(&temporary_path) {
                    Ok(path) => path,
                    Err(source) => {
                        drop(file);
                        if let Err(cleanup_source) = fs::remove_file(&temporary_path) {
                            return Err(path_io(
                                "cannot remove temporary output",
                                &temporary_path,
                                cleanup_source,
                            ));
                        }
                        return Err(path_io("cannot track temporary output for", output, source));
                    }
                };
                let temporary = NamedTempFile::from_parts(file, temp_path);
                #[cfg(unix)]
                if let Err(source) = set_private_permissions(&temporary) {
                    let error = path_io("cannot secure temporary output for", output, source);
                    return Err(error_after_cleanup(temporary, error));
                }
                return Ok(temporary);
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(source) => {
                return Err(path_io(
                    "cannot create temporary output for",
                    output,
                    source,
                ));
            }
        }
    }

    Err(CryptoError::TemporaryNameExhausted(output.to_path_buf()))
}

#[cfg(unix)]
fn set_private_permissions(temporary: &NamedTempFile) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))
}

fn commit_output(mut temporary: NamedTempFile, output: &Path) -> Result<(), CryptoError> {
    if let Err(source) = temporary.as_file_mut().flush() {
        let error = path_io("cannot flush output", output, source);
        return Err(error_after_cleanup(temporary, error));
    }
    if let Err(source) = temporary.as_file().sync_all() {
        let error = path_io("cannot synchronize output", output, source);
        return Err(error_after_cleanup(temporary, error));
    }

    let temporary_path = temporary.path().to_path_buf();
    match temporary.persist_noclobber(output) {
        Ok(file) => {
            drop(file);
            match fs::remove_file(&temporary_path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(source) => {
                    return Err(path_io(
                        "output was installed; cannot remove old temporary name",
                        &temporary_path,
                        source,
                    ));
                }
            }
            sync_output_parent(output)
        }
        Err(error) => {
            let operation_error = if error.error.kind() == io::ErrorKind::AlreadyExists {
                CryptoError::OutputExists(output.to_path_buf())
            } else {
                path_io("cannot install output", output, error.error)
            };
            Err(error_after_cleanup(error.file, operation_error))
        }
    }
}

fn error_after_cleanup(temporary: NamedTempFile, operation_error: CryptoError) -> CryptoError {
    let temporary_path = temporary.path().to_path_buf();
    match temporary.close() {
        Ok(()) => operation_error,
        Err(error) if error.kind() == io::ErrorKind::NotFound => operation_error,
        Err(source) => CryptoError::CleanupFailed {
            temporary_path,
            operation: Box::new(operation_error),
            source,
        },
    }
}

#[cfg(unix)]
fn sync_output_parent(output: &Path) -> Result<(), CryptoError> {
    let parent = output.parent().filter(|path| !path.as_os_str().is_empty());
    let parent = parent.unwrap_or_else(|| Path::new("."));
    let directory = File::open(parent).map_err(|source| {
        path_io(
            "output was installed; cannot open directory",
            parent,
            source,
        )
    })?;
    directory.sync_all().map_err(|source| {
        path_io(
            "output was installed; cannot synchronize directory",
            parent,
            source,
        )
    })
}

#[cfg(not(unix))]
fn sync_output_parent(_output: &Path) -> Result<(), CryptoError> {
    Ok(())
}

fn write_encrypted_container<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    header: &Header,
    cipher: &Cipher,
) -> Result<(), CryptoError> {
    write_all(output, &header.raw, "cannot write encrypted header")?;

    let chunk_size = header.profile.chunk_size as usize;
    let allocation = usize::try_from(header.plaintext_len.min(chunk_size as u64))
        .map_err(|_| CryptoError::FileTooLarge)?;
    let mut plaintext = Vec::new();
    plaintext
        .try_reserve_exact(allocation)
        .map_err(|_| CryptoError::ResourceLimit)?;
    let mut plaintext = Zeroizing::new(plaintext);
    let mut remaining = header.plaintext_len;
    let mut counter = 0_u64;

    while remaining != 0 {
        let record_len = usize::try_from(remaining.min(chunk_size as u64))
            .map_err(|_| CryptoError::FileTooLarge)?;
        plaintext.resize(record_len, 0);
        read_exact_input(input, &mut plaintext)?;

        let record_len_u32 = u32::try_from(record_len).map_err(|_| CryptoError::FileTooLarge)?;
        let prefix = record_prefix(RECORD_DATA, record_len_u32);
        let aad = record_aad(header, counter, &prefix);
        let tag = cipher.encrypt(header, counter, &aad, &mut plaintext)?;
        write_all(output, &prefix, "cannot write record prefix")?;
        write_all(output, &plaintext, "cannot write ciphertext")?;
        write_all(output, &tag, "cannot write authentication tag")?;

        remaining -= record_len as u64;
        counter = counter.checked_add(1).ok_or(CryptoError::FileTooLarge)?;
    }

    if read_one(input, "cannot check input length")?.is_some() {
        return Err(CryptoError::InputChanged);
    }

    let prefix = record_prefix(RECORD_FINAL, 0);
    let aad = record_aad(header, counter, &prefix);
    let tag = cipher.encrypt(header, counter, &aad, &mut [])?;
    write_all(output, &prefix, "cannot write final record")?;
    write_all(output, &tag, "cannot write final authentication tag")?;
    Ok(())
}

fn read_encrypted_records<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    header: &Header,
    cipher: &Cipher,
) -> Result<(), CryptoError> {
    let chunk_size = header.profile.chunk_size as usize;
    let allocation = usize::try_from(header.plaintext_len.min(chunk_size as u64))
        .map_err(|_| CryptoError::FileTooLarge)?;
    let mut plaintext = Vec::new();
    plaintext
        .try_reserve_exact(allocation)
        .map_err(|_| CryptoError::ResourceLimit)?;
    let mut plaintext = Zeroizing::new(plaintext);
    let mut remaining = header.plaintext_len;
    let mut counter = 0_u64;

    while remaining != 0 {
        let expected_len = usize::try_from(remaining.min(chunk_size as u64))
            .map_err(|_| CryptoError::FileTooLarge)?;
        let prefix = read_record_prefix(input)?;
        validate_record_prefix(&prefix, RECORD_DATA, expected_len)?;

        plaintext.resize(expected_len, 0);
        read_exact_format(input, &mut plaintext, "truncated ciphertext")?;
        let tag = read_tag(input)?;
        let aad = record_aad(header, counter, &prefix);
        cipher.decrypt(header, counter, &aad, &mut plaintext, tag)?;
        write_all(output, &plaintext, "cannot write decrypted data")?;

        remaining -= expected_len as u64;
        counter = counter.checked_add(1).ok_or(CryptoError::FileTooLarge)?;
    }

    let final_prefix = read_record_prefix(input)?;
    validate_record_prefix(&final_prefix, RECORD_FINAL, 0)?;
    let final_tag = read_tag(input)?;
    let final_aad = record_aad(header, counter, &final_prefix);
    cipher.decrypt(header, counter, &final_aad, &mut [], final_tag)?;

    if read_one(input, "cannot check for trailing encrypted data")?.is_some() {
        return Err(CryptoError::InvalidFormat(
            "trailing data after final record",
        ));
    }
    Ok(())
}

fn read_header<R: Read>(input: &mut R) -> Result<[u8; HEADER_LEN], CryptoError> {
    let mut header = [0_u8; HEADER_LEN];
    read_exact_format(input, &mut header, "truncated header")?;
    Ok(header)
}

fn read_record_prefix<R: Read>(input: &mut R) -> Result<[u8; RECORD_PREFIX_LEN], CryptoError> {
    let mut prefix = [0_u8; RECORD_PREFIX_LEN];
    read_exact_format(input, &mut prefix, "truncated record prefix")?;
    Ok(prefix)
}

fn read_tag<R: Read>(input: &mut R) -> Result<[u8; TAG_LEN], CryptoError> {
    let mut tag = [0_u8; TAG_LEN];
    read_exact_format(input, &mut tag, "truncated authentication tag")?;
    Ok(tag)
}

fn validate_record_prefix(
    prefix: &[u8; RECORD_PREFIX_LEN],
    expected_kind: u8,
    expected_len: usize,
) -> Result<(), CryptoError> {
    if prefix[0] != expected_kind {
        return Err(CryptoError::InvalidFormat("unexpected record type"));
    }
    if prefix[1..4] != [0_u8; 3] {
        return Err(CryptoError::InvalidFormat("nonzero record reserved bytes"));
    }
    let encoded_len = u32::from_be_bytes([prefix[4], prefix[5], prefix[6], prefix[7]]);
    let expected_len =
        u32::try_from(expected_len).map_err(|_| CryptoError::InvalidFormat("record too large"))?;
    if encoded_len != expected_len {
        return Err(CryptoError::InvalidFormat("noncanonical record length"));
    }
    Ok(())
}

fn read_exact_input<R: Read>(input: &mut R, mut destination: &mut [u8]) -> Result<(), CryptoError> {
    while !destination.is_empty() {
        match input.read(destination) {
            Ok(0) => return Err(CryptoError::InputChanged),
            Ok(read) if read > destination.len() => {
                return Err(stream_contract_error(
                    "cannot read input",
                    "reader returned more bytes than requested",
                ));
            }
            Ok(read) => destination = &mut destination[read..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(source) => {
                return Err(CryptoError::StreamIo {
                    context: "cannot read input",
                    source,
                });
            }
        }
    }
    Ok(())
}

fn read_exact_format<R: Read>(
    input: &mut R,
    mut destination: &mut [u8],
    truncated_reason: &'static str,
) -> Result<(), CryptoError> {
    while !destination.is_empty() {
        match input.read(destination) {
            Ok(0) => return Err(CryptoError::InvalidFormat(truncated_reason)),
            Ok(read) if read > destination.len() => {
                return Err(stream_contract_error(
                    "cannot read encrypted input",
                    "reader returned more bytes than requested",
                ));
            }
            Ok(read) => destination = &mut destination[read..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(source) => {
                return Err(CryptoError::StreamIo {
                    context: "cannot read encrypted input",
                    source,
                });
            }
        }
    }
    Ok(())
}

fn read_one<R: Read>(input: &mut R, context: &'static str) -> Result<Option<u8>, CryptoError> {
    let mut byte = [0_u8; 1];
    loop {
        match input.read(&mut byte) {
            Ok(0) => return Ok(None),
            Ok(1) => return Ok(Some(byte[0])),
            Ok(_) => {
                return Err(stream_contract_error(
                    context,
                    "reader returned more bytes than requested",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(source) => return Err(CryptoError::StreamIo { context, source }),
        }
    }
}

fn write_all<W: Write>(
    output: &mut W,
    mut bytes: &[u8],
    context: &'static str,
) -> Result<(), CryptoError> {
    while !bytes.is_empty() {
        match output.write(bytes) {
            Ok(0) => {
                return Err(CryptoError::StreamIo {
                    context,
                    source: io::Error::new(io::ErrorKind::WriteZero, "writer made no progress"),
                });
            }
            Ok(written) if written > bytes.len() => {
                return Err(stream_contract_error(
                    context,
                    "writer returned more bytes than requested",
                ));
            }
            Ok(written) => bytes = &bytes[written..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(source) => return Err(CryptoError::StreamIo { context, source }),
        }
    }
    Ok(())
}

fn stream_contract_error(context: &'static str, message: &'static str) -> CryptoError {
    CryptoError::StreamIo {
        context,
        source: io::Error::new(io::ErrorKind::InvalidData, message),
    }
}

fn path_io(context: &'static str, path: &Path, source: io::Error) -> CryptoError {
    CryptoError::PathIo {
        context,
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::{
        io::Cursor,
        sync::{Arc, Barrier},
        thread,
    };

    const PASSWORD: &[u8] = b"correct horse battery staple";

    fn test_profile(chunk_size: u32) -> Profile {
        Profile {
            chunk_size,
            memory_kib: 8,
            passes: 1,
            lanes: 1,
        }
    }

    fn fixed_header(
        algorithm: EncryptionAlgorithm,
        plaintext_len: u64,
        profile: Profile,
        variant: u8,
    ) -> Header {
        let mut salt = [0_u8; SALT_LEN];
        for (index, byte) in salt.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_add(variant);
        }
        let mut nonce = [0_u8; NONCE_STORAGE_LEN];
        let nonce_len = match algorithm {
            EncryptionAlgorithm::Aes256GcmSiv => 12,
            EncryptionAlgorithm::XChaCha20Poly1305 => 24,
        };
        for (index, byte) in nonce[..nonce_len].iter_mut().enumerate() {
            *byte = (0x40_u8).wrapping_add(index as u8).wrapping_add(variant);
        }
        Header::from_material(algorithm, plaintext_len, profile, salt, nonce).unwrap()
    }

    fn encrypt_bytes(
        plaintext: &[u8],
        algorithm: EncryptionAlgorithm,
        profile: Profile,
        variant: u8,
    ) -> Vec<u8> {
        let header = fixed_header(algorithm, plaintext.len() as u64, profile, variant);
        let cipher = Cipher::new(&header, PASSWORD).unwrap();
        let mut input = Cursor::new(plaintext);
        let mut output = Vec::new();
        write_encrypted_container(&mut input, &mut output, &header, &cipher).unwrap();
        output
    }

    fn decrypt_bytes(
        container: &[u8],
        expected_algorithm: EncryptionAlgorithm,
        password: &[u8],
        profile: Profile,
    ) -> Result<Vec<u8>, CryptoError> {
        let mut input = Cursor::new(container);
        let raw = read_header(&mut input)?;
        let header = Header::decode(raw, profile)?;
        if header.algorithm != expected_algorithm {
            return Err(CryptoError::AlgorithmMismatch {
                expected: expected_algorithm,
                found: header.algorithm,
            });
        }
        let cipher = Cipher::new(&header, password)?;
        let mut output = Vec::new();
        read_encrypted_records(&mut input, &mut output, &header, &cipher)?;
        Ok(output)
    }

    fn decode_hex(hex: &str) -> Vec<u8> {
        assert_eq!(hex.len() % 2, 0);
        let (pairs, remainder) = hex.as_bytes().as_chunks::<2>();
        assert!(remainder.is_empty());
        pairs
            .iter()
            .map(|pair| {
                let high = char::from(pair[0]).to_digit(16).unwrap() as u8;
                let low = char::from(pair[1]).to_digit(16).unwrap() as u8;
                (high << 4) | low
            })
            .collect()
    }

    #[test]
    fn cli_accepts_all_four_commands() {
        let cases = [
            (
                "E",
                "AES",
                Operation::Encrypt,
                EncryptionAlgorithm::Aes256GcmSiv,
            ),
            (
                "E",
                "XCHA",
                Operation::Encrypt,
                EncryptionAlgorithm::XChaCha20Poly1305,
            ),
            (
                "D",
                "AES",
                Operation::Decrypt,
                EncryptionAlgorithm::Aes256GcmSiv,
            ),
            (
                "D",
                "XCHA",
                Operation::Decrypt,
                EncryptionAlgorithm::XChaCha20Poly1305,
            ),
        ];
        for (operation, algorithm, expected_operation, expected_algorithm) in cases {
            let parsed = parse_cli_args([operation, algorithm, "in file", "-out"]).unwrap();
            let ParsedCommand::Run(command) = parsed else {
                panic!("expected runnable command");
            };
            assert_eq!(command.operation, expected_operation);
            assert_eq!(command.algorithm, expected_algorithm);
            assert_eq!(command.input, PathBuf::from("in file"));
            assert_eq!(command.output, PathBuf::from("-out"));
        }
    }

    #[test]
    fn cli_help_and_version_are_explicit() {
        assert_eq!(parse_cli_args(["--help"]).unwrap(), ParsedCommand::Help);
        assert_eq!(parse_cli_args(["-h"]).unwrap(), ParsedCommand::Help);
        assert_eq!(
            parse_cli_args(["--version"]).unwrap(),
            ParsedCommand::Version
        );
        assert_eq!(parse_cli_args(["-V"]).unwrap(), ParsedCommand::Version);
    }

    #[test]
    fn cli_rejects_bad_arity_and_tokens() {
        for args in [
            vec![],
            vec!["E"],
            vec!["E", "AES", "input"],
            vec!["E", "AES", "in", "out", "extra"],
            vec!["e", "AES", "in", "out"],
            vec!["E", "aes", "in", "out"],
            vec!["Q", "AES", "in", "out"],
            vec!["E", "CHACHA", "in", "out"],
        ] {
            assert!(parse_cli_args(args).is_err());
        }
        assert!(parse_cli_args(std::iter::repeat("E")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn cli_preserves_non_utf8_paths() {
        use std::os::unix::ffi::OsStringExt;

        let input = OsString::from_vec(vec![b'i', b'n', 0xff]);
        let output = OsString::from_vec(vec![b'o', b'u', b't', 0xfe]);
        let parsed = parse_cli_args([
            OsString::from("E"),
            OsString::from("AES"),
            input.clone(),
            output.clone(),
        ])
        .unwrap();
        let ParsedCommand::Run(command) = parsed else {
            panic!("expected runnable command");
        };
        assert_eq!(command.input, PathBuf::from(input));
        assert_eq!(command.output, PathBuf::from(output));
    }

    #[test]
    fn header_has_frozen_canonical_encoding() {
        let profile = test_profile(16);
        let salt = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let mut nonce = [0_u8; NONCE_STORAGE_LEN];
        nonce[..12].copy_from_slice(&[
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
        ]);
        let header = Header::from_material(
            EncryptionAlgorithm::Aes256GcmSiv,
            0x01_02_03,
            profile,
            salt,
            nonce,
        )
        .unwrap();
        let expected = [
            0x58, 0x32, 0x45, 0x4e, 0x43, 0x0d, 0x0a, 0x1a, 0x00, 0x01, 0x00, 0x50, 0x01, 0x01,
            0x13, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x00, 0x01,
            0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(header.raw, expected);
        let decoded = Header::decode(expected, profile).unwrap();
        assert_eq!(decoded.algorithm, EncryptionAlgorithm::Aes256GcmSiv);
        assert_eq!(decoded.plaintext_len, 0x01_02_03);
        assert_eq!(decoded.salt, salt);
        assert_eq!(decoded.base_nonce, nonce);
    }

    #[test]
    fn header_round_trips_both_algorithms() {
        let profile = test_profile(31);
        for algorithm in [
            EncryptionAlgorithm::Aes256GcmSiv,
            EncryptionAlgorithm::XChaCha20Poly1305,
        ] {
            let header = fixed_header(algorithm, 999, profile, 7);
            let decoded = Header::decode(header.raw, profile).unwrap();
            assert_eq!(decoded.algorithm, algorithm);
            assert_eq!(decoded.plaintext_len, 999);
            assert_eq!(decoded.raw, header.raw);
        }
    }

    #[test]
    fn header_rejects_every_structural_field_error() {
        let profile = test_profile(16);
        let original = fixed_header(EncryptionAlgorithm::Aes256GcmSiv, 9, profile, 0).raw;
        for offset in [0, 8, 10, 12, 13, 14, 15, 16, 20, 24, 28, 68] {
            let mut changed = original;
            changed[offset] ^= 1;
            assert!(Header::decode(changed, profile).is_err(), "offset {offset}");
        }
    }

    #[test]
    fn header_rejects_wrong_profile_before_key_derivation() {
        let profile = test_profile(16);
        let header = fixed_header(EncryptionAlgorithm::XChaCha20Poly1305, 1, profile, 0);
        assert!(Header::decode(header.raw, test_profile(17)).is_err());
    }

    #[test]
    fn size_and_expansion_calculations_are_checked() {
        let chunk = 16;
        assert_eq!(data_record_count(0, chunk).unwrap(), 0);
        assert_eq!(data_record_count(1, chunk).unwrap(), 1);
        assert_eq!(data_record_count(16, chunk).unwrap(), 1);
        assert_eq!(data_record_count(17, chunk).unwrap(), 2);
        assert!(matches!(
            data_record_count(1, 0),
            Err(CryptoError::InvalidFormat("invalid chunk size"))
        ));
        assert!(matches!(
            encrypted_container_len(1, 0),
            Err(CryptoError::InvalidFormat("invalid chunk size"))
        ));
        assert_eq!(encrypted_container_len(0, chunk).unwrap(), 104);
        assert_eq!(encrypted_container_len(16, chunk).unwrap(), 144);
        assert_eq!(encrypted_container_len(17, chunk).unwrap(), 169);

        let largest = (MAX_RECORDS - 1) * u64::from(chunk);
        assert!(validate_plaintext_len(largest, chunk).is_ok());
        assert!(validate_plaintext_len(largest + 1, chunk).is_err());
    }

    #[test]
    fn nonce_derivation_is_frozen_and_unique() {
        let profile = test_profile(16);
        let aes = fixed_header(EncryptionAlgorithm::Aes256GcmSiv, 0, profile, 0);
        assert_eq!(
            aes_nonce(&aes, 0),
            [
                0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b
            ]
        );
        assert_eq!(aes_nonce(&aes, 1)[11], 0x4a);
        assert_ne!(aes_nonce(&aes, 0), aes_nonce(&aes, 1));
        assert_ne!(aes_nonce(&aes, 1), aes_nonce(&aes, u64::MAX));

        let xcha = fixed_header(EncryptionAlgorithm::XChaCha20Poly1305, 0, profile, 0);
        assert_eq!(xcha_nonce(&xcha, 0), xcha.base_nonce);
        assert_eq!(xcha_nonce(&xcha, 1)[23], xcha.base_nonce[23] ^ 1);
        assert_ne!(xcha_nonce(&xcha, 0), xcha_nonce(&xcha, u64::MAX));
    }

    #[test]
    fn aad_binds_header_counter_kind_and_length() {
        let profile = test_profile(16);
        let header = fixed_header(EncryptionAlgorithm::Aes256GcmSiv, 16, profile, 0);
        let prefix = record_prefix(RECORD_DATA, 16);
        let baseline = record_aad(&header, 0, &prefix);
        assert_ne!(baseline, record_aad(&header, 1, &prefix));
        assert_ne!(
            baseline,
            record_aad(&header, 0, &record_prefix(RECORD_FINAL, 0))
        );
        assert_ne!(
            baseline,
            record_aad(&header, 0, &record_prefix(RECORD_DATA, 15))
        );
        let other_header = fixed_header(EncryptionAlgorithm::Aes256GcmSiv, 16, profile, 1);
        assert_ne!(baseline, record_aad(&other_header, 0, &prefix));
    }

    #[test]
    fn round_trip_all_boundaries_for_both_algorithms() {
        let profile = test_profile(16);
        for algorithm in [
            EncryptionAlgorithm::Aes256GcmSiv,
            EncryptionAlgorithm::XChaCha20Poly1305,
        ] {
            for length in [0, 1, 15, 16, 17, 31, 32, 33, 79] {
                let plaintext: Vec<u8> = (0..length)
                    .map(|index| (index as u8).wrapping_mul(37))
                    .collect();
                let encrypted = encrypt_bytes(&plaintext, algorithm, profile, 0);
                assert_eq!(
                    encrypted.len() as u64,
                    encrypted_container_len(length as u64, profile.chunk_size).unwrap()
                );
                let decrypted = decrypt_bytes(&encrypted, algorithm, PASSWORD, profile).unwrap();
                assert_eq!(
                    decrypted, plaintext,
                    "algorithm={algorithm}, length={length}"
                );
            }
        }
    }

    #[test]
    fn deterministic_material_is_stable_but_fresh_material_changes_ciphertext() {
        let profile = test_profile(16);
        let plaintext = b"same plaintext";
        let first = encrypt_bytes(
            plaintext,
            EncryptionAlgorithm::XChaCha20Poly1305,
            profile,
            0,
        );
        let same = encrypt_bytes(
            plaintext,
            EncryptionAlgorithm::XChaCha20Poly1305,
            profile,
            0,
        );
        let fresh = encrypt_bytes(
            plaintext,
            EncryptionAlgorithm::XChaCha20Poly1305,
            profile,
            1,
        );
        assert_eq!(first, same);
        assert_ne!(first, fresh);
    }

    #[test]
    fn complete_v1_containers_match_frozen_golden_vectors() {
        let vectors = [
            (
                EncryptionAlgorithm::Aes256GcmSiv,
                concat!(
                    "5832454e430d0a1a000100500101130000100000000100000000000300000004",
                    "0000000000000010000102030405060708090a0b0c0d0e0f4041424344454647",
                    "48494a4b00000000000000000000000000000000000000106da1df7fb02cfa66",
                    "9b3a732c327d65259db88c3eb5127b0ec74b77cda58db9f00100000000000000",
                    "5379450c7e8e83cb04e6e76aac72e6bc",
                ),
            ),
            (
                EncryptionAlgorithm::XChaCha20Poly1305,
                concat!(
                    "5832454e430d0a1a000100500201130000100000000100000000000300000004",
                    "0000000000000010000102030405060708090a0b0c0d0e0f4041424344454647",
                    "48494a4b4c4d4e4f50515253545556570000000000000010fda0ca4c471f3669",
                    "fafc66ca66ce3e2ad9e6e24b3bfa8a4eceb5fba4739d92170100000000000000",
                    "5db2f62a15c19e33a75222b03d9fc0d9",
                ),
            ),
        ];

        for (algorithm, expected_hex) in vectors {
            let expected = decode_hex(expected_hex);
            let actual = encrypt_bytes(b"v1 compatibility", algorithm, PRODUCTION_PROFILE, 0);
            assert_eq!(actual, expected, "{algorithm}");
            assert_eq!(
                decrypt_bytes(&expected, algorithm, PASSWORD, PRODUCTION_PROFILE).unwrap(),
                b"v1 compatibility"
            );
        }
    }

    #[test]
    fn wrong_password_and_wrong_algorithm_fail() {
        let profile = test_profile(16);
        for algorithm in [
            EncryptionAlgorithm::Aes256GcmSiv,
            EncryptionAlgorithm::XChaCha20Poly1305,
        ] {
            let encrypted = encrypt_bytes(b"classified", algorithm, profile, 0);
            assert!(matches!(
                decrypt_bytes(&encrypted, algorithm, b"wrong", profile),
                Err(CryptoError::AuthenticationFailed)
            ));
            let other = match algorithm {
                EncryptionAlgorithm::Aes256GcmSiv => EncryptionAlgorithm::XChaCha20Poly1305,
                EncryptionAlgorithm::XChaCha20Poly1305 => EncryptionAlgorithm::Aes256GcmSiv,
            };
            assert!(matches!(
                decrypt_bytes(&encrypted, other, PASSWORD, profile),
                Err(CryptoError::AlgorithmMismatch { .. })
            ));
        }
    }

    #[test]
    fn every_header_byte_is_authenticated_or_structurally_rejected() {
        let profile = test_profile(16);
        let encrypted = encrypt_bytes(
            b"header authentication",
            EncryptionAlgorithm::XChaCha20Poly1305,
            profile,
            0,
        );
        for offset in 0..HEADER_LEN {
            let mut changed = encrypted.clone();
            changed[offset] ^= 1;
            assert!(
                decrypt_bytes(
                    &changed,
                    EncryptionAlgorithm::XChaCha20Poly1305,
                    PASSWORD,
                    profile
                )
                .is_err(),
                "header offset {offset} was accepted"
            );
        }
    }

    #[test]
    fn every_frame_byte_is_authenticated_or_structurally_rejected() {
        let profile = test_profile(16);
        let encrypted = encrypt_bytes(
            b"frame authentication across chunks",
            EncryptionAlgorithm::Aes256GcmSiv,
            profile,
            0,
        );
        for offset in HEADER_LEN..encrypted.len() {
            let mut changed = encrypted.clone();
            changed[offset] ^= 1;
            assert!(
                decrypt_bytes(
                    &changed,
                    EncryptionAlgorithm::Aes256GcmSiv,
                    PASSWORD,
                    profile
                )
                .is_err(),
                "frame offset {offset} was accepted"
            );
        }
    }

    #[test]
    fn every_truncation_and_any_trailing_data_fail() {
        let profile = test_profile(16);
        let encrypted = encrypt_bytes(
            b"truncation crosses several records",
            EncryptionAlgorithm::XChaCha20Poly1305,
            profile,
            0,
        );
        for length in 0..encrypted.len() {
            assert!(
                decrypt_bytes(
                    &encrypted[..length],
                    EncryptionAlgorithm::XChaCha20Poly1305,
                    PASSWORD,
                    profile
                )
                .is_err(),
                "truncation length {length} was accepted"
            );
        }
        let mut appended = encrypted;
        appended.extend_from_slice(b"garbage");
        assert!(
            decrypt_bytes(
                &appended,
                EncryptionAlgorithm::XChaCha20Poly1305,
                PASSWORD,
                profile
            )
            .is_err()
        );
    }

    #[test]
    fn dropped_reordered_duplicated_and_spliced_records_fail() {
        let profile = test_profile(16);
        let original = encrypt_bytes(&[0x55; 30], EncryptionAlgorithm::Aes256GcmSiv, profile, 0);
        let other = encrypt_bytes(&[0xaa; 30], EncryptionAlgorithm::Aes256GcmSiv, profile, 1);
        let first_end = HEADER_LEN + RECORD_PREFIX_LEN + 16 + TAG_LEN;
        let second_end = first_end + RECORD_PREFIX_LEN + 14 + TAG_LEN;

        let mut dropped = original[..HEADER_LEN].to_vec();
        dropped.extend_from_slice(&original[first_end..]);

        let mut reordered = original[..HEADER_LEN].to_vec();
        reordered.extend_from_slice(&original[first_end..second_end]);
        reordered.extend_from_slice(&original[HEADER_LEN..first_end]);
        reordered.extend_from_slice(&original[second_end..]);

        let mut duplicated = original[..first_end].to_vec();
        duplicated.extend_from_slice(&original[HEADER_LEN..first_end]);
        duplicated.extend_from_slice(&original[first_end..]);

        let mut spliced = original.clone();
        spliced[HEADER_LEN..first_end].copy_from_slice(&other[HEADER_LEN..first_end]);

        for malformed in [dropped, reordered, duplicated, spliced] {
            assert!(
                decrypt_bytes(
                    &malformed,
                    EncryptionAlgorithm::Aes256GcmSiv,
                    PASSWORD,
                    profile
                )
                .is_err()
            );
        }
    }

    struct ShortReader<R> {
        inner: R,
        maximum: usize,
    }

    impl<R: Read> Read for ShortReader<R> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let allowed = buffer.len().min(self.maximum);
            self.inner.read(&mut buffer[..allowed])
        }
    }

    struct ShortWriter {
        bytes: Vec<u8>,
        maximum: usize,
    }

    impl Write for ShortWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let written = bytes.len().min(self.maximum);
            self.bytes.extend_from_slice(&bytes[..written]);
            Ok(written)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn short_reads_and_short_writes_are_fully_handled() {
        let profile = test_profile(16);
        let plaintext = b"many deliberately tiny reads and writes";
        let header = fixed_header(
            EncryptionAlgorithm::XChaCha20Poly1305,
            plaintext.len() as u64,
            profile,
            0,
        );
        let cipher = Cipher::new(&header, PASSWORD).unwrap();
        let mut reader = ShortReader {
            inner: Cursor::new(plaintext),
            maximum: 1,
        };
        let mut writer = ShortWriter {
            bytes: Vec::new(),
            maximum: 1,
        };
        write_encrypted_container(&mut reader, &mut writer, &header, &cipher).unwrap();

        let mut encrypted_reader = ShortReader {
            inner: Cursor::new(&writer.bytes),
            maximum: 1,
        };
        let raw = read_header(&mut encrypted_reader).unwrap();
        let decoded = Header::decode(raw, profile).unwrap();
        let decryptor = Cipher::new(&decoded, PASSWORD).unwrap();
        let mut plaintext_writer = ShortWriter {
            bytes: Vec::new(),
            maximum: 1,
        };
        read_encrypted_records(
            &mut encrypted_reader,
            &mut plaintext_writer,
            &decoded,
            &decryptor,
        )
        .unwrap();
        assert_eq!(plaintext_writer.bytes, plaintext);
    }

    struct FailingWriter {
        remaining: usize,
    }

    impl Write for FailingWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.remaining == 0 {
                return Err(io::Error::new(io::ErrorKind::StorageFull, "injected"));
            }
            let written = bytes.len().min(self.remaining);
            self.remaining -= written;
            Ok(written)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct InterruptedReader<R> {
        inner: R,
        interrupt_next: bool,
    }

    impl<R: Read> Read for InterruptedReader<R> {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            if self.interrupt_next {
                self.interrupt_next = false;
                Err(io::Error::from(io::ErrorKind::Interrupted))
            } else {
                self.inner.read(bytes)
            }
        }
    }

    struct InterruptedWriter {
        bytes: Vec<u8>,
        interrupt_next: bool,
    }

    impl Write for InterruptedWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.interrupt_next {
                self.interrupt_next = false;
                Err(io::Error::from(io::ErrorKind::Interrupted))
            } else {
                self.bytes.extend_from_slice(bytes);
                Ok(bytes.len())
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct ZeroWriter;

    impl Write for ZeroWriter {
        fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
            Ok(0)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct OverreportingReader;

    impl Read for OverreportingReader {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            Ok(bytes.len() + 1)
        }
    }

    struct OverreportingWriter;

    impl Write for OverreportingWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            Ok(bytes.len() + 1)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn write_failures_propagate_without_panics() {
        let profile = test_profile(16);
        let plaintext = b"write failure";
        let header = fixed_header(
            EncryptionAlgorithm::Aes256GcmSiv,
            plaintext.len() as u64,
            profile,
            0,
        );
        let cipher = Cipher::new(&header, PASSWORD).unwrap();
        let mut input = Cursor::new(plaintext);
        let mut output = FailingWriter { remaining: 85 };
        assert!(matches!(
            write_encrypted_container(&mut input, &mut output, &header, &cipher),
            Err(CryptoError::StreamIo { .. })
        ));
    }

    #[test]
    fn interrupted_io_is_retried() {
        let mut input = InterruptedReader {
            inner: Cursor::new(b"abc"),
            interrupt_next: true,
        };
        let mut bytes = [0_u8; 3];
        read_exact_input(&mut input, &mut bytes).unwrap();
        assert_eq!(&bytes, b"abc");

        let mut encrypted_input = InterruptedReader {
            inner: Cursor::new(b"xyz"),
            interrupt_next: true,
        };
        read_exact_format(&mut encrypted_input, &mut bytes, "truncated").unwrap();
        assert_eq!(&bytes, b"xyz");

        let mut one = InterruptedReader {
            inner: Cursor::new(b"q"),
            interrupt_next: true,
        };
        assert_eq!(read_one(&mut one, "read one").unwrap(), Some(b'q'));

        let mut output = InterruptedWriter {
            bytes: Vec::new(),
            interrupt_next: true,
        };
        write_all(&mut output, b"written", "write test").unwrap();
        assert_eq!(output.bytes, b"written");
    }

    #[test]
    fn zero_progress_and_contract_violating_io_are_errors_not_panics() {
        assert!(matches!(
            write_all(&mut ZeroWriter, b"x", "write test"),
            Err(CryptoError::StreamIo { .. })
        ));
        assert!(matches!(
            write_all(&mut OverreportingWriter, b"x", "write test"),
            Err(CryptoError::StreamIo { .. })
        ));

        let mut byte = [0_u8; 1];
        assert!(matches!(
            read_exact_input(&mut OverreportingReader, &mut byte),
            Err(CryptoError::StreamIo { .. })
        ));
        assert!(matches!(
            read_exact_format(&mut OverreportingReader, &mut byte, "truncated"),
            Err(CryptoError::StreamIo { .. })
        ));
        assert!(matches!(
            read_one(&mut OverreportingReader, "read one"),
            Err(CryptoError::StreamIo { .. })
        ));
    }

    #[test]
    fn encryption_detects_input_shrink_and_growth() {
        let profile = test_profile(16);
        let header = fixed_header(EncryptionAlgorithm::Aes256GcmSiv, 10, profile, 0);
        let cipher = Cipher::new(&header, PASSWORD).unwrap();
        for input in [vec![0_u8; 9], vec![0_u8; 11]] {
            let mut input = Cursor::new(input);
            let mut output = Vec::new();
            assert!(matches!(
                write_encrypted_container(&mut input, &mut output, &header, &cipher),
                Err(CryptoError::InputChanged)
            ));
        }
    }

    #[test]
    fn aes_256_gcm_siv_matches_rfc_8452_empty_vector() {
        let mut key = [0_u8; 32];
        key[0] = 1;
        let cipher = Aes256GcmSiv::new_from_slice(&key).unwrap();
        let nonce = AesNonce::from([3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let tag: [u8; TAG_LEN] = cipher
            .encrypt_inout_detached(&nonce, b"", (&mut [][..]).into())
            .unwrap()
            .into();
        assert_eq!(
            tag,
            [
                0x07, 0xf5, 0xf4, 0x16, 0x9b, 0xbf, 0x55, 0xa8, 0x40, 0x0c, 0xd4, 0x7e, 0xa6, 0xfd,
                0x40, 0x0f,
            ]
        );
    }

    #[test]
    fn xchacha20_poly1305_matches_ietf_draft_vector() {
        let key: [u8; 32] = std::array::from_fn(|index| 0x80 + index as u8);
        let nonce: [u8; 24] = std::array::from_fn(|index| 0x40 + index as u8);
        let aad = [
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        ];
        let mut plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".to_vec();
        let cipher = XChaCha20Poly1305::new_from_slice(&key).unwrap();
        let tag: [u8; TAG_LEN] = cipher
            .encrypt_inout_detached(&XNonce::from(nonce), &aad, plaintext.as_mut_slice().into())
            .unwrap()
            .into();
        let expected_ciphertext = [
            0xbd, 0x6d, 0x17, 0x9d, 0x3e, 0x83, 0xd4, 0x3b, 0x95, 0x76, 0x57, 0x94, 0x93, 0xc0,
            0xe9, 0x39, 0x57, 0x2a, 0x17, 0x00, 0x25, 0x2b, 0xfa, 0xcc, 0xbe, 0xd2, 0x90, 0x2c,
            0x21, 0x39, 0x6c, 0xbb, 0x73, 0x1c, 0x7f, 0x1b, 0x0b, 0x4a, 0xa6, 0x44, 0x0b, 0xf3,
            0xa8, 0x2f, 0x4e, 0xda, 0x7e, 0x39, 0xae, 0x64, 0xc6, 0x70, 0x8c, 0x54, 0xc2, 0x16,
            0xcb, 0x96, 0xb7, 0x2e, 0x12, 0x13, 0xb4, 0x52, 0x2f, 0x8c, 0x9b, 0xa4, 0x0d, 0xb5,
            0xd9, 0x45, 0xb1, 0x1b, 0x69, 0xb9, 0x82, 0xc1, 0xbb, 0x9e, 0x3f, 0x3f, 0xac, 0x2b,
            0xc3, 0x69, 0x48, 0x8f, 0x76, 0xb2, 0x38, 0x35, 0x65, 0xd3, 0xff, 0xf9, 0x21, 0xf9,
            0x66, 0x4c, 0x97, 0x63, 0x7d, 0xa9, 0x76, 0x88, 0x12, 0xf6, 0x15, 0xc6, 0x8b, 0x13,
            0xb5, 0x2e,
        ];
        assert_eq!(plaintext, expected_ciphertext);
        assert_eq!(
            tag,
            [
                0xc0, 0x87, 0x59, 0x24, 0xc1, 0xc7, 0x98, 0x79, 0x47, 0xde, 0xaf, 0xd8, 0x78, 0x0a,
                0xcf, 0x49,
            ]
        );
    }

    #[test]
    fn argon2id_matches_reference_vector() {
        let params = Params::new(256, 2, 1, Some(32)).unwrap();
        let mut memory = vec![Block::default(); params.block_count()];
        let argon = Argon2::new(ArgonAlgorithm::Argon2id, Version::V0x13, params);
        let mut output = [0_u8; 32];
        argon
            .hash_password_into_with_memory(b"password", b"somesalt", &mut output, &mut memory)
            .unwrap();
        assert_eq!(
            output,
            [
                0x9d, 0xfe, 0xb9, 0x10, 0xe8, 0x0b, 0xad, 0x03, 0x11, 0xfe, 0xe2, 0x0f, 0x9c, 0x0e,
                0x2b, 0x12, 0xc1, 0x79, 0x87, 0xb4, 0xca, 0xc9, 0x0c, 0x2e, 0xf5, 0x4d, 0x5b, 0x30,
                0x21, 0xc6, 0x8b, 0xfe,
            ]
        );
    }

    #[test]
    fn file_round_trip_uses_atomic_no_clobber_output() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("plain");
        let encrypted = directory.path().join("encrypted");
        let decrypted = directory.path().join("decrypted");
        let plaintext: Vec<u8> = (0..257).map(|value| value as u8).collect();
        fs::write(&input, &plaintext).unwrap();

        encrypt_file_with_profile(
            &input,
            &encrypted,
            PASSWORD,
            EncryptionAlgorithm::XChaCha20Poly1305,
            test_profile(31),
        )
        .unwrap();
        decrypt_file_with_profile(
            &encrypted,
            &decrypted,
            PASSWORD,
            EncryptionAlgorithm::XChaCha20Poly1305,
            test_profile(31),
        )
        .unwrap();
        assert_eq!(fs::read(decrypted).unwrap(), plaintext);
    }

    #[test]
    fn multi_megabyte_file_round_trip_stays_chunked() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("plain-large");
        let encrypted = directory.path().join("encrypted-large");
        let decrypted = directory.path().join("decrypted-large");
        let length = 3 * 1_048_576 + 17;
        let plaintext: Vec<u8> = (0..length)
            .map(|index| (index as u8).wrapping_mul(131).wrapping_add(17))
            .collect();
        fs::write(&input, &plaintext).unwrap();
        let profile = test_profile(1_048_576);

        encrypt_file_with_profile(
            &input,
            &encrypted,
            PASSWORD,
            EncryptionAlgorithm::XChaCha20Poly1305,
            profile,
        )
        .unwrap();
        decrypt_file_with_profile(
            &encrypted,
            &decrypted,
            PASSWORD,
            EncryptionAlgorithm::XChaCha20Poly1305,
            profile,
        )
        .unwrap();
        assert_eq!(fs::read(decrypted).unwrap(), plaintext);
    }

    #[test]
    fn existing_output_is_never_changed() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("plain");
        let output = directory.path().join("existing");
        fs::write(&input, b"secret").unwrap();
        fs::write(&output, b"keep me").unwrap();
        let result = encrypt_file_with_profile(
            &input,
            &output,
            PASSWORD,
            EncryptionAlgorithm::Aes256GcmSiv,
            test_profile(16),
        );
        assert!(matches!(result, Err(CryptoError::OutputExists(_))));
        assert_eq!(fs::read(output).unwrap(), b"keep me");
    }

    #[cfg(unix)]
    #[test]
    fn prepared_operation_keeps_the_pre_prompt_input_handle() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("plain");
        let moved = directory.path().join("plain-original");
        let encrypted = directory.path().join("encrypted");
        let decrypted = directory.path().join("decrypted");
        fs::write(&input, b"selected before prompt").unwrap();
        let profile = test_profile(16);
        let prepared = prepare_file_operation_with_profile(
            Command {
                operation: Operation::Encrypt,
                algorithm: EncryptionAlgorithm::Aes256GcmSiv,
                input: input.clone(),
                output: encrypted.clone(),
            },
            profile,
        )
        .unwrap();

        fs::rename(&input, &moved).unwrap();
        fs::write(&input, b"replacement after prompt began").unwrap();
        execute_prepared_file_operation_inner(prepared, PASSWORD).unwrap();
        decrypt_file_with_profile(
            &encrypted,
            &decrypted,
            PASSWORD,
            EncryptionAlgorithm::Aes256GcmSiv,
            profile,
        )
        .unwrap();
        assert_eq!(fs::read(decrypted).unwrap(), b"selected before prompt");
    }

    #[cfg(unix)]
    #[test]
    fn prepared_operation_resolves_the_output_directory_once() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let first = directory.path().join("first");
        let second = directory.path().join("second");
        let alias = directory.path().join("output-alias");
        fs::create_dir(&first).unwrap();
        fs::create_dir(&second).unwrap();
        symlink(&first, &alias).unwrap();

        let input = directory.path().join("plain");
        fs::write(&input, b"stable output selection").unwrap();
        let prepared = prepare_file_operation_with_profile(
            Command {
                operation: Operation::Encrypt,
                algorithm: EncryptionAlgorithm::Aes256GcmSiv,
                input,
                output: alias.join("encrypted"),
            },
            test_profile(16),
        )
        .unwrap();
        assert!(prepared.output_path.is_absolute());

        fs::remove_file(&alias).unwrap();
        symlink(&second, &alias).unwrap();
        execute_prepared_file_operation_inner(prepared, PASSWORD).unwrap();
        assert!(first.join("encrypted").is_file());
        assert!(!second.join("encrypted").exists());
    }

    #[test]
    fn wrong_password_and_corruption_leave_no_plaintext_output_or_temp() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("plain");
        let encrypted = directory.path().join("encrypted");
        let output = directory.path().join("should-not-exist");
        fs::write(&input, b"sensitive plaintext").unwrap();
        encrypt_file_with_profile(
            &input,
            &encrypted,
            PASSWORD,
            EncryptionAlgorithm::Aes256GcmSiv,
            test_profile(8),
        )
        .unwrap();

        assert!(
            decrypt_file_with_profile(
                &encrypted,
                &output,
                b"wrong password",
                EncryptionAlgorithm::Aes256GcmSiv,
                test_profile(8),
            )
            .is_err()
        );
        assert!(!output.exists());

        let mut bytes = fs::read(&encrypted).unwrap();
        bytes[HEADER_LEN + RECORD_PREFIX_LEN] ^= 1;
        fs::write(&encrypted, bytes).unwrap();
        assert!(
            decrypt_file_with_profile(
                &encrypted,
                &output,
                PASSWORD,
                EncryptionAlgorithm::Aes256GcmSiv,
                test_profile(8),
            )
            .is_err()
        );
        assert!(!output.exists());
        let names: Vec<OsString> = fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert!(
            !names
                .iter()
                .any(|name| name.to_string_lossy().starts_with(".x2-"))
        );
    }

    #[test]
    fn same_path_and_non_regular_inputs_are_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("plain");
        fs::write(&input, b"preserve").unwrap();
        assert!(matches!(
            encrypt_file_with_profile(
                &input,
                &input,
                PASSWORD,
                EncryptionAlgorithm::Aes256GcmSiv,
                test_profile(16),
            ),
            Err(CryptoError::OutputExists(_))
        ));
        assert_eq!(fs::read(&input).unwrap(), b"preserve");

        let output = directory.path().join("out");
        assert!(matches!(
            encrypt_file_with_profile(
                directory.path(),
                &output,
                PASSWORD,
                EncryptionAlgorithm::Aes256GcmSiv,
                test_profile(16),
            ),
            Err(CryptoError::InputNotRegular(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn fifo_input_is_rejected_without_waiting_for_a_writer() {
        let directory = tempfile::tempdir().unwrap();
        let fifo = directory.path().join("input-fifo");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(status.success());
        assert!(matches!(
            open_regular_input(&fifo),
            Err(CryptoError::InputNotRegular(_))
        ));
    }

    #[test]
    fn missing_or_non_directory_output_parent_is_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("plain");
        fs::write(&input, b"secret").unwrap();
        let missing = directory.path().join("missing").join("out");
        assert!(
            encrypt_file_with_profile(
                &input,
                &missing,
                PASSWORD,
                EncryptionAlgorithm::Aes256GcmSiv,
                test_profile(16),
            )
            .is_err()
        );

        let parent_file = directory.path().join("parent-file");
        fs::write(&parent_file, b"not a directory").unwrap();
        let child = parent_file.join("out");
        assert!(
            encrypt_file_with_profile(
                &input,
                &child,
                PASSWORD,
                EncryptionAlgorithm::Aes256GcmSiv,
                test_profile(16),
            )
            .is_err()
        );

        let mut trailing_separator = directory
            .path()
            .join("must-not-be-created")
            .into_os_string();
        trailing_separator.push(std::path::MAIN_SEPARATOR.to_string());
        let trailing_separator = PathBuf::from(trailing_separator);
        assert!(matches!(
            encrypt_file_with_profile(
                &input,
                &trailing_separator,
                PASSWORD,
                EncryptionAlgorithm::Aes256GcmSiv,
                test_profile(16),
            ),
            Err(CryptoError::InvalidOutputPath(_))
        ));
        assert!(!directory.path().join("must-not-be-created").exists());
    }

    #[cfg(unix)]
    #[test]
    fn output_mode_is_private_and_dangling_symlinks_are_not_overwritten() {
        use std::os::unix::fs::{MetadataExt, symlink};

        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("plain");
        let encrypted = directory.path().join("encrypted");
        fs::write(&input, b"secret").unwrap();
        encrypt_file_with_profile(
            &input,
            &encrypted,
            PASSWORD,
            EncryptionAlgorithm::Aes256GcmSiv,
            test_profile(16),
        )
        .unwrap();
        assert_eq!(fs::metadata(&encrypted).unwrap().mode() & 0o777, 0o600);

        let dangling = directory.path().join("dangling");
        symlink(directory.path().join("missing-target"), &dangling).unwrap();
        assert!(matches!(
            encrypt_file_with_profile(
                &input,
                &dangling,
                PASSWORD,
                EncryptionAlgorithm::Aes256GcmSiv,
                test_profile(16),
            ),
            Err(CryptoError::OutputExists(_))
        ));
        assert!(
            fs::symlink_metadata(dangling)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn competing_writers_cannot_clobber_each_other() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("plain");
        let output = directory.path().join("encrypted");
        fs::write(&input, vec![0x42; 128]).unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let mut handles = Vec::new();
        for _ in 0..2 {
            let input = input.clone();
            let output = output.clone();
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                encrypt_file_with_profile(
                    &input,
                    &output,
                    PASSWORD,
                    EncryptionAlgorithm::XChaCha20Poly1305,
                    test_profile(16),
                )
            }));
        }
        let results: Vec<Result<(), CryptoError>> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(CryptoError::OutputExists(_))))
                .count(),
            1
        );
    }

    #[test]
    fn production_argon_profile_round_trips() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("plain");
        let encrypted = directory.path().join("encrypted");
        let decrypted = directory.path().join("decrypted");
        fs::write(&input, b"production profile check").unwrap();
        encrypt_file(
            &input,
            &encrypted,
            PASSWORD,
            EncryptionAlgorithm::Aes256GcmSiv,
        )
        .unwrap();
        decrypt_file(
            &encrypted,
            &decrypted,
            PASSWORD,
            EncryptionAlgorithm::Aes256GcmSiv,
        )
        .unwrap();
        assert_eq!(fs::read(decrypted).unwrap(), b"production profile check");
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(48))]

        #[test]
        fn arbitrary_untrusted_headers_never_panic(raw in any::<[u8; HEADER_LEN]>()) {
            let _ = Header::decode(raw, test_profile(16));
        }

        #[test]
        fn structurally_valid_headers_reach_deep_decode_paths(
            plaintext_len in 0_u64..((MAX_RECORDS - 1) * 16),
            salt in any::<[u8; SALT_LEN]>(),
            nonce in any::<[u8; NONCE_STORAGE_LEN]>(),
            use_aes in any::<bool>(),
        ) {
            let algorithm = if use_aes {
                EncryptionAlgorithm::Aes256GcmSiv
            } else {
                EncryptionAlgorithm::XChaCha20Poly1305
            };
            let mut nonce = nonce;
            if use_aes {
                nonce[12..].fill(0);
            }
            let profile = test_profile(16);
            let header = Header::from_material(
                algorithm,
                plaintext_len,
                profile,
                salt,
                nonce,
            ).unwrap();
            let decoded = Header::decode(header.raw, profile).unwrap();
            prop_assert_eq!(decoded.plaintext_len, plaintext_len);
            prop_assert_eq!(decoded.salt, salt);
            prop_assert_eq!(decoded.base_nonce, nonce);
        }

        #[test]
        fn structured_header_mutations_never_panic(
            offset in 8_usize..HEADER_LEN,
            bit in 0_u8..8,
            use_aes in any::<bool>(),
        ) {
            let algorithm = if use_aes {
                EncryptionAlgorithm::Aes256GcmSiv
            } else {
                EncryptionAlgorithm::XChaCha20Poly1305
            };
            let profile = test_profile(16);
            let mut raw = fixed_header(algorithm, 17, profile, 0).raw;
            raw[offset] ^= 1_u8 << bit;
            let _ = Header::decode(raw, profile);
        }

        #[test]
        fn arbitrary_record_mutations_never_panic(
            mutations in proptest::collection::vec((HEADER_LEN..169_usize, any::<u8>()), 0..24),
        ) {
            let profile = test_profile(16);
            let mut container = encrypt_bytes(
                b"seventeen bytes!!",
                EncryptionAlgorithm::Aes256GcmSiv,
                profile,
                0,
            );
            prop_assert_eq!(container.len(), 169);
            for (offset, value) in mutations {
                container[offset] ^= value;
            }
            let _ = decrypt_bytes(
                &container,
                EncryptionAlgorithm::Aes256GcmSiv,
                PASSWORD,
                profile,
            );
        }

        #[test]
        fn arbitrary_plaintexts_round_trip(
            plaintext in proptest::collection::vec(any::<u8>(), 0..257),
            use_aes in any::<bool>(),
            chunk in 1_u32..65,
        ) {
            let algorithm = if use_aes {
                EncryptionAlgorithm::Aes256GcmSiv
            } else {
                EncryptionAlgorithm::XChaCha20Poly1305
            };
            let profile = test_profile(chunk);
            let encrypted = encrypt_bytes(&plaintext, algorithm, profile, 3);
            let decrypted = decrypt_bytes(&encrypted, algorithm, PASSWORD, profile).unwrap();
            prop_assert_eq!(decrypted, plaintext);
        }
    }
}
