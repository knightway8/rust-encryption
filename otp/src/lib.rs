//! Authenticated, single-message one-time-pad file encryption.
//!
//! The XOR pad provides perfect confidentiality when the pad is generated
//! uniformly, kept secret, and never reused. An independent HMAC key adds
//! computational integrity without changing that confidentiality property.

use std::env;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tempfile::NamedTempFile;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

type HmacSha256 = Hmac<Sha256>;

pub const PAD_MAGIC: &[u8; 8] = b"OTPPAD01";
pub const ENVELOPE_MAGIC: &[u8; 8] = b"OTPENC01";
pub const FORMAT_VERSION: u16 = 1;
pub const SUITE_XOR_HMAC_SHA256: u16 = 1;
pub const PAD_HEADER_LEN: usize = 80;
pub const ENVELOPE_HEADER_LEN: usize = 64;
pub const KEY_ID_LEN: usize = 32;
pub const AUTH_KEY_LEN: usize = 32;
pub const TAG_LEN: usize = 32;
pub const PAD_SECRET_OFFSET: u64 = PAD_HEADER_LEN as u64;
pub const PAD_BYTES_OFFSET: u64 = (PAD_HEADER_LEN + AUTH_KEY_LEN) as u64;
pub const PAD_STATE_OFFSET: u64 = 17;
pub const IO_BUFFER_SIZE: usize = 64 * 1024;

const PAD_CHECKSUM_LEN: u64 = 32;
const PAD_FIXED_LEN: u64 = PAD_HEADER_LEN as u64 + AUTH_KEY_LEN as u64 + PAD_CHECKSUM_LEN;
const ENVELOPE_FIXED_LEN: u64 = ENVELOPE_HEADER_LEN as u64 + TAG_LEN as u64;
const PAD_CHECKSUM_DOMAIN: &[u8] = b"otp/pad-checksum/v1\0";
const ENVELOPE_AUTH_DOMAIN: &[u8] = b"otp/envelope-auth/v1\0";
const LEDGER_MAGIC: &[u8; 8] = b"OTPUSE01";

#[derive(Debug, Error)]
pub enum OtpError {
    #[error("{action} '{path}': {source}")]
    Io {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("invalid pad: {0}")]
    InvalidPad(String),

    #[error("invalid encrypted file: {0}")]
    InvalidEnvelope(String),

    #[error("pad is already consumed or reserved for use")]
    PadAlreadyUsed,

    #[error("wrong pad role: this operation requires a {expected} pad, but the file is {actual}")]
    WrongPadRole { expected: PadRole, actual: PadRole },

    #[error(
        "length mismatch: pad capacity is {pad_bytes} bytes, but the input is {input_bytes} bytes"
    )]
    LengthMismatch { pad_bytes: u64, input_bytes: u64 },

    #[error("the encrypted file belongs to a different pad")]
    WrongPad,

    #[error("authentication failed; the encrypted file or pad is wrong, damaged, or modified")]
    AuthenticationFailed,

    #[error("output already exists; refusing to overwrite '{0}'")]
    OutputExists(PathBuf),

    #[error(
        "pad-pair publication did not complete cleanly after receiver pad '{}' was published; inspect both paths and explicitly destroy any orphan before retrying: {source}",
        receiver.display()
    )]
    PartialPadPair {
        receiver: PathBuf,
        #[source]
        source: Box<OtpError>,
    },

    #[error(
        "output '{}' was published, but its directory could not be synchronized; the path may exist and a consumed pad must not be retried: {source}",
        path.display()
    )]
    PublishedButNotDurable {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("refusing to use the same file as both {0}")]
    SameFile(&'static str),

    #[error("random-number generation failed: {0}")]
    Random(String),

    #[error("invalid size: {0}")]
    InvalidSize(String),

    #[error("no per-user state directory is available; set OTP_STATE_DIR")]
    StateDirectoryUnavailable,

    #[error("refusing to destroy a pad without --yes")]
    ConfirmationRequired,

    #[error("the cryptographic operation completed, but consumed-pad cleanup failed: {0}")]
    Cleanup(String),
}

pub type Result<T> = std::result::Result<T, OtpError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PadRole {
    Sender = 1,
    Receiver = 2,
}

impl fmt::Display for PadRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sender => f.write_str("sender"),
            Self::Receiver => f.write_str("receiver"),
        }
    }
}

impl TryFrom<u8> for PadRole {
    type Error = OtpError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Sender),
            2 => Ok(Self::Receiver),
            other => Err(OtpError::InvalidPad(format!("unknown role value {other}"))),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PadInfo {
    pub id: [u8; KEY_ID_LEN],
    pub capacity: u64,
    pub role: PadRole,
    pub consumed: bool,
}

impl PadInfo {
    pub fn id_hex(&self) -> String {
        hex_encode(&self.id)
    }
}

#[derive(Clone, Debug)]
struct PadHeader {
    id: [u8; KEY_ID_LEN],
    capacity: u64,
    role: PadRole,
    consumed: bool,
}

#[derive(Clone, Debug)]
struct EnvelopeHeader {
    id: [u8; KEY_ID_LEN],
    plaintext_len: u64,
}

/// Entropy source used by pad generation.
///
/// Implementations must fill every requested byte with independent,
/// cryptographically secure randomness. A deterministic implementation is
/// suitable only for tests; using one for a real pad destroys confidentiality.
pub trait RandomSource {
    /// Fill the complete destination or fail without claiming success.
    fn fill(&mut self, destination: &mut [u8]) -> Result<()>;
}

/// Direct operating-system cryptographic random source.
#[derive(Default)]
pub struct OsRandom;

impl RandomSource for OsRandom {
    fn fill(&mut self, destination: &mut [u8]) -> Result<()> {
        getrandom::fill(destination).map_err(|error| OtpError::Random(error.to_string()))
    }
}

fn io_error(action: &'static str, path: &Path, source: io::Error) -> OtpError {
    OtpError::Io {
        action,
        path: path.to_path_buf(),
        source,
    }
}

fn checked_pad_file_len(capacity: u64) -> Result<u64> {
    PAD_FIXED_LEN
        .checked_add(capacity)
        .ok_or_else(|| OtpError::InvalidPad("declared capacity overflows the file size".into()))
}

fn checked_envelope_file_len(plaintext_len: u64) -> Result<u64> {
    ENVELOPE_FIXED_LEN
        .checked_add(plaintext_len)
        .ok_or_else(|| {
            OtpError::InvalidEnvelope("declared plaintext length overflows the file size".into())
        })
}

fn encode_pad_header(header: &PadHeader) -> [u8; PAD_HEADER_LEN] {
    let mut bytes = [0_u8; PAD_HEADER_LEN];
    bytes[0..8].copy_from_slice(PAD_MAGIC);
    bytes[8..10].copy_from_slice(&FORMAT_VERSION.to_be_bytes());
    bytes[10..12].copy_from_slice(&(PAD_HEADER_LEN as u16).to_be_bytes());
    bytes[12..14].copy_from_slice(&SUITE_XOR_HMAC_SHA256.to_be_bytes());
    bytes[14..16].copy_from_slice(&0_u16.to_be_bytes());
    bytes[16] = header.role as u8;
    bytes[17] = u8::from(header.consumed);
    bytes[24..56].copy_from_slice(&header.id);
    bytes[56..64].copy_from_slice(&header.capacity.to_be_bytes());
    bytes
}

fn parse_pad_header(bytes: &[u8; PAD_HEADER_LEN]) -> Result<PadHeader> {
    if &bytes[0..8] != PAD_MAGIC {
        return Err(OtpError::InvalidPad("unrecognized magic bytes".into()));
    }
    if u16::from_be_bytes([bytes[8], bytes[9]]) != FORMAT_VERSION {
        return Err(OtpError::InvalidPad("unsupported format version".into()));
    }
    if u16::from_be_bytes([bytes[10], bytes[11]]) as usize != PAD_HEADER_LEN {
        return Err(OtpError::InvalidPad("invalid header length".into()));
    }
    if u16::from_be_bytes([bytes[12], bytes[13]]) != SUITE_XOR_HMAC_SHA256 {
        return Err(OtpError::InvalidPad("unsupported algorithm suite".into()));
    }
    if bytes[14..16] != [0, 0]
        || bytes[18..24].iter().any(|byte| *byte != 0)
        || bytes[64..80].iter().any(|byte| *byte != 0)
    {
        return Err(OtpError::InvalidPad(
            "reserved fields or flags are not zero".into(),
        ));
    }
    let consumed = match bytes[17] {
        0 => false,
        1 => true,
        other => {
            return Err(OtpError::InvalidPad(format!(
                "unknown consumption state {other}"
            )));
        }
    };
    let role = PadRole::try_from(bytes[16])?;
    let mut id = [0_u8; KEY_ID_LEN];
    id.copy_from_slice(&bytes[24..56]);
    if id.iter().all(|byte| *byte == 0) {
        return Err(OtpError::InvalidPad(
            "the pad identifier is all zero".into(),
        ));
    }
    let capacity = u64::from_be_bytes(bytes[56..64].try_into().expect("fixed slice"));
    Ok(PadHeader {
        id,
        capacity,
        role,
        consumed,
    })
}

fn encode_envelope_header(header: &EnvelopeHeader) -> [u8; ENVELOPE_HEADER_LEN] {
    let mut bytes = [0_u8; ENVELOPE_HEADER_LEN];
    bytes[0..8].copy_from_slice(ENVELOPE_MAGIC);
    bytes[8..10].copy_from_slice(&FORMAT_VERSION.to_be_bytes());
    bytes[10..12].copy_from_slice(&(ENVELOPE_HEADER_LEN as u16).to_be_bytes());
    bytes[12..14].copy_from_slice(&SUITE_XOR_HMAC_SHA256.to_be_bytes());
    bytes[14..16].copy_from_slice(&0_u16.to_be_bytes());
    bytes[16..48].copy_from_slice(&header.id);
    bytes[48..56].copy_from_slice(&header.plaintext_len.to_be_bytes());
    bytes
}

fn parse_envelope_header(bytes: &[u8; ENVELOPE_HEADER_LEN]) -> Result<EnvelopeHeader> {
    if &bytes[0..8] != ENVELOPE_MAGIC {
        return Err(OtpError::InvalidEnvelope("unrecognized magic bytes".into()));
    }
    if u16::from_be_bytes([bytes[8], bytes[9]]) != FORMAT_VERSION {
        return Err(OtpError::InvalidEnvelope(
            "unsupported format version".into(),
        ));
    }
    if u16::from_be_bytes([bytes[10], bytes[11]]) as usize != ENVELOPE_HEADER_LEN {
        return Err(OtpError::InvalidEnvelope("invalid header length".into()));
    }
    if u16::from_be_bytes([bytes[12], bytes[13]]) != SUITE_XOR_HMAC_SHA256 {
        return Err(OtpError::InvalidEnvelope(
            "unsupported algorithm suite".into(),
        ));
    }
    if bytes[14..16] != [0, 0] || bytes[56..64].iter().any(|byte| *byte != 0) {
        return Err(OtpError::InvalidEnvelope(
            "reserved fields or flags are not zero".into(),
        ));
    }
    let mut id = [0_u8; KEY_ID_LEN];
    id.copy_from_slice(&bytes[16..48]);
    if id.iter().all(|byte| *byte == 0) {
        return Err(OtpError::InvalidEnvelope(
            "the pad identifier is all zero".into(),
        ));
    }
    let plaintext_len = u64::from_be_bytes(bytes[48..56].try_into().expect("fixed slice"));
    Ok(EnvelopeHeader { id, plaintext_len })
}

fn read_pad_header(file: &mut File, path: &Path) -> Result<([u8; PAD_HEADER_LEN], PadHeader)> {
    let mut bytes = [0_u8; PAD_HEADER_LEN];
    file.seek(SeekFrom::Start(0))
        .map_err(|error| io_error("seeking pad", path, error))?;
    file.read_exact(&mut bytes).map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            OtpError::InvalidPad("truncated header".into())
        } else {
            io_error("reading pad header", path, error)
        }
    })?;
    let header = parse_pad_header(&bytes)?;
    Ok((bytes, header))
}

fn read_envelope_header(
    file: &mut File,
    path: &Path,
) -> Result<([u8; ENVELOPE_HEADER_LEN], EnvelopeHeader)> {
    let mut bytes = [0_u8; ENVELOPE_HEADER_LEN];
    file.seek(SeekFrom::Start(0))
        .map_err(|error| io_error("seeking encrypted file", path, error))?;
    file.read_exact(&mut bytes).map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            OtpError::InvalidEnvelope("truncated header".into())
        } else {
            io_error("reading encrypted-file header", path, error)
        }
    })?;
    let header = parse_envelope_header(&bytes)?;
    Ok((bytes, header))
}

fn open_regular(path: &Path, writable: bool, description: &'static str) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(writable);
    let file = options
        .open(path)
        .map_err(|error| io_error("opening file", path, error))?;
    let metadata = file
        .metadata()
        .map_err(|error| io_error("reading file metadata", path, error))?;
    if !metadata.is_file() {
        return Err(if description == "pad" {
            OtpError::InvalidPad("path is not a regular file".into())
        } else {
            OtpError::InvalidEnvelope(format!("{description} path is not a regular file"))
        });
    }
    Ok(file)
}

fn open_pad(path: &Path, writable: bool) -> Result<File> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| io_error("checking pad path", path, error))?;
    if metadata.file_type().is_symlink() {
        return Err(OtpError::InvalidPad(
            "symbolic links and reparse-point aliases are not accepted as pad paths".into(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(OtpError::InvalidPad(
                "permissions are too broad; restrict the pad to its owner (chmod 600)".into(),
            ));
        }
    }
    open_regular(path, writable, "pad")
}

fn ensure_distinct(first: &Path, second: &Path, description: &'static str) -> Result<()> {
    match same_file::is_same_file(first, second) {
        Ok(true) => Err(OtpError::SameFile(description)),
        Ok(false) => Ok(()),
        Err(error) => Err(io_error("comparing file identities", first, error)),
    }
}

struct OutputTransaction {
    temp: Option<NamedTempFile>,
    destination: PathBuf,
}

impl OutputTransaction {
    fn new(destination: &Path) -> Result<Self> {
        match fs::symlink_metadata(destination) {
            Ok(_) => return Err(OtpError::OutputExists(destination.to_path_buf())),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(io_error("checking output destination", destination, error));
            }
        }
        let parent = destination
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        if destination.file_name().is_none() {
            return Err(io_error(
                "creating output",
                destination,
                io::Error::new(io::ErrorKind::InvalidInput, "missing file name"),
            ));
        }
        let temp = NamedTempFile::new_in(parent)
            .map_err(|error| io_error("creating temporary output", destination, error))?;
        Ok(Self {
            temp: Some(temp),
            destination: destination.to_path_buf(),
        })
    }

    fn file_mut(&mut self) -> &mut File {
        self.temp
            .as_mut()
            .expect("transaction is open")
            .as_file_mut()
    }

    fn sync(&mut self) -> Result<()> {
        let file = self.file_mut();
        file.flush()
            .and_then(|()| file.sync_all())
            .map_err(|error| io_error("synchronizing temporary output", &self.destination, error))
    }

    fn commit(mut self) -> Result<()> {
        let temp = self.temp.take().expect("transaction is open");
        match temp.persist_noclobber(&self.destination) {
            Ok(_) => {
                sync_parent(&self.destination).map_err(|source| OtpError::PublishedButNotDurable {
                    path: self.destination,
                    source,
                })
            }
            Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => {
                Err(OtpError::OutputExists(self.destination))
            }
            Err(error) => Err(io_error(
                "committing output",
                &self.destination,
                error.error,
            )),
        }
    }
}

fn sync_parent(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let directory = File::open(parent)?;
        directory.sync_all()?;
    }
    // Rust's portable File API cannot open directories with the Windows
    // backup-semantics flag. The newly created file itself is still flushed.
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn normalized_header_for_checksum(header_bytes: &[u8; PAD_HEADER_LEN]) -> [u8; PAD_HEADER_LEN] {
    let mut normalized = *header_bytes;
    normalized[PAD_STATE_OFFSET as usize] = 0;
    normalized
}

fn begin_pad_checksum(header_bytes: &[u8; PAD_HEADER_LEN], authentication_key: &[u8]) -> Sha256 {
    let mut digest = Sha256::new();
    digest.update(PAD_CHECKSUM_DOMAIN);
    digest.update(normalized_header_for_checksum(header_bytes));
    digest.update(authentication_key);
    digest
}

fn verify_exact_pad_checksum(
    digest: Sha256,
    expected: &[u8; PAD_CHECKSUM_LEN as usize],
) -> Result<()> {
    let calculated = digest.finalize();
    if calculated.as_slice().ct_eq(expected).unwrap_u8() != 1 {
        return Err(OtpError::InvalidPad(
            "pad material changed while it was being used".into(),
        ));
    }
    Ok(())
}

fn validate_pad(
    file: &mut File,
    path: &Path,
    header_bytes: &[u8; PAD_HEADER_LEN],
    header: &PadHeader,
) -> Result<Zeroizing<[u8; PAD_CHECKSUM_LEN as usize]>> {
    let actual_len = file
        .metadata()
        .map_err(|error| io_error("reading pad metadata", path, error))?
        .len();
    let expected_len = checked_pad_file_len(header.capacity)?;
    if actual_len != expected_len {
        return Err(OtpError::InvalidPad(format!(
            "file size is {actual_len} bytes; expected {expected_len}"
        )));
    }

    let mut digest = Sha256::new();
    digest.update(PAD_CHECKSUM_DOMAIN);
    digest.update(normalized_header_for_checksum(header_bytes));
    file.seek(SeekFrom::Start(PAD_SECRET_OFFSET))
        .map_err(|error| io_error("seeking pad", path, error))?;
    let mut remaining = AUTH_KEY_LEN as u64 + header.capacity;
    let mut buffer = Zeroizing::new(vec![0_u8; IO_BUFFER_SIZE]);
    while remaining > 0 {
        let amount = usize::try_from(remaining.min(IO_BUFFER_SIZE as u64)).expect("bounded");
        file.read_exact(&mut buffer[..amount])
            .map_err(|error| io_error("reading pad material", path, error))?;
        digest.update(&buffer[..amount]);
        remaining -= amount as u64;
    }
    let mut stored = Zeroizing::new([0_u8; PAD_CHECKSUM_LEN as usize]);
    file.read_exact(&mut stored[..])
        .map_err(|error| io_error("reading pad checksum", path, error))?;
    let calculated = digest.finalize();
    if calculated.as_slice().ct_eq(stored.as_slice()).unwrap_u8() != 1 {
        return Err(OtpError::InvalidPad(
            "secret-material checksum does not match".into(),
        ));
    }
    Ok(stored)
}

pub fn create_pad_pair(
    capacity: u64,
    sender_path: impl AsRef<Path>,
    receiver_path: impl AsRef<Path>,
) -> Result<()> {
    create_pad_pair_with_rng(capacity, sender_path, receiver_path, &mut OsRandom)
}

/// Create a pair using an explicitly supplied cryptographic random source.
///
/// Normal applications should call create_pad_pair, which always uses the
/// operating system. This entry point exists for deterministic format tests and
/// specialized audited integrations.
pub fn create_pad_pair_with_rng<R: RandomSource>(
    capacity: u64,
    sender_path: impl AsRef<Path>,
    receiver_path: impl AsRef<Path>,
    random: &mut R,
) -> Result<()> {
    let sender_path = sender_path.as_ref();
    let receiver_path = receiver_path.as_ref();
    let _ = checked_pad_file_len(capacity)?;

    if sender_path == receiver_path {
        return Err(OtpError::SameFile("sender and receiver pads"));
    }
    let mut sender = OutputTransaction::new(sender_path)?;
    let mut receiver = OutputTransaction::new(receiver_path)?;

    let mut id = Zeroizing::new([0_u8; KEY_ID_LEN]);
    random.fill(&mut id[..])?;
    if id.iter().all(|byte| *byte == 0) {
        return Err(OtpError::Random(
            "the random source returned an all-zero pad identifier".into(),
        ));
    }
    let sender_header = PadHeader {
        id: *id,
        capacity,
        role: PadRole::Sender,
        consumed: false,
    };
    let receiver_header = PadHeader {
        id: *id,
        capacity,
        role: PadRole::Receiver,
        consumed: false,
    };
    let sender_header_bytes = encode_pad_header(&sender_header);
    let receiver_header_bytes = encode_pad_header(&receiver_header);
    sender
        .file_mut()
        .write_all(&sender_header_bytes)
        .map_err(|error| io_error("writing sender pad header", sender_path, error))?;
    receiver
        .file_mut()
        .write_all(&receiver_header_bytes)
        .map_err(|error| io_error("writing receiver pad header", receiver_path, error))?;

    let mut sender_digest = Sha256::new();
    sender_digest.update(PAD_CHECKSUM_DOMAIN);
    sender_digest.update(sender_header_bytes);
    let mut receiver_digest = Sha256::new();
    receiver_digest.update(PAD_CHECKSUM_DOMAIN);
    receiver_digest.update(receiver_header_bytes);

    let mut authentication_key = Zeroizing::new([0_u8; AUTH_KEY_LEN]);
    random.fill(&mut authentication_key[..])?;
    for (transaction, path) in [(&mut sender, sender_path), (&mut receiver, receiver_path)] {
        transaction
            .file_mut()
            .write_all(&authentication_key[..])
            .map_err(|error| io_error("writing authentication key", path, error))?;
    }
    sender_digest.update(&authentication_key[..]);
    receiver_digest.update(&authentication_key[..]);

    let mut remaining = capacity;
    let mut pad_buffer = Zeroizing::new(vec![0_u8; IO_BUFFER_SIZE]);
    while remaining > 0 {
        let amount = usize::try_from(remaining.min(IO_BUFFER_SIZE as u64)).expect("bounded");
        random.fill(&mut pad_buffer[..amount])?;
        sender
            .file_mut()
            .write_all(&pad_buffer[..amount])
            .map_err(|error| io_error("writing sender pad", sender_path, error))?;
        receiver
            .file_mut()
            .write_all(&pad_buffer[..amount])
            .map_err(|error| io_error("writing receiver pad", receiver_path, error))?;
        sender_digest.update(&pad_buffer[..amount]);
        receiver_digest.update(&pad_buffer[..amount]);
        pad_buffer[..amount].zeroize();
        remaining -= amount as u64;
    }

    sender
        .file_mut()
        .write_all(&sender_digest.finalize())
        .map_err(|error| io_error("writing sender pad checksum", sender_path, error))?;
    receiver
        .file_mut()
        .write_all(&receiver_digest.finalize())
        .map_err(|error| io_error("writing receiver pad checksum", receiver_path, error))?;
    sender.sync()?;
    receiver.sync()?;

    receiver.commit()?;
    sender.commit().map_err(|source| OtpError::PartialPadPair {
        receiver: receiver_path.to_path_buf(),
        source: Box::new(source),
    })
}

pub fn inspect_pad(path: impl AsRef<Path>) -> Result<PadInfo> {
    let path = path.as_ref();
    let mut file = open_pad(path, false)?;
    file.lock_shared()
        .map_err(|error| io_error("locking pad", path, error))?;
    let (header_bytes, header) = read_pad_header(&mut file, path)?;
    let _checksum = validate_pad(&mut file, path, &header_bytes, &header)?;
    Ok(PadInfo {
        id: header.id,
        capacity: header.capacity,
        role: header.role,
        consumed: header.consumed,
    })
}

pub fn default_state_directory() -> Result<PathBuf> {
    if let Some(path) = env::var_os("OTP_STATE_DIR")
        && !path.is_empty()
    {
        return Ok(PathBuf::from(path));
    }

    #[cfg(windows)]
    {
        if let Some(base) = env::var_os("LOCALAPPDATA").or_else(|| env::var_os("APPDATA")) {
            return Ok(PathBuf::from(base).join("otp").join("state-v1"));
        }
    }

    #[cfg(not(windows))]
    {
        if let Some(base) = env::var_os("XDG_STATE_HOME") {
            return Ok(PathBuf::from(base).join("otp").join("state-v1"));
        }
        if let Some(home) = env::var_os("HOME") {
            return Ok(PathBuf::from(home)
                .join(".local")
                .join("state")
                .join("otp")
                .join("state-v1"));
        }
    }

    Err(OtpError::StateDirectoryUnavailable)
}

fn ledger_path(state_directory: &Path, id: &[u8; KEY_ID_LEN], role: PadRole) -> PathBuf {
    state_directory.join(format!("{}-{role}.used", hex_encode(id)))
}

fn ensure_state_directory(path: &Path) -> Result<()> {
    fs::create_dir_all(path)
        .map_err(|error| io_error("creating usage-state directory", path, error))?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| io_error("checking usage-state directory", path, error))?;
    if !metadata.file_type().is_dir() {
        return Err(io_error(
            "checking usage-state directory",
            path,
            io::Error::new(io::ErrorKind::InvalidInput, "path is not a directory"),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|error| io_error("securing usage-state directory", path, error))?;
    }
    Ok(())
}

fn secure_create_new(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

fn reserve_usage(state_directory: &Path, id: &[u8; KEY_ID_LEN], role: PadRole) -> Result<()> {
    ensure_state_directory(state_directory)?;
    let path = ledger_path(state_directory, id, role);
    let mut file = match secure_create_new(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            return Err(OtpError::PadAlreadyUsed);
        }
        Err(error) => return Err(io_error("reserving pad usage", &path, error)),
    };

    let mut record = [0_u8; 48];
    record[0..8].copy_from_slice(LEDGER_MAGIC);
    record[8..10].copy_from_slice(&FORMAT_VERSION.to_be_bytes());
    record[10] = role as u8;
    record[16..48].copy_from_slice(id);
    // A partial or corrupt record still means "used": it is deliberately
    // never repaired or rolled back automatically.
    file.write_all(&record)
        .and_then(|()| file.flush())
        .and_then(|()| file.sync_all())
        .map_err(|error| io_error("persisting pad usage reservation", &path, error))?;
    sync_parent(&path)
        .map_err(|error| io_error("synchronizing usage-state directory", &path, error))?;
    Ok(())
}

pub fn is_reserved_in(
    state_directory: impl AsRef<Path>,
    id: &[u8; KEY_ID_LEN],
    role: PadRole,
) -> Result<bool> {
    let state_directory = state_directory.as_ref();
    match fs::symlink_metadata(state_directory) {
        Ok(metadata) if !metadata.file_type().is_dir() => {
            return Err(io_error(
                "checking pad usage-state directory",
                state_directory,
                io::Error::new(io::ErrorKind::InvalidInput, "path is not a directory"),
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(io_error(
                "checking pad usage-state directory",
                state_directory,
                error,
            ));
        }
    }
    let path = ledger_path(state_directory, id, role);
    match fs::symlink_metadata(&path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(io_error("checking pad usage reservation", &path, error)),
    }
}

fn read_authentication_key(file: &mut File, path: &Path) -> Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0_u8; AUTH_KEY_LEN]);
    file.seek(SeekFrom::Start(PAD_SECRET_OFFSET))
        .map_err(|error| io_error("seeking authentication key", path, error))?;
    file.read_exact(&mut key[..])
        .map_err(|error| io_error("reading authentication key", path, error))?;
    Ok(key)
}

fn mark_pad_consumed(file: &mut File, path: &Path) -> Result<()> {
    file.seek(SeekFrom::Start(PAD_STATE_OFFSET))
        .map_err(|error| io_error("seeking pad state", path, error))?;
    file.write_all(&[1])
        .and_then(|()| file.flush())
        .and_then(|()| file.sync_all())
        .map_err(|error| io_error("persisting consumed-pad state", path, error))
}

fn wipe_pad(mut file: File, path: &Path) -> Result<()> {
    let length = file
        .metadata()
        .map_err(|error| {
            OtpError::Cleanup(io_error("reading pad metadata", path, error).to_string())
        })?
        .len();
    let cleanup = (|| -> io::Result<()> {
        file.seek(SeekFrom::Start(0))?;
        let zeros = vec![0_u8; IO_BUFFER_SIZE];
        let mut remaining = length;
        while remaining > 0 {
            let amount = usize::try_from(remaining.min(IO_BUFFER_SIZE as u64)).expect("bounded");
            file.write_all(&zeros[..amount])?;
            remaining -= amount as u64;
        }
        file.flush()?;
        file.sync_all()?;
        file.set_len(0)?;
        file.sync_all()?;
        Ok(())
    })();
    if let Err(error) = cleanup {
        return Err(OtpError::Cleanup(format!(
            "could not overwrite '{}': {error}",
            path.display()
        )));
    }
    Ok(())
}

fn require_fresh_role(header: &PadHeader, expected: PadRole) -> Result<()> {
    if header.role != expected {
        return Err(OtpError::WrongPadRole {
            expected,
            actual: header.role,
        });
    }
    if header.consumed {
        return Err(OtpError::PadAlreadyUsed);
    }
    Ok(())
}

fn read_exact_as(
    reader: &mut impl Read,
    buffer: &mut [u8],
    invalid: impl FnOnce() -> OtpError,
    action: &'static str,
    path: &Path,
) -> Result<()> {
    reader.read_exact(buffer).map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            invalid()
        } else {
            io_error(action, path, error)
        }
    })
}

fn decrypt_file_region(
    input: &mut File,
    pad: &mut File,
    output: &mut File,
    byte_count: u64,
    paths: [&Path; 3],
    ciphertext_mac: &mut HmacSha256,
    pad_digest: &mut Sha256,
) -> Result<()> {
    let [input_path, pad_path, output_path] = paths;
    let mut data = Zeroizing::new(vec![0_u8; IO_BUFFER_SIZE]);
    let mut key = Zeroizing::new(vec![0_u8; IO_BUFFER_SIZE]);
    let mut remaining = byte_count;
    while remaining > 0 {
        let amount = usize::try_from(remaining.min(IO_BUFFER_SIZE as u64)).expect("bounded");
        input
            .read_exact(&mut data[..amount])
            .map_err(|error| io_error("reading input", input_path, error))?;
        pad.read_exact(&mut key[..amount])
            .map_err(|error| io_error("reading pad material", pad_path, error))?;
        ciphertext_mac.update(&data[..amount]);
        pad_digest.update(&key[..amount]);
        for (data_byte, key_byte) in data[..amount].iter_mut().zip(&key[..amount]) {
            *data_byte ^= *key_byte;
        }
        output
            .write_all(&data[..amount])
            .map_err(|error| io_error("writing temporary output", output_path, error))?;
        data[..amount].zeroize();
        key[..amount].zeroize();
        remaining -= amount as u64;
    }
    Ok(())
}

/// XOR two exact-length byte strings.
///
/// This low-level primitive provides no authentication, framing, randomness, or
/// reuse protection. It must not replace encrypt_file for real encryption.
pub fn xor_exact(input: &[u8], pad: &[u8]) -> Result<Vec<u8>> {
    if input.len() != pad.len() {
        return Err(OtpError::LengthMismatch {
            pad_bytes: pad.len() as u64,
            input_bytes: input.len() as u64,
        });
    }
    Ok(input
        .iter()
        .zip(pad)
        .map(|(input_byte, pad_byte)| input_byte ^ pad_byte)
        .collect())
}

pub fn encrypt_file(
    input_path: impl AsRef<Path>,
    pad_path: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
) -> Result<()> {
    let state_directory = default_state_directory()?;
    encrypt_file_with_state(input_path, pad_path, output_path, state_directory)
}

/// Encrypt using an explicit durable reuse-ledger directory.
///
/// Every operation for a given account must keep using the same protected
/// directory. Changing or deleting it creates a new reuse namespace and weakens
/// restored-copy protection.
pub fn encrypt_file_with_state(
    input_path: impl AsRef<Path>,
    pad_path: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
    state_directory: impl AsRef<Path>,
) -> Result<()> {
    let input_path = input_path.as_ref();
    let pad_path = pad_path.as_ref();
    let output_path = output_path.as_ref();
    let state_directory = state_directory.as_ref();
    ensure_distinct(input_path, pad_path, "input and pad")?;

    let mut input = open_regular(input_path, false, "plaintext")?;
    let input_len = input
        .metadata()
        .map_err(|error| io_error("reading input metadata", input_path, error))?
        .len();
    let mut pad = open_pad(pad_path, true)?;
    pad.lock()
        .map_err(|error| io_error("locking pad", pad_path, error))?;
    let (pad_header_bytes, pad_header) = read_pad_header(&mut pad, pad_path)?;
    let expected_pad_checksum = validate_pad(&mut pad, pad_path, &pad_header_bytes, &pad_header)?;
    require_fresh_role(&pad_header, PadRole::Sender)?;
    if pad_header.capacity != input_len {
        return Err(OtpError::LengthMismatch {
            pad_bytes: pad_header.capacity,
            input_bytes: input_len,
        });
    }

    let mut transaction = OutputTransaction::new(output_path)?;
    let authentication_key = read_authentication_key(&mut pad, pad_path)?;
    let envelope_header = EnvelopeHeader {
        id: pad_header.id,
        plaintext_len: input_len,
    };
    let envelope_header_bytes = encode_envelope_header(&envelope_header);

    reserve_usage(state_directory, &pad_header.id, PadRole::Sender)?;
    mark_pad_consumed(&mut pad, pad_path)?;

    (|| -> Result<()> {
        input
            .seek(SeekFrom::Start(0))
            .map_err(|error| io_error("seeking input", input_path, error))?;
        pad.seek(SeekFrom::Start(PAD_BYTES_OFFSET))
            .map_err(|error| io_error("seeking pad material", pad_path, error))?;
        transaction
            .file_mut()
            .write_all(&envelope_header_bytes)
            .map_err(|error| io_error("writing encrypted-file header", output_path, error))?;

        let mut mac =
            HmacSha256::new_from_slice(&authentication_key[..]).expect("HMAC accepts any key size");
        mac.update(ENVELOPE_AUTH_DOMAIN);
        mac.update(&envelope_header_bytes);
        let mut exact_pad_digest = begin_pad_checksum(&pad_header_bytes, &authentication_key[..]);

        let mut plaintext = Zeroizing::new(vec![0_u8; IO_BUFFER_SIZE]);
        let mut key = Zeroizing::new(vec![0_u8; IO_BUFFER_SIZE]);
        let mut remaining = input_len;
        while remaining > 0 {
            let amount = usize::try_from(remaining.min(IO_BUFFER_SIZE as u64)).expect("bounded");
            input
                .read_exact(&mut plaintext[..amount])
                .map_err(|error| io_error("reading plaintext", input_path, error))?;
            pad.read_exact(&mut key[..amount])
                .map_err(|error| io_error("reading pad material", pad_path, error))?;
            exact_pad_digest.update(&key[..amount]);
            for (plain_byte, key_byte) in plaintext[..amount].iter_mut().zip(&key[..amount]) {
                *plain_byte ^= *key_byte;
            }
            transaction
                .file_mut()
                .write_all(&plaintext[..amount])
                .map_err(|error| io_error("writing ciphertext", output_path, error))?;
            mac.update(&plaintext[..amount]);
            plaintext[..amount].zeroize();
            key[..amount].zeroize();
            remaining -= amount as u64;
        }
        let mut extra = [0_u8; 1];
        if input
            .read(&mut extra)
            .map_err(|error| io_error("checking plaintext length", input_path, error))?
            != 0
        {
            return Err(OtpError::LengthMismatch {
                pad_bytes: pad_header.capacity,
                input_bytes: pad_header.capacity.saturating_add(1),
            });
        }
        verify_exact_pad_checksum(exact_pad_digest, &expected_pad_checksum)?;
        let tag = mac.finalize().into_bytes();
        transaction
            .file_mut()
            .write_all(&tag)
            .map_err(|error| io_error("writing authentication tag", output_path, error))?;
        transaction.sync()?;
        transaction.commit()
    })()
}

fn authenticate_envelope(
    encrypted: &mut File,
    encrypted_path: &Path,
    header_bytes: &[u8; ENVELOPE_HEADER_LEN],
    header: &EnvelopeHeader,
    authentication_key: &[u8],
) -> Result<()> {
    encrypted
        .seek(SeekFrom::Start(ENVELOPE_HEADER_LEN as u64))
        .map_err(|error| io_error("seeking ciphertext", encrypted_path, error))?;
    let mut mac =
        HmacSha256::new_from_slice(authentication_key).expect("HMAC accepts any key size");
    mac.update(ENVELOPE_AUTH_DOMAIN);
    mac.update(header_bytes);
    let mut remaining = header.plaintext_len;
    let mut buffer = vec![0_u8; IO_BUFFER_SIZE];
    while remaining > 0 {
        let amount = usize::try_from(remaining.min(IO_BUFFER_SIZE as u64)).expect("bounded");
        read_exact_as(
            encrypted,
            &mut buffer[..amount],
            || OtpError::InvalidEnvelope("truncated ciphertext".into()),
            "reading ciphertext",
            encrypted_path,
        )?;
        mac.update(&buffer[..amount]);
        remaining -= amount as u64;
    }
    let mut tag = [0_u8; TAG_LEN];
    read_exact_as(
        encrypted,
        &mut tag,
        || OtpError::InvalidEnvelope("truncated authentication tag".into()),
        "reading authentication tag",
        encrypted_path,
    )?;
    mac.verify_slice(&tag)
        .map_err(|_| OtpError::AuthenticationFailed)
}

pub fn decrypt_file(
    input_path: impl AsRef<Path>,
    pad_path: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
) -> Result<()> {
    let state_directory = default_state_directory()?;
    decrypt_file_with_state(input_path, pad_path, output_path, state_directory)
}

/// Decrypt using an explicit durable reuse-ledger directory.
///
/// This must be the same stable, protected directory used for the lifetime of
/// the pad. Authentication failure occurs before receiver usage is reserved.
pub fn decrypt_file_with_state(
    input_path: impl AsRef<Path>,
    pad_path: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
    state_directory: impl AsRef<Path>,
) -> Result<()> {
    let input_path = input_path.as_ref();
    let pad_path = pad_path.as_ref();
    let output_path = output_path.as_ref();
    let state_directory = state_directory.as_ref();
    ensure_distinct(input_path, pad_path, "encrypted input and pad")?;

    let mut encrypted = open_regular(input_path, false, "encrypted input")?;
    let encrypted_len = encrypted
        .metadata()
        .map_err(|error| io_error("reading encrypted-file metadata", input_path, error))?
        .len();
    let (envelope_header_bytes, envelope_header) =
        read_envelope_header(&mut encrypted, input_path)?;
    let expected_encrypted_len = checked_envelope_file_len(envelope_header.plaintext_len)?;
    if encrypted_len != expected_encrypted_len {
        return Err(OtpError::InvalidEnvelope(format!(
            "file size is {encrypted_len} bytes; expected {expected_encrypted_len}"
        )));
    }

    let mut pad = open_pad(pad_path, true)?;
    pad.lock()
        .map_err(|error| io_error("locking pad", pad_path, error))?;
    let (pad_header_bytes, pad_header) = read_pad_header(&mut pad, pad_path)?;
    let expected_pad_checksum = validate_pad(&mut pad, pad_path, &pad_header_bytes, &pad_header)?;
    require_fresh_role(&pad_header, PadRole::Receiver)?;
    if envelope_header.id != pad_header.id {
        return Err(OtpError::WrongPad);
    }
    if envelope_header.plaintext_len != pad_header.capacity {
        return Err(OtpError::LengthMismatch {
            pad_bytes: pad_header.capacity,
            input_bytes: envelope_header.plaintext_len,
        });
    }
    let authentication_key = read_authentication_key(&mut pad, pad_path)?;
    authenticate_envelope(
        &mut encrypted,
        input_path,
        &envelope_header_bytes,
        &envelope_header,
        &authentication_key[..],
    )?;

    let mut transaction = OutputTransaction::new(output_path)?;
    reserve_usage(state_directory, &pad_header.id, PadRole::Receiver)?;
    mark_pad_consumed(&mut pad, pad_path)?;

    encrypted
        .seek(SeekFrom::Start(ENVELOPE_HEADER_LEN as u64))
        .map_err(|error| io_error("seeking ciphertext", input_path, error))?;
    pad.seek(SeekFrom::Start(PAD_BYTES_OFFSET))
        .map_err(|error| io_error("seeking pad material", pad_path, error))?;

    let mut second_pass_mac =
        HmacSha256::new_from_slice(&authentication_key[..]).expect("HMAC accepts any key size");
    second_pass_mac.update(ENVELOPE_AUTH_DOMAIN);
    second_pass_mac.update(&envelope_header_bytes);
    let mut exact_pad_digest = begin_pad_checksum(&pad_header_bytes, &authentication_key[..]);

    decrypt_file_region(
        &mut encrypted,
        &mut pad,
        transaction.file_mut(),
        envelope_header.plaintext_len,
        [input_path, pad_path, output_path],
        &mut second_pass_mac,
        &mut exact_pad_digest,
    )?;
    let mut second_pass_tag = [0_u8; TAG_LEN];
    read_exact_as(
        &mut encrypted,
        &mut second_pass_tag,
        || OtpError::InvalidEnvelope("truncated authentication tag".into()),
        "reading authentication tag",
        input_path,
    )?;
    second_pass_mac
        .verify_slice(&second_pass_tag)
        .map_err(|_| OtpError::AuthenticationFailed)?;
    verify_exact_pad_checksum(exact_pad_digest, &expected_pad_checksum)?;
    transaction.sync()?;
    transaction.commit()
}

pub fn destroy_pad(path: impl AsRef<Path>) -> Result<()> {
    let path = path.as_ref();
    let mut file = open_pad(path, true)?;
    file.lock()
        .map_err(|error| io_error("locking pad", path, error))?;
    let (header_bytes, header) = read_pad_header(&mut file, path)?;
    let _checksum = validate_pad(&mut file, path, &header_bytes, &header)?;
    wipe_pad(file, path)
}

pub fn file_length(path: impl AsRef<Path>) -> Result<u64> {
    let path = path.as_ref();
    let metadata =
        fs::metadata(path).map_err(|error| io_error("reading file metadata", path, error))?;
    if !metadata.is_file() {
        return Err(io_error(
            "reading file metadata",
            path,
            io::Error::new(io::ErrorKind::InvalidInput, "path is not a regular file"),
        ));
    }
    Ok(metadata.len())
}

pub fn parse_size(text: &str) -> std::result::Result<u64, String> {
    let text = text.trim();
    if text.is_empty() {
        return Err("size cannot be empty".into());
    }
    let digit_end = text
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(text.len());
    if digit_end == 0 {
        return Err(format!(
            "'{text}' does not begin with a non-negative integer"
        ));
    }
    let number: u64 = text[..digit_end]
        .parse()
        .map_err(|_| format!("'{text}' contains an invalid integer"))?;
    let unit = text[digit_end..].trim().to_ascii_lowercase();
    let multiplier = match unit.as_str() {
        "" | "b" => 1_u64,
        "kb" => 1_000,
        "mb" => 1_000_000,
        "gb" => 1_000_000_000,
        "tb" => 1_000_000_000_000,
        "kib" => 1 << 10,
        "mib" => 1 << 20,
        "gib" => 1 << 30,
        "tib" => 1_u64 << 40,
        _ => {
            return Err(format!(
                "unknown unit '{unit}'; use B, KB, MB, GB, TB, KiB, MiB, GiB, or TiB"
            ));
        }
    };
    number
        .checked_mul(multiplier)
        .ok_or_else(|| format!("'{text}' is too large"))
}

pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}
