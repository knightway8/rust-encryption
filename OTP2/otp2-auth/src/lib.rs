//! Linux-only detached authentication for arbitrary regular files.
//!
//! The input file is never modified. A fixed-size sidecar contains a
//! versioned header and an HMAC-SHA-256 tag over that header and the exact file
//! bytes. The secret authentication key remains separate from both files.

#[cfg(not(target_os = "linux"))]
compile_error!("otp2-auth supports Linux targets only");

use std::env;
use std::error::Error;
use std::ffi::{CString, OsStr, OsString};
use std::fmt;
use std::fs::{self, File, Metadata, OpenOptions, Permissions};
use std::io::{self, Read, Seek, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::SystemTime;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

/// The secret key filename expected beside the running executable.
pub const AUTH_KEY_FILE_NAME: &str = "auth.key";
/// The suffix used when no explicit sidecar path is supplied.
pub const TAG_SUFFIX: &str = ".otp2auth";
/// The required raw authentication-key length.
pub const AUTH_KEY_LENGTH: usize = 32;
/// The canonical detached-tag header length.
pub const HEADER_LENGTH: usize = 32;
/// The full HMAC-SHA-256 tag length.
pub const TAG_LENGTH: usize = 32;
/// The exact length of every version-one sidecar.
pub const TAG_FILE_LENGTH: usize = HEADER_LENGTH + TAG_LENGTH;

const MAGIC: &[u8; 8] = b"otp2TAG\0";
const VERSION: u16 = 1;
const FLAGS: u32 = 0;
const RESERVED: u64 = 0;
const MAC_DOMAIN: &[u8] = b"otp2-auth/detached/v1\0";
const STREAM_BUFFER_SIZE: usize = 64 * 1024;
const TEMP_CREATE_ATTEMPTS: usize = 256;
static TEMP_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

type HmacSha256 = Hmac<Sha256>;

/// Result of durably creating or replacing a filesystem entry.
#[derive(Debug)]
pub enum AuthOutcome {
    /// The entry and its containing directory were synchronized.
    Committed,
    /// The entry was committed, but a syscall result or directory
    /// synchronization did not confirm crash durability.
    ///
    /// The caller must inspect the resulting path instead of retrying blindly.
    CommittedButDurabilityUncertain(io::Error),
}

/// A detached-authentication error.
#[derive(Debug)]
pub enum AuthError {
    Io {
        action: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    InvalidFile {
        role: &'static str,
        path: PathBuf,
        reason: &'static str,
    },
    InvalidKeyLength {
        path: PathBuf,
        actual: u64,
    },
    FileIsKey {
        file_path: PathBuf,
        key_path: PathBuf,
    },
    FileAndTagAlias {
        file_path: PathBuf,
        tag_path: PathBuf,
    },
    TagIsKey {
        tag_path: PathBuf,
        key_path: PathBuf,
    },
    TagAlreadyExists {
        path: PathBuf,
    },
    InvalidTag {
        path: PathBuf,
        reason: &'static str,
    },
    AuthenticationFailed {
        file_path: PathBuf,
        tag_path: PathBuf,
    },
    ConcurrentModification {
        path: PathBuf,
    },
    StagedTagInvalid {
        path: PathBuf,
    },
    CommitOutcomeUncertain {
        role: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    NoExecutableDirectory {
        executable: PathBuf,
    },
}

impl AuthError {
    fn io(action: &'static str, path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::Io {
            action,
            path: path.into(),
            source,
        }
    }

    fn invalid_tag(path: &Path, reason: &'static str) -> Self {
        Self::InvalidTag {
            path: path.to_path_buf(),
            reason,
        }
    }

    /// Whether this error means that no valid authentication statement was
    /// established for the supplied file.
    pub fn is_authentication_failure(&self) -> bool {
        matches!(
            self,
            Self::InvalidTag { .. } | Self::AuthenticationFailed { .. }
        )
    }
}

impl fmt::Display for AuthError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io {
                action,
                path,
                source,
            } => write!(formatter, "{action} '{}': {source}", path.display()),
            Self::InvalidFile { role, path, reason } => {
                write!(formatter, "{role} '{}' {reason}", path.display())
            }
            Self::InvalidKeyLength { path, actual } => write!(
                formatter,
                "authentication key '{}' must contain exactly {AUTH_KEY_LENGTH} raw bytes, but it has {actual}",
                path.display()
            ),
            Self::FileIsKey {
                file_path,
                key_path,
            } => write!(
                formatter,
                "file '{}' and authentication key '{}' refer to the same file",
                file_path.display(),
                key_path.display()
            ),
            Self::FileAndTagAlias {
                file_path,
                tag_path,
            } => write!(
                formatter,
                "file '{}' and sidecar '{}' refer to the same file",
                file_path.display(),
                tag_path.display()
            ),
            Self::TagIsKey { tag_path, key_path } => write!(
                formatter,
                "sidecar '{}' and authentication key '{}' refer to the same file",
                tag_path.display(),
                key_path.display()
            ),
            Self::TagAlreadyExists { path } => write!(
                formatter,
                "sidecar '{}' already exists; use --replace to replace an existing regular sidecar",
                path.display()
            ),
            Self::InvalidTag { path, reason } => {
                write!(
                    formatter,
                    "sidecar '{}' is invalid: {reason}",
                    path.display()
                )
            }
            Self::AuthenticationFailed {
                file_path,
                tag_path,
            } => write!(
                formatter,
                "authentication failed for '{}' using sidecar '{}'",
                file_path.display(),
                tag_path.display()
            ),
            Self::ConcurrentModification { path } => write!(
                formatter,
                "'{}' changed while it was being authenticated; no reliable result was produced",
                path.display()
            ),
            Self::StagedTagInvalid { path } => write!(
                formatter,
                "synchronized temporary sidecar '{}' failed read-back validation",
                path.display()
            ),
            Self::CommitOutcomeUncertain { role, path, source } => write!(
                formatter,
                "the commit outcome for {role} '{}' could not be determined: {source}; DO NOT RETRY automatically—inspect both the destination and temporary entries first",
                path.display()
            ),
            Self::NoExecutableDirectory { executable } => write!(
                formatter,
                "cannot determine the directory containing executable '{}'",
                executable.display()
            ),
        }
    }
}

impl Error for AuthError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } | Self::CommitOutcomeUncertain { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Return the `auth.key` path beside the executable reported by Linux.
pub fn auth_key_path_next_to_current_exe() -> Result<PathBuf, AuthError> {
    let executable = env::current_exe().map_err(|source| {
        AuthError::io("cannot locate the running executable", "otp2-auth", source)
    })?;
    let directory = executable
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or_else(|| AuthError::NoExecutableDirectory {
            executable: executable.clone(),
        })?;
    Ok(directory.join(AUTH_KEY_FILE_NAME))
}

/// Append `.otp2auth` to a file path without requiring UTF-8.
pub fn default_tag_path(file_path: impl AsRef<Path>) -> Result<PathBuf, AuthError> {
    let file_path = file_path.as_ref();
    validate_terminal_name(file_path, "file")?;
    let mut path = file_path.as_os_str().to_os_string();
    path.push(TAG_SUFFIX);
    Ok(PathBuf::from(path))
}

/// Generate a fresh 32-byte `auth.key` beside the running executable.
///
/// An existing path is never followed or replaced. The new key is mode 0600,
/// synchronized, effective-user-owned, and single-linked before success.
pub fn generate_key_next_to_current_exe() -> Result<AuthOutcome, AuthError> {
    let key_path = anchor_path(&auth_key_path_next_to_current_exe()?, "authentication key")?;
    let parent = usable_parent(&key_path);
    let directory = ParentDirectory::open(parent).map_err(|source| {
        AuthError::io("cannot open authentication-key directory", parent, source)
    })?;

    let mut key = Zeroizing::new([0_u8; AUTH_KEY_LENGTH]);
    getrandom::fill(key.as_mut()).map_err(|source| {
        AuthError::io(
            "cannot obtain operating-system randomness",
            &key_path,
            io::Error::other(source.to_string()),
        )
    })?;

    let mut temporary = SiblingTemp::create(&directory).map_err(|source| {
        AuthError::io("cannot create temporary authentication key", parent, source)
    })?;

    let result = (|| -> io::Result<()> {
        temporary
            .file
            .set_permissions(Permissions::from_mode(0o600))?;
        temporary.file.write_all(key.as_ref())?;
        temporary.file.flush()?;
        temporary.file.sync_all()?;
        Ok(())
    })();
    if let Err(source) = result {
        return Err(AuthError::io(
            "cannot write and synchronize temporary authentication key",
            &temporary.path,
            source,
        ));
    }

    let metadata = temporary.file.metadata().map_err(|source| {
        AuthError::io(
            "cannot inspect temporary authentication key",
            &temporary.path,
            source,
        )
    })?;
    let snapshot = FileSnapshot::from_metadata(&metadata);
    let valid = snapshot.len == AUTH_KEY_LENGTH as u64
        && snapshot.links == 1
        && snapshot.uid == effective_uid()
        && snapshot.mode & 0o777 == 0o600
        && snapshot.identity() == temporary.identity;
    if !valid {
        return Err(AuthError::ConcurrentModification {
            path: temporary.path.clone(),
        });
    }
    ensure_path_identity(&temporary.directory, &temporary.path, temporary.identity)?;

    let commit_warning =
        match temporary.commit(&key_path, DestinationExpectation::Absent, &snapshot) {
            Ok(warning) => warning,
            Err(CommitFailure::NotCommitted(source)) => {
                return Err(AuthError::io(
                    "cannot publish authentication key (existing paths are never replaced)",
                    &key_path,
                    source,
                ));
            }
            Err(CommitFailure::OutcomeUncertain(source)) => {
                return Err(AuthError::CommitOutcomeUncertain {
                    role: "authentication key",
                    path: key_path,
                    source,
                });
            }
        };
    Ok(committed_outcome(
        "authentication key",
        commit_warning,
        directory.sync(),
    ))
}

/// Create a detached sidecar for an arbitrary regular file.
///
/// The input is streamed and never modified. If `replace` is false, an
/// existing sidecar is never overwritten. If it is true, only an existing
/// regular, non-symlink, single-linked sidecar may be atomically replaced.
pub fn create_tag(
    file_path: impl AsRef<Path>,
    tag_path: impl AsRef<Path>,
    key_path: impl AsRef<Path>,
    replace: bool,
) -> Result<AuthOutcome, AuthError> {
    let file_path = anchor_path(file_path.as_ref(), "file")?;
    let tag_path = anchor_path(tag_path.as_ref(), "sidecar")?;
    let key_path = anchor_path(key_path.as_ref(), "authentication key")?;

    let mut input = OpenRegular::open("file", &file_path)?;
    let key = OpenAuthKey::open(&key_path)?;
    reject_file_key_alias(&input, &key)?;

    let tag_directory = ParentDirectory::open(usable_parent(&tag_path)).map_err(|source| {
        AuthError::io(
            "cannot open sidecar directory",
            usable_parent(&tag_path),
            source,
        )
    })?;
    let destination = inspect_destination(&tag_directory, &tag_path, replace)?;
    if let DestinationExpectation::Present { identity, links } = destination {
        if links > 1 {
            return Err(AuthError::InvalidFile {
                role: "existing sidecar",
                path: tag_path,
                reason: "must not have multiple hard links",
            });
        }
        reject_tag_aliases(
            &file_path,
            input.snapshot.identity(),
            &tag_path,
            identity,
            &key,
        )?;
    }

    input.recheck()?;
    key.recheck()?;
    let header = encode_header(input.snapshot.len);
    let mut mac = new_mac(key.bytes.as_ref());
    mac.update(MAC_DOMAIN);
    mac.update(&header);

    let mut temporary = SiblingTemp::create(&tag_directory).map_err(|source| {
        AuthError::io(
            "cannot create temporary sidecar",
            usable_parent(&tag_path),
            source,
        )
    })?;
    temporary
        .file
        .write_all(&header)
        .map_err(|source| AuthError::io("cannot write sidecar header", &temporary.path, source))?;

    stream_file_into_mac(&mut input.file, input.snapshot.len, &mut mac, &file_path)?;
    ensure_no_extra_bytes(&mut input.file, &file_path, "file")?;
    input.recheck()?;
    key.recheck()?;

    let computed = mac.finalize().into_bytes();
    let mut tag = [0_u8; TAG_LENGTH];
    tag.copy_from_slice(&computed);
    temporary.file.write_all(&tag).map_err(|source| {
        AuthError::io("cannot write authentication tag", &temporary.path, source)
    })?;
    temporary
        .file
        .set_permissions(Permissions::from_mode(0o600))
        .map_err(|source| {
            AuthError::io("cannot set sidecar permissions", &temporary.path, source)
        })?;
    temporary.file.flush().map_err(|source| {
        AuthError::io("cannot flush temporary sidecar", &temporary.path, source)
    })?;
    temporary.file.sync_all().map_err(|source| {
        AuthError::io(
            "cannot synchronize temporary sidecar",
            &temporary.path,
            source,
        )
    })?;
    let staged_snapshot = validate_staged_tag(&mut temporary, &header, &tag)?;

    input.recheck()?;
    key.recheck()?;
    recheck_staged_tag(&temporary, &staged_snapshot)?;
    let commit_warning = match temporary.commit(&tag_path, destination, &staged_snapshot) {
        Ok(warning) => warning,
        Err(CommitFailure::NotCommitted(source)) => {
            if matches!(destination, DestinationExpectation::Absent)
                && source.raw_os_error() == Some(libc::EEXIST)
            {
                return Err(AuthError::TagAlreadyExists { path: tag_path });
            }
            return Err(AuthError::io("cannot commit sidecar", &tag_path, source));
        }
        Err(CommitFailure::OutcomeUncertain(source)) => {
            return Err(AuthError::CommitOutcomeUncertain {
                role: "sidecar",
                path: tag_path,
                source,
            });
        }
    };

    Ok(committed_outcome(
        "sidecar",
        commit_warning,
        tag_directory.sync(),
    ))
}

fn committed_outcome(
    role: &'static str,
    commit_warning: Option<io::Error>,
    directory_sync: io::Result<()>,
) -> AuthOutcome {
    match (commit_warning, directory_sync) {
        (None, Ok(())) => AuthOutcome::Committed,
        (None, Err(source)) | (Some(source), Ok(())) => {
            AuthOutcome::CommittedButDurabilityUncertain(source)
        }
        (Some(commit_source), Err(sync_source)) => {
            AuthOutcome::CommittedButDurabilityUncertain(io::Error::other(format!(
                "renameat2 reported an error after the new {role} appeared at its destination ({commit_source}); directory synchronization also failed ({sync_source})"
            )))
        }
    }
}

/// Verify a file against a detached sidecar without modifying either path.
pub fn verify_file(
    file_path: impl AsRef<Path>,
    tag_path: impl AsRef<Path>,
    key_path: impl AsRef<Path>,
) -> Result<(), AuthError> {
    let file_path = anchor_path(file_path.as_ref(), "file")?;
    let tag_path = anchor_path(tag_path.as_ref(), "sidecar")?;
    let key_path = anchor_path(key_path.as_ref(), "authentication key")?;

    let mut input = OpenRegular::open("file", &file_path)?;
    let mut sidecar = OpenRegular::open("sidecar", &tag_path)?;
    let key = OpenAuthKey::open(&key_path)?;

    reject_file_key_alias(&input, &key)?;
    reject_tag_aliases(
        &file_path,
        input.snapshot.identity(),
        &tag_path,
        sidecar.snapshot.identity(),
        &key,
    )?;

    let parsed = read_tag(&mut sidecar.file, sidecar.snapshot.len, &tag_path)?;
    if parsed.file_len != input.snapshot.len {
        return Err(AuthError::invalid_tag(
            &tag_path,
            "declared file length does not match the supplied file",
        ));
    }

    let mut mac = new_mac(key.bytes.as_ref());
    mac.update(MAC_DOMAIN);
    mac.update(&parsed.header);
    stream_file_into_mac(&mut input.file, input.snapshot.len, &mut mac, &file_path)?;
    ensure_no_extra_bytes(&mut input.file, &file_path, "file")?;

    input.recheck()?;
    sidecar.recheck()?;
    key.recheck()?;
    mac.verify_slice(&parsed.tag)
        .map_err(|_| AuthError::AuthenticationFailed {
            file_path,
            tag_path,
        })
}

#[derive(Clone, Copy, Debug)]
struct ParsedTag {
    header: [u8; HEADER_LENGTH],
    file_len: u64,
    tag: [u8; TAG_LENGTH],
}

fn encode_header(file_len: u64) -> [u8; HEADER_LENGTH] {
    let mut header = [0_u8; HEADER_LENGTH];
    header[..8].copy_from_slice(MAGIC);
    header[8..10].copy_from_slice(&VERSION.to_be_bytes());
    header[10..12].copy_from_slice(&(HEADER_LENGTH as u16).to_be_bytes());
    header[12..16].copy_from_slice(&FLAGS.to_be_bytes());
    header[16..24].copy_from_slice(&file_len.to_be_bytes());
    header[24..32].copy_from_slice(&RESERVED.to_be_bytes());
    header
}

fn parse_header(header: [u8; HEADER_LENGTH], path: &Path) -> Result<u64, AuthError> {
    if &header[..8] != MAGIC {
        return Err(AuthError::invalid_tag(path, "marker is missing"));
    }
    if u16::from_be_bytes([header[8], header[9]]) != VERSION {
        return Err(AuthError::invalid_tag(path, "version is unsupported"));
    }
    if u16::from_be_bytes([header[10], header[11]]) != HEADER_LENGTH as u16 {
        return Err(AuthError::invalid_tag(
            path,
            "header length is not canonical",
        ));
    }
    if u32::from_be_bytes(header[12..16].try_into().expect("fixed slice")) != FLAGS {
        return Err(AuthError::invalid_tag(path, "flags are unsupported"));
    }
    if u64::from_be_bytes(header[24..32].try_into().expect("fixed slice")) != RESERVED {
        return Err(AuthError::invalid_tag(path, "reserved fields are nonzero"));
    }
    Ok(u64::from_be_bytes(
        header[16..24].try_into().expect("fixed slice"),
    ))
}

fn read_tag(file: &mut File, file_len: u64, path: &Path) -> Result<ParsedTag, AuthError> {
    if file_len != TAG_FILE_LENGTH as u64 {
        return Err(AuthError::invalid_tag(
            path,
            "length is not the canonical 64 bytes",
        ));
    }
    let mut bytes = [0_u8; TAG_FILE_LENGTH];
    match file.read_exact(&mut bytes) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
            return Err(AuthError::ConcurrentModification {
                path: path.to_path_buf(),
            });
        }
        Err(source) => {
            return Err(AuthError::io("cannot read complete sidecar", path, source));
        }
    }
    ensure_no_extra_bytes(file, path, "sidecar")?;
    let mut header = [0_u8; HEADER_LENGTH];
    header.copy_from_slice(&bytes[..HEADER_LENGTH]);
    let file_len = parse_header(header, path)?;
    let mut tag = [0_u8; TAG_LENGTH];
    tag.copy_from_slice(&bytes[HEADER_LENGTH..]);
    Ok(ParsedTag {
        header,
        file_len,
        tag,
    })
}

fn new_mac(key: &[u8]) -> HmacSha256 {
    HmacSha256::new_from_slice(key).expect("HMAC accepts a 32-byte key")
}

fn stream_file_into_mac(
    file: &mut File,
    length: u64,
    mac: &mut HmacSha256,
    path: &Path,
) -> Result<(), AuthError> {
    let mut buffer = Zeroizing::new([0_u8; STREAM_BUFFER_SIZE]);
    let mut remaining = length;
    while remaining != 0 {
        let amount = usize::try_from(remaining.min(STREAM_BUFFER_SIZE as u64))
            .expect("bounded chunk fits usize");
        match file.read_exact(&mut buffer[..amount]) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                return Err(AuthError::ConcurrentModification {
                    path: path.to_path_buf(),
                });
            }
            Err(source) => return Err(AuthError::io("cannot read complete file", path, source)),
        }
        mac.update(&buffer[..amount]);
        remaining -= amount as u64;
    }
    Ok(())
}

fn ensure_no_extra_bytes(
    file: &mut File,
    path: &Path,
    role: &'static str,
) -> Result<(), AuthError> {
    let mut byte = [0_u8; 1];
    loop {
        match file.read(&mut byte) {
            Ok(0) => return Ok(()),
            Ok(_) => {
                return Err(AuthError::ConcurrentModification {
                    path: path.to_path_buf(),
                });
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(source) => {
                let action = if role == "authentication key" {
                    "cannot verify final authentication-key length"
                } else {
                    "cannot verify final file length"
                };
                return Err(AuthError::io(action, path, source));
            }
        }
    }
}

fn validate_staged_tag(
    temporary: &mut SiblingTemp,
    expected_header: &[u8; HEADER_LENGTH],
    expected_tag: &[u8; TAG_LENGTH],
) -> Result<FileSnapshot, AuthError> {
    let metadata = temporary.file.metadata().map_err(|source| {
        AuthError::io("cannot inspect temporary sidecar", &temporary.path, source)
    })?;
    let snapshot = FileSnapshot::from_metadata(&metadata);
    let valid_metadata = snapshot.len == TAG_FILE_LENGTH as u64
        && snapshot.links == 1
        && snapshot.mode & 0o777 == 0o600
        && snapshot.identity() == temporary.identity;
    if !valid_metadata {
        return Err(AuthError::StagedTagInvalid {
            path: temporary.path.clone(),
        });
    }
    recheck_staged_tag(temporary, &snapshot)?;
    temporary.file.rewind().map_err(|source| {
        AuthError::io("cannot rewind temporary sidecar", &temporary.path, source)
    })?;
    let mut actual = [0_u8; TAG_FILE_LENGTH];
    match temporary.file.read_exact(&mut actual) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
            return Err(AuthError::StagedTagInvalid {
                path: temporary.path.clone(),
            });
        }
        Err(source) => {
            return Err(AuthError::io(
                "cannot read back temporary sidecar",
                &temporary.path,
                source,
            ));
        }
    }
    let valid =
        &actual[..HEADER_LENGTH] == expected_header && &actual[HEADER_LENGTH..] == expected_tag;
    if !valid {
        return Err(AuthError::StagedTagInvalid {
            path: temporary.path.clone(),
        });
    }
    if let Err(error) = ensure_no_extra_bytes(&mut temporary.file, &temporary.path, "sidecar") {
        return match error {
            AuthError::ConcurrentModification { .. } => Err(AuthError::StagedTagInvalid {
                path: temporary.path.clone(),
            }),
            other => Err(other),
        };
    }
    recheck_staged_tag(temporary, &snapshot)?;
    Ok(snapshot)
}

fn recheck_staged_tag(temporary: &SiblingTemp, expected: &FileSnapshot) -> Result<(), AuthError> {
    let metadata = temporary.file.metadata().map_err(|source| {
        AuthError::io("cannot recheck temporary sidecar", &temporary.path, source)
    })?;
    if FileSnapshot::from_metadata(&metadata) != *expected {
        return Err(AuthError::StagedTagInvalid {
            path: temporary.path.clone(),
        });
    }
    let current = temporary
        .directory
        .identity_at(&temporary.path)
        .map_err(|source| {
            AuthError::io(
                "cannot recheck temporary sidecar path",
                &temporary.path,
                source,
            )
        })?;
    if current != Some(temporary.identity) {
        return Err(AuthError::StagedTagInvalid {
            path: temporary.path.clone(),
        });
    }
    Ok(())
}

struct OpenAuthKey {
    regular: OpenRegular,
    bytes: Zeroizing<[u8; AUTH_KEY_LENGTH]>,
}

impl OpenAuthKey {
    fn open(path: &Path) -> Result<Self, AuthError> {
        let mut regular = OpenRegular::open("authentication key", path)?;
        if regular.snapshot.links > 1 {
            return Err(AuthError::InvalidFile {
                role: "authentication key",
                path: path.to_path_buf(),
                reason: "must not have multiple hard links",
            });
        }
        if regular.snapshot.len != AUTH_KEY_LENGTH as u64 {
            return Err(AuthError::InvalidKeyLength {
                path: path.to_path_buf(),
                actual: regular.snapshot.len,
            });
        }
        if let Some(reason) = key_security_rejection_reason(
            regular.snapshot.mode,
            regular.snapshot.uid,
            effective_uid(),
        ) {
            return Err(AuthError::InvalidFile {
                role: "authentication key",
                path: path.to_path_buf(),
                reason,
            });
        }
        let mut bytes = Zeroizing::new([0_u8; AUTH_KEY_LENGTH]);
        match regular.file.read_exact(bytes.as_mut()) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                return Err(AuthError::ConcurrentModification {
                    path: path.to_path_buf(),
                });
            }
            Err(source) => {
                return Err(AuthError::io(
                    "cannot read complete authentication key",
                    path,
                    source,
                ));
            }
        }
        ensure_no_extra_bytes(&mut regular.file, path, "authentication key")?;
        regular.recheck()?;
        Ok(Self { regular, bytes })
    }

    fn recheck(&self) -> Result<(), AuthError> {
        self.regular.recheck()
    }

    fn identity(&self) -> FileIdentity {
        self.regular.snapshot.identity()
    }

    fn path(&self) -> &Path {
        &self.regular.path
    }
}

fn key_security_rejection_reason(
    mode: u32,
    owner_uid: u32,
    effective_uid: libc::uid_t,
) -> Option<&'static str> {
    if mode & 0o077 != 0 {
        Some(
            "must not be readable, writable, or executable by group or other users (use mode 0600 or stricter)",
        )
    } else if owner_uid != effective_uid {
        Some("must be owned by the effective user running otp2-auth")
    } else {
        None
    }
}

fn reject_file_key_alias(input: &OpenRegular, key: &OpenAuthKey) -> Result<(), AuthError> {
    if input.snapshot.identity() == key.identity() {
        Err(AuthError::FileIsKey {
            file_path: input.path.clone(),
            key_path: key.path().to_path_buf(),
        })
    } else {
        Ok(())
    }
}

fn reject_tag_aliases(
    file_path: &Path,
    file_identity: FileIdentity,
    tag_path: &Path,
    tag_identity: FileIdentity,
    key: &OpenAuthKey,
) -> Result<(), AuthError> {
    if file_identity == tag_identity {
        return Err(AuthError::FileAndTagAlias {
            file_path: file_path.to_path_buf(),
            tag_path: tag_path.to_path_buf(),
        });
    }
    if key.identity() == tag_identity {
        return Err(AuthError::TagIsKey {
            tag_path: tag_path.to_path_buf(),
            key_path: key.path().to_path_buf(),
        });
    }
    Ok(())
}

fn validate_terminal_name(path: &Path, role: &'static str) -> Result<(), AuthError> {
    if has_ambiguous_terminal_component(path) {
        return Err(AuthError::InvalidFile {
            role,
            path: path.to_path_buf(),
            reason: "must not end in a separator or '.' component",
        });
    }
    if path.file_name().is_none() {
        return Err(AuthError::InvalidFile {
            role,
            path: path.to_path_buf(),
            reason: "must include a filename",
        });
    }
    Ok(())
}

fn anchor_path(path: &Path, role: &'static str) -> Result<PathBuf, AuthError> {
    validate_terminal_name(path, role)?;
    let file_name = path.file_name().expect("validated filename");
    let parent = usable_parent(path);
    let anchored_parent = fs::canonicalize(parent)
        .map_err(|source| AuthError::io("cannot resolve containing directory", parent, source))?;
    Ok(anchored_parent.join(file_name))
}

fn has_ambiguous_terminal_component(path: &Path) -> bool {
    let bytes = path.as_os_str().as_encoded_bytes();
    bytes.ends_with(b"/") || bytes.ends_with(b"/.")
}

fn usable_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

struct OpenRegular {
    file: File,
    directory: ParentDirectory,
    path: PathBuf,
    snapshot: FileSnapshot,
}

impl OpenRegular {
    fn open(role: &'static str, path: &Path) -> Result<Self, AuthError> {
        let parent = usable_parent(path);
        let directory = ParentDirectory::open(parent)
            .map_err(|source| AuthError::io("cannot open containing directory", parent, source))?;
        let inspected = directory
            .inspect_nofollow(path)
            .map_err(|source| AuthError::io("cannot inspect file", path, source))?;
        let inspected_metadata = inspected
            .metadata()
            .map_err(|source| AuthError::io("cannot inspect file", path, source))?;
        if inspected_metadata.file_type().is_symlink() {
            return Err(AuthError::InvalidFile {
                role,
                path: path.to_path_buf(),
                reason: "must not be a symbolic link",
            });
        }
        require_regular(role, path, &inspected_metadata)?;
        let inspected_identity = file_identity_from_metadata(&inspected_metadata);

        let file = match directory.open_readonly(path) {
            Ok(file) => file,
            Err(source) if is_symlink_open_error(&source) => {
                return Err(AuthError::ConcurrentModification {
                    path: path.to_path_buf(),
                });
            }
            Err(source) => return Err(AuthError::io("cannot open file", path, source)),
        };
        let metadata = file
            .metadata()
            .map_err(|source| AuthError::io("cannot inspect open file", path, source))?;
        require_regular(role, path, &metadata)?;
        if file_identity_from_metadata(&metadata) != inspected_identity {
            return Err(AuthError::ConcurrentModification {
                path: path.to_path_buf(),
            });
        }
        let snapshot = FileSnapshot::from_metadata(&metadata);
        let opened = Self {
            file,
            directory,
            path: path.to_path_buf(),
            snapshot,
        };
        opened.recheck()?;
        Ok(opened)
    }

    fn recheck(&self) -> Result<(), AuthError> {
        let metadata = self
            .file
            .metadata()
            .map_err(|source| AuthError::io("cannot recheck open file", &self.path, source))?;
        if FileSnapshot::from_metadata(&metadata) != self.snapshot {
            return Err(AuthError::ConcurrentModification {
                path: self.path.clone(),
            });
        }
        ensure_path_identity(&self.directory, &self.path, self.snapshot.identity())
    }
}

fn require_regular(role: &'static str, path: &Path, metadata: &Metadata) -> Result<(), AuthError> {
    if metadata.is_file() {
        Ok(())
    } else {
        Err(AuthError::InvalidFile {
            role,
            path: path.to_path_buf(),
            reason: "must be a regular file",
        })
    }
}

fn inspect_destination(
    directory: &ParentDirectory,
    path: &Path,
    replace: bool,
) -> Result<DestinationExpectation, AuthError> {
    let inspected = match directory.inspect_nofollow(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(DestinationExpectation::Absent);
        }
        Err(source) => return Err(AuthError::io("cannot inspect sidecar path", path, source)),
    };
    if !replace {
        return Err(AuthError::TagAlreadyExists {
            path: path.to_path_buf(),
        });
    }
    let metadata = inspected
        .metadata()
        .map_err(|source| AuthError::io("cannot inspect existing sidecar", path, source))?;
    if metadata.file_type().is_symlink() {
        return Err(AuthError::InvalidFile {
            role: "existing sidecar",
            path: path.to_path_buf(),
            reason: "must not be a symbolic link",
        });
    }
    require_regular("existing sidecar", path, &metadata)?;
    Ok(DestinationExpectation::Present {
        identity: file_identity_from_metadata(&metadata),
        links: metadata.nlink(),
    })
}

#[derive(Clone, Copy)]
enum DestinationExpectation {
    Absent,
    Present { identity: FileIdentity, links: u64 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

#[derive(Debug, Eq, PartialEq)]
struct FileSnapshot {
    len: u64,
    modified: Option<SystemTime>,
    readonly: bool,
    identity: FileIdentity,
    links: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl FileSnapshot {
    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            len: metadata.len(),
            modified: metadata.modified().ok(),
            readonly: metadata.permissions().readonly(),
            identity: file_identity_from_metadata(metadata),
            links: metadata.nlink(),
            mode: metadata.mode(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        }
    }

    fn identity(&self) -> FileIdentity {
        self.identity
    }
}

fn file_identity(file: &File) -> io::Result<FileIdentity> {
    file.metadata()
        .map(|metadata| file_identity_from_metadata(&metadata))
}

fn file_identity_from_metadata(metadata: &Metadata) -> FileIdentity {
    FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

fn ensure_path_identity(
    directory: &ParentDirectory,
    path: &Path,
    expected: FileIdentity,
) -> Result<(), AuthError> {
    let current = directory
        .identity_at(path)
        .map_err(|source| AuthError::io("cannot recheck file path identity", path, source))?;
    if current == Some(expected) {
        Ok(())
    } else {
        Err(AuthError::ConcurrentModification {
            path: path.to_path_buf(),
        })
    }
}

struct ParentDirectory {
    handle: File,
    path: PathBuf,
}

impl ParentDirectory {
    fn open(path: &Path) -> io::Result<Self> {
        let mut options = OpenOptions::new();
        options.read(true).custom_flags(
            libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        );
        let handle = options.open(path)?;
        Ok(Self {
            handle,
            path: path.to_path_buf(),
        })
    }

    fn sync(&self) -> io::Result<()> {
        self.handle.sync_all()
    }

    fn open_readonly(&self, path: &Path) -> io::Result<File> {
        self.open_at(
            path_file_name(path)?,
            libc::O_RDONLY
                | libc::O_CLOEXEC
                | libc::O_NOFOLLOW
                | libc::O_NONBLOCK
                | libc::O_LARGEFILE,
            0,
        )
    }

    fn inspect_nofollow(&self, path: &Path) -> io::Result<File> {
        self.open_at(
            path_file_name(path)?,
            libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0,
        )
    }

    fn create_new(&self, path: &Path, mode: libc::mode_t) -> io::Result<File> {
        self.open_at(
            path_file_name(path)?,
            libc::O_RDWR
                | libc::O_CLOEXEC
                | libc::O_CREAT
                | libc::O_EXCL
                | libc::O_NOFOLLOW
                | libc::O_LARGEFILE,
            mode,
        )
    }

    fn identity_at(&self, path: &Path) -> io::Result<Option<FileIdentity>> {
        self.identity_at_name(path_file_name(path)?)
    }

    fn identity_at_name(&self, name: &OsStr) -> io::Result<Option<FileIdentity>> {
        let file = match self.open_at(name, libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW, 0) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Ok(None);
        }
        Ok(Some(file_identity_from_metadata(&metadata)))
    }

    fn is_single_link_regular_with_identity(
        &self,
        path: &Path,
        expected: FileIdentity,
    ) -> io::Result<bool> {
        let file = match self.inspect_nofollow(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        };
        let metadata = file.metadata()?;
        Ok(metadata.is_file()
            && metadata.nlink() == 1
            && file_identity_from_metadata(&metadata) == expected)
    }

    fn remove_name_if_same_identity(&self, name: &OsStr, identity: FileIdentity) {
        if self.identity_at_name(name).ok() == Some(Some(identity)) {
            let _ = self.unlink_at(name);
        }
    }

    fn replace(&self, source_name: &OsStr, destination: &Path) -> io::Result<()> {
        self.rename(source_name, destination, 0)
    }

    fn install_new(&self, source_name: &OsStr, destination: &Path) -> io::Result<()> {
        self.rename(source_name, destination, libc::RENAME_NOREPLACE)
    }

    fn rename(
        &self,
        source_name: &OsStr,
        destination: &Path,
        flags: libc::c_uint,
    ) -> io::Result<()> {
        if usable_parent(destination) != self.path {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "destination is outside the pinned directory",
            ));
        }
        let source = os_string_to_cstring(source_name)?;
        let destination = os_string_to_cstring(path_file_name(destination)?)?;
        // Do not blindly retry an interrupted rename. On remote filesystems an
        // error can be reported after the server committed the operation; a
        // retry could turn a successful RENAME_NOREPLACE into EEXIST.
        // SAFETY: both strings are valid and live for the call, both file
        // descriptors are owned by `self`, and flags is either zero or the
        // Linux RENAME_NOREPLACE flag.
        let result = unsafe {
            libc::renameat2(
                self.handle.as_raw_fd(),
                source.as_ptr(),
                self.handle.as_raw_fd(),
                destination.as_ptr(),
                flags,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn open_at(&self, name: &OsStr, flags: libc::c_int, mode: libc::mode_t) -> io::Result<File> {
        let name = os_string_to_cstring(name)?;
        loop {
            // SAFETY: `name` is NUL-terminated, the directory descriptor is
            // live, and a successful new descriptor is transferred to `File`.
            let descriptor =
                unsafe { libc::openat(self.handle.as_raw_fd(), name.as_ptr(), flags, mode) };
            if descriptor >= 0 {
                // SAFETY: `openat` returned a new owned descriptor.
                return Ok(unsafe { File::from_raw_fd(descriptor) });
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }

    fn unlink_at(&self, name: &OsStr) -> io::Result<()> {
        let name = os_string_to_cstring(name)?;
        // As with rename, an outcome-ambiguous error must not be retried: the
        // name could have been recreated with a different inode in between.
        // SAFETY: the C string and owned directory descriptor are valid.
        let result = unsafe { libc::unlinkat(self.handle.as_raw_fd(), name.as_ptr(), 0) };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

enum CommitFailure {
    NotCommitted(io::Error),
    OutcomeUncertain(io::Error),
}

struct SiblingTemp {
    file: File,
    path: PathBuf,
    name: OsString,
    directory: ParentDirectory,
    identity: FileIdentity,
    committed: bool,
}

impl SiblingTemp {
    fn create(parent: &ParentDirectory) -> io::Result<Self> {
        let directory = ParentDirectory {
            handle: parent.handle.try_clone()?,
            path: parent.path.clone(),
        };
        for _ in 0..TEMP_CREATE_ATTEMPTS {
            let name = unique_temp_name()?;
            let path = directory.path.join(&name);
            match directory.create_new(&path, 0o600) {
                Ok(file) => {
                    let identity = match file_identity(&file) {
                        Ok(identity) => identity,
                        Err(error) => {
                            drop(file);
                            return Err(error);
                        }
                    };
                    return Ok(Self {
                        file,
                        path,
                        name,
                        directory,
                        identity,
                        committed: false,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique sibling temporary filename",
        ))
    }

    fn commit(
        mut self,
        destination: &Path,
        expectation: DestinationExpectation,
        staged_snapshot: &FileSnapshot,
    ) -> Result<Option<io::Error>, CommitFailure> {
        let metadata = self.file.metadata().map_err(CommitFailure::NotCommitted)?;
        if &FileSnapshot::from_metadata(&metadata) != staged_snapshot {
            return Err(CommitFailure::NotCommitted(io::Error::other(
                "temporary sidecar changed before commit",
            )));
        }
        if self
            .directory
            .identity_at_name(&self.name)
            .map_err(CommitFailure::NotCommitted)?
            != Some(self.identity)
        {
            return Err(CommitFailure::NotCommitted(io::Error::other(
                "temporary file path changed before commit",
            )));
        }
        let rename_result = match expectation {
            DestinationExpectation::Absent => self.directory.install_new(&self.name, destination),
            DestinationExpectation::Present { identity, .. } => {
                if !self
                    .directory
                    .is_single_link_regular_with_identity(destination, identity)
                    .map_err(CommitFailure::NotCommitted)?
                {
                    return Err(CommitFailure::NotCommitted(io::Error::other(
                        "existing sidecar path changed before replacement",
                    )));
                }
                self.directory.replace(&self.name, destination)
            }
        };
        if let Err(source) = rename_result {
            let source_identity = self.directory.identity_at_name(&self.name);
            let destination_identity = self.directory.identity_at(destination);
            return match (source_identity, destination_identity) {
                (Ok(Some(current_source)), Ok(current_destination))
                    if current_source == self.identity
                        && current_destination != Some(self.identity) =>
                {
                    Err(CommitFailure::NotCommitted(source))
                }
                (Ok(current_source), Ok(Some(current_destination)))
                    if current_source != Some(self.identity)
                        && current_destination == self.identity =>
                {
                    self.committed = true;
                    Ok(Some(source))
                }
                _ => {
                    // Suppress cleanup when the namespace no longer proves
                    // whether the rename committed. Deleting either name could
                    // destroy the only recoverable copy.
                    self.committed = true;
                    Err(CommitFailure::OutcomeUncertain(source))
                }
            };
        }
        self.committed = true;
        Ok(None)
    }
}

impl Drop for SiblingTemp {
    fn drop(&mut self) {
        if !self.committed {
            self.directory
                .remove_name_if_same_identity(&self.name, self.identity);
        }
    }
}

fn unique_temp_name() -> io::Result<OsString> {
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let mut nonce = [0_u8; 16];
    getrandom::fill(&mut nonce).map_err(|source| {
        io::Error::other(format!("cannot randomize temporary filename: {source}"))
    })?;
    let nonce = u128::from_ne_bytes(nonce);
    Ok(OsString::from(format!(
        ".otp2-auth-{}-{sequence:016x}-{nonce:032x}.tmp",
        std::process::id()
    )))
}

fn path_file_name(path: &Path) -> io::Result<&OsStr> {
    path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "a directory-relative operation requires a filename",
        )
    })
}

fn os_string_to_cstring(value: &OsStr) -> io::Result<CString> {
    CString::new(value.as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Linux pathnames cannot contain NUL bytes",
        )
    })
}

fn is_symlink_open_error(error: &io::Error) -> bool {
    error.raw_os_error() == Some(libc::ELOOP)
}

fn effective_uid() -> libc::uid_t {
    // SAFETY: `geteuid` has no preconditions and accesses no caller memory.
    unsafe { libc::geteuid() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};

    #[test]
    fn canonical_header_layout_is_stable() {
        assert_eq!(
            encode_header(0x0102_0304_0506_0708),
            [
                b'o', b't', b'p', b'2', b'T', b'A', b'G', 0, 0, 1, 0, 32, 0, 0, 0, 0, 1, 2, 3, 4,
                5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0,
            ]
        );
    }

    #[test]
    fn canonical_header_parser_rejects_every_noncanonical_field() {
        let path = Path::new("tag");
        let valid = encode_header(7);
        assert_eq!(parse_header(valid, path).unwrap(), 7);
        for range in [0..8, 8..10, 10..12, 12..16, 24..32] {
            let mut changed = valid;
            changed[range.start] ^= 1;
            assert!(matches!(
                parse_header(changed, path),
                Err(AuthError::InvalidTag { .. })
            ));
        }
    }

    #[test]
    fn default_sidecar_path_preserves_non_utf8_bytes() {
        let name = OsString::from_vec(vec![b'f', 0xff, b'x']);
        let result = default_tag_path(Path::new(&name)).unwrap();
        assert_eq!(result.as_os_str().as_bytes(), b"f\xffx.otp2auth");
    }

    #[test]
    fn default_sidecar_path_rejects_directory_spellings() {
        for path in ["/", ".", "x/", "x/."] {
            assert!(matches!(
                default_tag_path(path),
                Err(AuthError::InvalidFile { .. })
            ));
        }
    }

    #[test]
    fn authentication_failure_classification_is_narrow() {
        let invalid = AuthError::invalid_tag(Path::new("tag"), "bad");
        assert!(invalid.is_authentication_failure());
        let mismatch = AuthError::AuthenticationFailed {
            file_path: "file".into(),
            tag_path: "tag".into(),
        };
        assert!(mismatch.is_authentication_failure());
        let changed = AuthError::ConcurrentModification {
            path: "file".into(),
        };
        assert!(!changed.is_authentication_failure());
    }

    #[test]
    fn key_policy_requires_effective_owner_and_private_mode() {
        let uid = effective_uid();
        assert_eq!(key_security_rejection_reason(0o100600, uid, uid), None);
        assert_eq!(key_security_rejection_reason(0o100400, uid, uid), None);
        for mode in [0o100640, 0o100604, 0o100610, 0o100601] {
            assert!(key_security_rejection_reason(mode, uid, uid).is_some());
        }
        assert!(key_security_rejection_reason(0o100600, uid.wrapping_add(1), uid).is_some());
    }
}
