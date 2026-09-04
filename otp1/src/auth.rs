//! Optional authenticated envelopes for `otp1` ciphertext.
//!
//! This module deliberately does not change the raw XOR format used by
//! `otp1`. A separate 32-byte authentication key protects a versioned
//! envelope containing the raw ciphertext. Unwrapping a valid envelope
//! restores the exact bytes that `otp1` expects.

use std::env;
use std::error::Error;
use std::fmt;
#[cfg(unix)]
use std::fs::OpenOptions;
use std::fs::{self, File, Metadata, Permissions};
use std::io::{self, Read, Seek, Write};
use std::path::{Path, PathBuf};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use super::{
    FileIdentity, FileSnapshot, ParentDirectory, SiblingTemp, has_ambiguous_terminal_component,
    identity_at_path, usable_parent,
};

/// The authentication-key filename expected beside `otp1-auth`.
pub const AUTH_KEY_FILE_NAME: &str = "auth.key";
/// The exact required length of `auth.key` in raw bytes.
pub const AUTH_KEY_LENGTH: usize = 32;
/// The fixed authenticated-envelope header length.
pub const HEADER_LENGTH: usize = 32;
/// The full HMAC-SHA-256 tag length.
pub const TAG_LENGTH: usize = 32;

const MAGIC: &[u8; 8] = b"OTP1AUTH";
const VERSION: u16 = 1;
const FLAGS: u32 = 0;
const RESERVED: u64 = 0;
const MAC_DOMAIN: &[u8] = b"otp1-auth/envelope/v1\0";
const STREAM_BUFFER_SIZE: usize = 64 * 1024;

type HmacSha256 = Hmac<Sha256>;

/// The result of an operation which created or atomically replaced a file.
#[derive(Debug)]
pub enum AuthOutcome {
    /// The operation and all platform-supported synchronization completed.
    Committed,
    /// The file operation completed, but synchronizing its directory failed.
    ///
    /// The caller must inspect the file rather than blindly retrying.
    CommittedButDurabilityUncertain(io::Error),
}

/// An authentication-envelope error which occurred before replacement.
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
    TargetIsKey {
        target_path: PathBuf,
        key_path: PathBuf,
    },
    InvalidEnvelope {
        path: PathBuf,
        reason: &'static str,
    },
    AuthenticationFailed {
        path: PathBuf,
    },
    StagedOutputInvalid {
        path: PathBuf,
    },
    AlreadyEnvelope {
        path: PathBuf,
    },
    ConcurrentModification {
        path: PathBuf,
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

    fn invalid_envelope(path: &Path, reason: &'static str) -> Self {
        Self::InvalidEnvelope {
            path: path.to_path_buf(),
            reason,
        }
    }

    /// Whether this error means the supplied file was not a valid,
    /// authenticated envelope.
    pub fn is_authentication_failure(&self) -> bool {
        matches!(
            self,
            Self::InvalidEnvelope { .. } | Self::AuthenticationFailed { .. }
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
            Self::TargetIsKey {
                target_path,
                key_path,
            } => write!(
                formatter,
                "target '{}' and authentication key '{}' refer to the same file",
                target_path.display(),
                key_path.display()
            ),
            Self::InvalidEnvelope { path, reason } => {
                write!(
                    formatter,
                    "'{}' is not a valid otp1 authenticated envelope: {reason}",
                    path.display()
                )
            }
            Self::AuthenticationFailed { path } => write!(
                formatter,
                "authentication failed for '{}'; its contents and path were not changed",
                path.display()
            ),
            Self::StagedOutputInvalid { path } => write!(
                formatter,
                "synchronized temporary output '{}' failed read-back authentication; the original file was not replaced",
                path.display()
            ),
            Self::AlreadyEnvelope { path } => write!(
                formatter,
                "'{}' already begins with the otp1 authenticated-envelope marker; refusing to seal it again",
                path.display()
            ),
            Self::ConcurrentModification { path } => write!(
                formatter,
                "'{}' changed while it was being authenticated; the original path was not replaced",
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
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Return the `auth.key` path beside the executable reported by the operating
/// system for the current process.
pub fn auth_key_path_next_to_current_exe() -> Result<PathBuf, AuthError> {
    let executable = env::current_exe().map_err(|source| {
        AuthError::io("cannot locate the running executable", "otp1-auth", source)
    })?;
    let directory = executable
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or_else(|| AuthError::NoExecutableDirectory {
            executable: executable.clone(),
        })?;
    Ok(directory.join(AUTH_KEY_FILE_NAME))
}

/// Generate a new random `auth.key` beside the running executable.
///
/// Existing files are never overwritten. On Unix the new file is created with
/// mode `0600`.
#[cfg(unix)]
pub fn generate_key_next_to_current_exe() -> Result<AuthOutcome, AuthError> {
    let key_path = auth_key_path_next_to_current_exe()?;
    let parent = usable_parent(&key_path);
    let parent_directory = ParentDirectory::open(parent).map_err(|source| {
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

    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(&key_path).map_err(|source| {
        AuthError::io(
            "cannot create authentication key (existing keys are never overwritten)",
            &key_path,
            source,
        )
    })?;
    let identity = file.metadata().and_then(|metadata| {
        FileSnapshot::from_open_file(&file, &metadata).map(|snapshot| snapshot.identity())
    });
    let identity = match identity {
        Ok(identity) => identity,
        Err(source) => {
            drop(file);
            let _ = fs::remove_file(&key_path);
            return Err(AuthError::io(
                "cannot identify new authentication key",
                key_path,
                source,
            ));
        }
    };

    let write_result = (|| -> io::Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(Permissions::from_mode(0o600))?;
        }
        file.write_all(key.as_ref())?;
        file.flush()?;
        file.sync_all()?;
        Ok(())
    })();
    if let Err(source) = write_result {
        drop(file);
        remove_if_same_identity(&key_path, identity);
        return Err(AuthError::io(
            "cannot write and synchronize new authentication key",
            key_path,
            source,
        ));
    }

    let metadata = match file.metadata() {
        Ok(metadata) => metadata,
        Err(source) => {
            drop(file);
            remove_if_same_identity(&key_path, identity);
            return Err(AuthError::io(
                "cannot inspect new authentication key",
                key_path,
                source,
            ));
        }
    };
    let snapshot = match FileSnapshot::from_open_file(&file, &metadata) {
        Ok(snapshot) => snapshot,
        Err(source) => {
            drop(file);
            remove_if_same_identity(&key_path, identity);
            return Err(AuthError::io(
                "cannot identify new authentication key",
                key_path,
                source,
            ));
        }
    };
    if snapshot.len != AUTH_KEY_LENGTH as u64
        || snapshot.link_count() != 1
        || snapshot.identity() != identity
    {
        drop(file);
        remove_if_same_identity(&key_path, identity);
        return Err(AuthError::ConcurrentModification { path: key_path });
    }
    ensure_path_identity(&key_path, identity)?;

    #[cfg(test)]
    let parent_sync_result = inject_auth_test_failure(AuthTestFailPoint::ParentSync)
        .and_then(|()| parent_directory.sync());
    #[cfg(not(test))]
    let parent_sync_result = parent_directory.sync();

    match parent_sync_result {
        Ok(()) => Ok(AuthOutcome::Committed),
        Err(source) => Ok(AuthOutcome::CommittedButDurabilityUncertain(source)),
    }
}

/// Refuse to generate a key when this build cannot establish private key-file
/// permissions itself.
#[cfg(windows)]
pub fn generate_key_next_to_current_exe() -> Result<AuthOutcome, AuthError> {
    let key_path = auth_key_path_next_to_current_exe()?;
    Err(AuthError::InvalidFile {
        role: "authentication key",
        path: key_path,
        reason: "was not created because otp1-auth cannot establish a private Windows ACL; provision exactly 32 random bytes in a user-private executable directory",
    })
}

/// Atomically wrap a raw `otp1` ciphertext in an authenticated envelope.
pub fn seal_in_place(
    input_path: impl AsRef<Path>,
    key_path: impl AsRef<Path>,
) -> Result<AuthOutcome, AuthError> {
    seal_in_place_with_marker_policy(input_path.as_ref(), key_path.as_ref(), true)
}

/// Atomically wrap raw bytes even when they begin with the authenticated
/// envelope marker.
///
/// This is the explicit escape hatch for a legitimate raw `otp1` ciphertext
/// whose first eight bytes happen to be `OTP1AUTH`. Callers should otherwise
/// prefer [`seal_in_place`], which catches accidental double sealing and many
/// damaged-envelope mistakes.
pub fn seal_raw_in_place(
    input_path: impl AsRef<Path>,
    key_path: impl AsRef<Path>,
) -> Result<AuthOutcome, AuthError> {
    seal_in_place_with_marker_policy(input_path.as_ref(), key_path.as_ref(), false)
}

fn seal_in_place_with_marker_policy(
    input_path: &Path,
    key_path: &Path,
    reject_marker: bool,
) -> Result<AuthOutcome, AuthError> {
    let input_path = anchor_auth_path(input_path, "input file")?;
    let key_path = anchor_auth_path(key_path, "authentication key")?;
    let input_path = input_path.as_path();
    let key_path = key_path.as_path();

    let (mut input, input_metadata, input_snapshot) = open_regular("input file", input_path)?;
    ensure_path_identity(input_path, input_snapshot.identity())?;
    if input_snapshot.link_count() > 1 {
        return Err(AuthError::InvalidFile {
            role: "input file",
            path: input_path.to_path_buf(),
            reason: "must not have multiple hard links",
        });
    }
    if reject_marker {
        reject_envelope_marker(&mut input, input_metadata.len(), input_path)?;
    }

    let key = open_auth_key(key_path)?;
    reject_target_key_alias(input_path, input_snapshot.identity(), &key)?;

    let payload_len = input_metadata.len();
    let expected_len = envelope_length(payload_len)
        .ok_or_else(|| AuthError::invalid_envelope(input_path, "file is too large to envelope"))?;
    let header = encode_header(payload_len);
    let original_permissions = input_metadata.permissions();
    let parent = usable_parent(input_path);
    let parent_directory = ParentDirectory::open(parent)
        .map_err(|source| AuthError::io("cannot open input directory", parent, source))?;
    let mut temporary = SiblingTemp::create(parent)
        .map_err(|source| AuthError::io("cannot create temporary envelope", parent, source))?;
    #[cfg(test)]
    inject_auth_test_failure(AuthTestFailPoint::AfterTempCreate).map_err(|source| {
        AuthError::io(
            "injected failure after temporary envelope creation",
            &temporary.path,
            source,
        )
    })?;

    let mut mac = new_mac(key.bytes.as_ref());
    mac.update(MAC_DOMAIN);
    mac.update(&header);
    temporary
        .file
        .write_all(&header)
        .map_err(|source| AuthError::io("cannot write envelope header", &temporary.path, source))?;
    stream_payload_for_seal(
        &mut input,
        &mut temporary.file,
        &mut mac,
        payload_len,
        input_path,
        &temporary.path,
    )?;
    #[cfg(test)]
    inject_auth_test_failure(AuthTestFailPoint::AfterPayload).map_err(|source| {
        AuthError::io(
            "injected failure after writing envelope payload",
            &temporary.path,
            source,
        )
    })?;
    let tag = mac.finalize().into_bytes();
    temporary.file.write_all(&tag).map_err(|source| {
        AuthError::io(
            "cannot write envelope authentication tag",
            &temporary.path,
            source,
        )
    })?;
    #[cfg(test)]
    inject_auth_test_failure(AuthTestFailPoint::AfterTag).map_err(|source| {
        AuthError::io(
            "injected failure after writing authentication tag",
            &temporary.path,
            source,
        )
    })?;

    ensure_no_extra_bytes(&mut input, input_path, "input file")?;
    ensure_file_unchanged(&input, &input_snapshot, input_path)?;
    key.recheck()?;
    finish_and_commit(
        temporary,
        expected_len,
        StagedValidation::Envelope,
        original_permissions,
        input_path,
        &input,
        &input_snapshot,
        &key,
        &parent_directory,
    )
}

/// Verify an authenticated envelope without changing its contents or replacing
/// its path. Normal reads may update access-time metadata.
pub fn verify_file(
    envelope_path: impl AsRef<Path>,
    key_path: impl AsRef<Path>,
) -> Result<(), AuthError> {
    let envelope_path = anchor_auth_path(envelope_path.as_ref(), "envelope file")?;
    let key_path = anchor_auth_path(key_path.as_ref(), "authentication key")?;
    let envelope_path = envelope_path.as_path();
    let key_path = key_path.as_path();

    let (mut envelope, metadata, snapshot) = open_regular("envelope file", envelope_path)?;
    ensure_path_identity(envelope_path, snapshot.identity())?;
    let parsed = read_and_parse_header(&mut envelope, metadata.len(), envelope_path)?;
    let key = open_auth_key(key_path)?;
    reject_target_key_alias(envelope_path, snapshot.identity(), &key)?;

    let _tag = verify_payload_and_tag(
        &mut envelope,
        None,
        parsed,
        key.bytes.as_ref(),
        envelope_path,
    )?;
    ensure_no_extra_bytes(&mut envelope, envelope_path, "envelope file")?;
    ensure_file_unchanged(&envelope, &snapshot, envelope_path)?;
    key.recheck()?;
    ensure_path_identity(envelope_path, snapshot.identity())?;
    Ok(())
}

/// Verify and atomically remove an authenticated envelope, restoring the exact
/// raw ciphertext bytes expected by `otp1`.
pub fn unwrap_in_place(
    envelope_path: impl AsRef<Path>,
    key_path: impl AsRef<Path>,
) -> Result<AuthOutcome, AuthError> {
    let envelope_path = anchor_auth_path(envelope_path.as_ref(), "envelope file")?;
    let key_path = anchor_auth_path(key_path.as_ref(), "authentication key")?;
    let envelope_path = envelope_path.as_path();
    let key_path = key_path.as_path();

    let (mut envelope, metadata, snapshot) = open_regular("envelope file", envelope_path)?;
    ensure_path_identity(envelope_path, snapshot.identity())?;
    if snapshot.link_count() > 1 {
        return Err(AuthError::InvalidFile {
            role: "envelope file",
            path: envelope_path.to_path_buf(),
            reason: "must not have multiple hard links",
        });
    }
    let parsed = read_and_parse_header(&mut envelope, metadata.len(), envelope_path)?;
    let key = open_auth_key(key_path)?;
    reject_target_key_alias(envelope_path, snapshot.identity(), &key)?;

    let original_permissions = metadata.permissions();
    let parent = usable_parent(envelope_path);
    let parent_directory = ParentDirectory::open(parent)
        .map_err(|source| AuthError::io("cannot open envelope directory", parent, source))?;
    let mut temporary = SiblingTemp::create(parent)
        .map_err(|source| AuthError::io("cannot create temporary ciphertext", parent, source))?;
    #[cfg(test)]
    inject_auth_test_failure(AuthTestFailPoint::AfterTempCreate).map_err(|source| {
        AuthError::io(
            "injected failure after temporary ciphertext creation",
            &temporary.path,
            source,
        )
    })?;

    let authenticated_tag = verify_payload_and_tag(
        &mut envelope,
        Some((&mut temporary.file, &temporary.path)),
        parsed,
        key.bytes.as_ref(),
        envelope_path,
    )?;
    #[cfg(test)]
    inject_auth_test_failure(AuthTestFailPoint::AfterPayload).map_err(|source| {
        AuthError::io(
            "injected failure after restoring ciphertext payload",
            &temporary.path,
            source,
        )
    })?;
    ensure_no_extra_bytes(&mut envelope, envelope_path, "envelope file")?;
    ensure_file_unchanged(&envelope, &snapshot, envelope_path)?;
    key.recheck()?;

    finish_and_commit(
        temporary,
        parsed.payload_len,
        StagedValidation::RawPayload {
            header: parsed.bytes,
            tag: authenticated_tag,
        },
        original_permissions,
        envelope_path,
        &envelope,
        &snapshot,
        &key,
        &parent_directory,
    )
}

struct OpenAuthKey {
    file: File,
    path: PathBuf,
    snapshot: FileSnapshot,
    bytes: Zeroizing<[u8; AUTH_KEY_LENGTH]>,
}

impl OpenAuthKey {
    fn recheck(&self) -> Result<(), AuthError> {
        ensure_file_unchanged(&self.file, &self.snapshot, &self.path)?;
        ensure_path_identity(&self.path, self.snapshot.identity())
    }
}

fn open_auth_key(path: &Path) -> Result<OpenAuthKey, AuthError> {
    let (mut file, metadata, snapshot) = open_regular("authentication key", path)?;
    if snapshot.link_count() > 1 {
        return Err(AuthError::InvalidFile {
            role: "authentication key",
            path: path.to_path_buf(),
            reason: "must not have multiple hard links",
        });
    }
    if metadata.len() != AUTH_KEY_LENGTH as u64 {
        return Err(AuthError::InvalidKeyLength {
            path: path.to_path_buf(),
            actual: metadata.len(),
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: `geteuid` has no preconditions and does not dereference any
        // pointers. Its return type is `uid_t`, represented by libc here.
        let effective_uid = unsafe { libc::geteuid() };
        if let Some(reason) =
            unix_key_security_rejection_reason(metadata.mode(), metadata.uid(), effective_uid)
        {
            return Err(AuthError::InvalidFile {
                role: "authentication key",
                path: path.to_path_buf(),
                reason,
            });
        }
    }
    let mut bytes = Zeroizing::new([0_u8; AUTH_KEY_LENGTH]);
    file.read_exact(bytes.as_mut())
        .map_err(|source| AuthError::io("cannot read complete authentication key", path, source))?;
    ensure_no_extra_bytes(&mut file, path, "authentication key")?;
    ensure_file_unchanged(&file, &snapshot, path)?;
    ensure_path_identity(path, snapshot.identity())?;
    Ok(OpenAuthKey {
        file,
        path: path.to_path_buf(),
        snapshot,
        bytes,
    })
}

#[cfg(unix)]
fn unix_key_security_rejection_reason(
    mode: u32,
    owner_uid: u32,
    effective_uid: libc::uid_t,
) -> Option<&'static str> {
    if mode & 0o077 != 0 {
        Some(
            "must not be readable, writable, or executable by group or other users (use mode 0600 or stricter)",
        )
    } else if owner_uid != effective_uid {
        Some("must be owned by the effective user running otp1-auth")
    } else {
        None
    }
}

fn reject_target_key_alias(
    target_path: &Path,
    target_identity: FileIdentity,
    key: &OpenAuthKey,
) -> Result<(), AuthError> {
    if target_identity == key.snapshot.identity() {
        Err(AuthError::TargetIsKey {
            target_path: target_path.to_path_buf(),
            key_path: key.path.clone(),
        })
    } else {
        Ok(())
    }
}

fn anchor_auth_path(path: &Path, role: &'static str) -> Result<PathBuf, AuthError> {
    if has_ambiguous_terminal_component(path) {
        return Err(AuthError::InvalidFile {
            role,
            path: path.to_path_buf(),
            reason: "must not end in a separator or '.' component",
        });
    }
    let Some(file_name) = path.file_name() else {
        return Err(AuthError::InvalidFile {
            role,
            path: path.to_path_buf(),
            reason: "must include a filename",
        });
    };
    let parent = usable_parent(path);
    let anchored_parent = fs::canonicalize(parent)
        .map_err(|source| AuthError::io("cannot resolve containing directory", parent, source))?;
    Ok(anchored_parent.join(file_name))
}

fn open_regular(
    role: &'static str,
    path: &Path,
) -> Result<(File, Metadata, FileSnapshot), AuthError> {
    let link_metadata = fs::symlink_metadata(path)
        .map_err(|source| AuthError::io("cannot inspect file", path, source))?;
    if link_metadata.file_type().is_symlink() {
        return Err(AuthError::InvalidFile {
            role,
            path: path.to_path_buf(),
            reason: "must not be a symbolic link",
        });
    }
    require_regular(role, path, &link_metadata)?;

    let file =
        File::open(path).map_err(|source| AuthError::io("cannot open file", path, source))?;
    let metadata = file
        .metadata()
        .map_err(|source| AuthError::io("cannot inspect open file", path, source))?;
    require_regular(role, path, &metadata)?;
    let snapshot = FileSnapshot::from_open_file(&file, &metadata)
        .map_err(|source| AuthError::io("cannot identify open file", path, source))?;
    Ok((file, metadata, snapshot))
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

fn ensure_file_unchanged(
    file: &File,
    snapshot: &FileSnapshot,
    path: &Path,
) -> Result<(), AuthError> {
    let metadata = file
        .metadata()
        .map_err(|source| AuthError::io("cannot recheck open file", path, source))?;
    let current = FileSnapshot::from_open_file(file, &metadata)
        .map_err(|source| AuthError::io("cannot re-identify open file", path, source))?;
    if &current == snapshot {
        Ok(())
    } else {
        Err(AuthError::ConcurrentModification {
            path: path.to_path_buf(),
        })
    }
}

fn ensure_path_identity(path: &Path, original: FileIdentity) -> Result<(), AuthError> {
    let current = identity_at_path(path)
        .map_err(|source| AuthError::io("cannot recheck file path identity", path, source))?;
    if current == Some(original) {
        Ok(())
    } else {
        Err(AuthError::ConcurrentModification {
            path: path.to_path_buf(),
        })
    }
}

#[cfg(unix)]
fn remove_if_same_identity(path: &Path, identity: FileIdentity) {
    if identity_at_path(path).ok() == Some(Some(identity)) {
        let _ = fs::remove_file(path);
    }
}

fn reject_envelope_marker(file: &mut File, len: u64, path: &Path) -> Result<(), AuthError> {
    if len >= MAGIC.len() as u64 {
        let mut marker = [0_u8; MAGIC.len()];
        file.read_exact(&mut marker)
            .map_err(|source| AuthError::io("cannot inspect input marker", path, source))?;
        file.rewind()
            .map_err(|source| AuthError::io("cannot rewind input file", path, source))?;
        if &marker == MAGIC {
            return Err(AuthError::AlreadyEnvelope {
                path: path.to_path_buf(),
            });
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct ParsedHeader {
    bytes: [u8; HEADER_LENGTH],
    payload_len: u64,
}

fn encode_header(payload_len: u64) -> [u8; HEADER_LENGTH] {
    let mut header = [0_u8; HEADER_LENGTH];
    header[..8].copy_from_slice(MAGIC);
    header[8..10].copy_from_slice(&VERSION.to_be_bytes());
    header[10..12].copy_from_slice(&(HEADER_LENGTH as u16).to_be_bytes());
    header[12..16].copy_from_slice(&FLAGS.to_be_bytes());
    header[16..24].copy_from_slice(&payload_len.to_be_bytes());
    header[24..32].copy_from_slice(&RESERVED.to_be_bytes());
    header
}

fn read_and_parse_header(
    file: &mut File,
    file_len: u64,
    path: &Path,
) -> Result<ParsedHeader, AuthError> {
    if file_len < (HEADER_LENGTH + TAG_LENGTH) as u64 {
        return Err(AuthError::invalid_envelope(path, "file is too short"));
    }
    let mut header = [0_u8; HEADER_LENGTH];
    read_exact_envelope(file, &mut header, path)?;
    parse_header(header, file_len, path)
}

fn parse_header(
    header: [u8; HEADER_LENGTH],
    file_len: u64,
    path: &Path,
) -> Result<ParsedHeader, AuthError> {
    if &header[..8] != MAGIC {
        return Err(AuthError::invalid_envelope(path, "marker is missing"));
    }
    if u16::from_be_bytes([header[8], header[9]]) != VERSION {
        return Err(AuthError::invalid_envelope(path, "version is unsupported"));
    }
    if u16::from_be_bytes([header[10], header[11]]) != HEADER_LENGTH as u16 {
        return Err(AuthError::invalid_envelope(
            path,
            "header length is not canonical",
        ));
    }
    if u32::from_be_bytes(header[12..16].try_into().expect("fixed slice")) != FLAGS {
        return Err(AuthError::invalid_envelope(path, "flags are unsupported"));
    }
    if u64::from_be_bytes(header[24..32].try_into().expect("fixed slice")) != RESERVED {
        return Err(AuthError::invalid_envelope(
            path,
            "reserved fields are nonzero",
        ));
    }
    let payload_len = u64::from_be_bytes(header[16..24].try_into().expect("fixed slice"));
    let Some(expected_len) = envelope_length(payload_len) else {
        return Err(AuthError::invalid_envelope(
            path,
            "declared payload length overflows the format",
        ));
    };
    if expected_len != file_len {
        return Err(AuthError::invalid_envelope(
            path,
            "declared payload length does not match the file size",
        ));
    }
    Ok(ParsedHeader {
        bytes: header,
        payload_len,
    })
}

fn envelope_length(payload_len: u64) -> Option<u64> {
    payload_len
        .checked_add(HEADER_LENGTH as u64)?
        .checked_add(TAG_LENGTH as u64)
}

fn new_mac(key: &[u8]) -> HmacSha256 {
    HmacSha256::new_from_slice(key).expect("HMAC accepts a 32-byte key")
}

fn stream_payload_for_seal<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    mac: &mut HmacSha256,
    length: u64,
    input_path: &Path,
    output_path: &Path,
) -> Result<(), AuthError> {
    let mut buffer = [0_u8; STREAM_BUFFER_SIZE];
    let mut remaining = length;
    while remaining != 0 {
        let amount = usize::try_from(remaining.min(STREAM_BUFFER_SIZE as u64))
            .expect("bounded chunk fits usize");
        match input.read_exact(&mut buffer[..amount]) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                return Err(AuthError::ConcurrentModification {
                    path: input_path.to_path_buf(),
                });
            }
            Err(source) => {
                return Err(AuthError::io(
                    "cannot read complete input payload",
                    input_path,
                    source,
                ));
            }
        }
        mac.update(&buffer[..amount]);
        output.write_all(&buffer[..amount]).map_err(|source| {
            AuthError::io(
                "cannot write complete envelope payload",
                output_path,
                source,
            )
        })?;
        remaining -= amount as u64;
    }
    Ok(())
}

fn verify_payload_and_tag(
    envelope: &mut File,
    mut output: Option<(&mut File, &Path)>,
    parsed: ParsedHeader,
    key: &[u8],
    envelope_path: &Path,
) -> Result<[u8; TAG_LENGTH], AuthError> {
    let mut mac = new_mac(key);
    mac.update(MAC_DOMAIN);
    mac.update(&parsed.bytes);

    let mut buffer = [0_u8; STREAM_BUFFER_SIZE];
    let mut remaining = parsed.payload_len;
    while remaining != 0 {
        let amount = usize::try_from(remaining.min(STREAM_BUFFER_SIZE as u64))
            .expect("bounded chunk fits usize");
        read_exact_envelope(envelope, &mut buffer[..amount], envelope_path)?;
        mac.update(&buffer[..amount]);
        if let Some((file, path)) = output.as_mut() {
            file.write_all(&buffer[..amount]).map_err(|source| {
                AuthError::io("cannot restore complete ciphertext", *path, source)
            })?;
        }
        remaining -= amount as u64;
    }

    let mut tag = [0_u8; TAG_LENGTH];
    read_exact_envelope(envelope, &mut tag, envelope_path)?;
    mac.verify_slice(&tag)
        .map_err(|_| AuthError::AuthenticationFailed {
            path: envelope_path.to_path_buf(),
        })?;
    Ok(tag)
}

fn read_exact_envelope(file: &mut File, bytes: &mut [u8], path: &Path) -> Result<(), AuthError> {
    match file.read_exact(bytes) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
            Err(AuthError::invalid_envelope(path, "file is truncated"))
        }
        Err(source) => Err(AuthError::io("cannot read envelope", path, source)),
    }
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
                return Err(AuthError::io(
                    if role == "authentication key" {
                        "cannot verify final authentication-key length"
                    } else {
                        "cannot verify final file length"
                    },
                    path,
                    source,
                ));
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn finish_and_commit(
    mut temporary: SiblingTemp,
    expected_len: u64,
    staged_validation: StagedValidation,
    original_permissions: Permissions,
    destination: &Path,
    source: &File,
    source_snapshot: &FileSnapshot,
    key: &OpenAuthKey,
    parent_directory: &ParentDirectory,
) -> Result<AuthOutcome, AuthError> {
    temporary
        .file
        .set_permissions(original_permissions)
        .map_err(|source| {
            AuthError::io(
                "cannot preserve permissions on temporary output",
                &temporary.path,
                source,
            )
        })?;
    #[cfg(test)]
    inject_auth_test_failure(AuthTestFailPoint::AfterPermissions).map_err(|source| {
        AuthError::io(
            "injected failure after preserving permissions",
            &temporary.path,
            source,
        )
    })?;
    temporary.file.flush().map_err(|source| {
        AuthError::io("cannot flush temporary output", &temporary.path, source)
    })?;
    #[cfg(test)]
    inject_auth_test_failure(AuthTestFailPoint::BeforeTempSync).map_err(|source| {
        AuthError::io(
            "injected failure before synchronizing temporary output",
            &temporary.path,
            source,
        )
    })?;
    temporary.file.sync_all().map_err(|source| {
        AuthError::io(
            "cannot synchronize temporary output",
            &temporary.path,
            source,
        )
    })?;
    #[cfg(test)]
    corrupt_staged_output_if_selected(&mut temporary.file, expected_len).map_err(|source| {
        AuthError::io(
            "cannot inject staged-output corruption",
            &temporary.path,
            source,
        )
    })?;

    if let Err(error) = validate_staged_output(
        &mut temporary.file,
        expected_len,
        staged_validation,
        key.bytes.as_ref(),
        &temporary.path,
    ) {
        if matches!(error, AuthError::Io { .. }) {
            return Err(error);
        }
        return Err(AuthError::StagedOutputInvalid {
            path: temporary.path.clone(),
        });
    }

    let metadata = temporary.file.metadata().map_err(|source| {
        AuthError::io("cannot inspect temporary output", &temporary.path, source)
    })?;
    let snapshot = FileSnapshot::from_open_file(&temporary.file, &metadata).map_err(|source| {
        AuthError::io("cannot identify temporary output", &temporary.path, source)
    })?;
    if snapshot.len != expected_len || snapshot.link_count() != 1 {
        return Err(AuthError::ConcurrentModification {
            path: temporary.path.clone(),
        });
    }

    ensure_file_unchanged(source, source_snapshot, destination)?;
    key.recheck()?;
    ensure_file_unchanged(&temporary.file, &snapshot, &temporary.path)?;
    ensure_path_identity(destination, source_snapshot.identity())?;
    ensure_path_identity(&key.path, key.snapshot.identity())?;
    #[cfg(test)]
    inject_auth_test_failure(AuthTestFailPoint::BeforeRename).map_err(|source| {
        AuthError::io(
            "injected failure before atomic replacement",
            destination,
            source,
        )
    })?;

    temporary
        .commit(destination)
        .map_err(|source| AuthError::io("cannot atomically replace file", destination, source))?;

    #[cfg(test)]
    let parent_sync_result = inject_auth_test_failure(AuthTestFailPoint::ParentSync)
        .and_then(|()| parent_directory.sync());
    #[cfg(not(test))]
    let parent_sync_result = parent_directory.sync();

    match parent_sync_result {
        Ok(()) => Ok(AuthOutcome::Committed),
        Err(source) => Ok(AuthOutcome::CommittedButDurabilityUncertain(source)),
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuthTestFailPoint {
    AfterTempCreate,
    AfterPayload,
    AfterTag,
    AfterPermissions,
    BeforeTempSync,
    CorruptAfterSync(u64),
    BeforeRename,
    ParentSync,
}

#[cfg(test)]
thread_local! {
    static AUTH_TEST_FAIL_POINT: std::cell::Cell<Option<AuthTestFailPoint>> = const {
        std::cell::Cell::new(None)
    };
}

#[cfg(test)]
fn inject_auth_test_failure(point: AuthTestFailPoint) -> io::Result<()> {
    AUTH_TEST_FAIL_POINT.with(|selected| {
        if selected.get() == Some(point) {
            selected.set(None);
            Err(io::Error::other(format!(
                "test-injected authentication failure at {point:?}"
            )))
        } else {
            Ok(())
        }
    })
}

#[derive(Clone, Copy)]
enum StagedValidation {
    Envelope,
    RawPayload {
        header: [u8; HEADER_LENGTH],
        tag: [u8; TAG_LENGTH],
    },
}

fn validate_staged_output(
    file: &mut File,
    expected_len: u64,
    validation: StagedValidation,
    key: &[u8],
    path: &Path,
) -> Result<(), AuthError> {
    file.rewind()
        .map_err(|source| AuthError::io("cannot rewind temporary output", path, source))?;
    match validation {
        StagedValidation::Envelope => {
            let parsed = read_and_parse_header(file, expected_len, path)?;
            let _tag = verify_payload_and_tag(file, None, parsed, key, path)?;
        }
        StagedValidation::RawPayload { header, tag } => {
            let payload_len = u64::from_be_bytes(header[16..24].try_into().expect("fixed slice"));
            if payload_len != expected_len {
                return Err(AuthError::StagedOutputInvalid {
                    path: path.to_path_buf(),
                });
            }
            let mut mac = new_mac(key);
            mac.update(MAC_DOMAIN);
            mac.update(&header);
            let mut buffer = [0_u8; STREAM_BUFFER_SIZE];
            let mut remaining = payload_len;
            while remaining != 0 {
                let amount = usize::try_from(remaining.min(STREAM_BUFFER_SIZE as u64))
                    .expect("bounded chunk fits usize");
                read_exact_envelope(file, &mut buffer[..amount], path)?;
                mac.update(&buffer[..amount]);
                remaining -= amount as u64;
            }
            mac.verify_slice(&tag)
                .map_err(|_| AuthError::StagedOutputInvalid {
                    path: path.to_path_buf(),
                })?;
        }
    }
    ensure_no_extra_bytes(file, path, "temporary output")
}

#[cfg(test)]
fn corrupt_staged_output_if_selected(file: &mut File, expected_len: u64) -> io::Result<()> {
    let offset = AUTH_TEST_FAIL_POINT.with(|point| {
        let Some(AuthTestFailPoint::CorruptAfterSync(offset)) = point.get() else {
            return None;
        };
        point.set(None);
        Some(offset)
    });
    let Some(offset) = offset else {
        return Ok(());
    };

    if expected_len == 0 {
        file.seek(std::io::SeekFrom::End(0))?;
        file.write_all(&[0xa5])?;
    } else {
        if offset >= expected_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "test corruption offset exceeds staged output",
            ));
        }
        file.seek(std::io::SeekFrom::Start(offset))?;
        let mut byte = [0_u8; 1];
        file.read_exact(&mut byte)?;
        file.seek(std::io::SeekFrom::Start(offset))?;
        file.write_all(&[byte[0] ^ 0x80])?;
    }
    file.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            for _ in 0..100 {
                let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
                let path = env::temp_dir().join(format!(
                    "otp1-auth-lib-{label}-{}-{sequence}",
                    std::process::id()
                ));
                match fs::create_dir(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("cannot create test directory: {error}"),
                }
            }
            panic!("cannot allocate test directory")
        }

        fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }

        fn entries(&self) -> Vec<OsString> {
            let mut entries: Vec<_> = fs::read_dir(&self.0)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect();
            entries.sort();
            entries
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct FailPointGuard;

    fn fail_at(point: AuthTestFailPoint) -> FailPointGuard {
        AUTH_TEST_FAIL_POINT.with(|selected| {
            assert_eq!(selected.get(), None);
            selected.set(Some(point));
        });
        FailPointGuard
    }

    impl Drop for FailPointGuard {
        fn drop(&mut self) {
            AUTH_TEST_FAIL_POINT.with(|selected| selected.set(None));
        }
    }

    fn decode_hex<const N: usize>(encoded: &str) -> [u8; N] {
        assert_eq!(encoded.len(), N * 2);
        let mut decoded = [0_u8; N];
        for (index, byte) in decoded.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&encoded[index * 2..index * 2 + 2], 16).unwrap();
        }
        decoded
    }

    fn test_key() -> [u8; AUTH_KEY_LENGTH] {
        std::array::from_fn(|index| index as u8)
    }

    fn write_fixture(directory: &TestDirectory, payload: &[u8]) -> (PathBuf, PathBuf) {
        let input = directory.join("payload.bin");
        let key = directory.join(AUTH_KEY_FILE_NAME);
        fs::write(&input, payload).unwrap();
        fs::write(&key, test_key()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&key, Permissions::from_mode(0o600)).unwrap();
        }
        (input, key)
    }

    fn assert_committed(outcome: AuthOutcome) {
        assert!(matches!(outcome, AuthOutcome::Committed));
    }

    #[test]
    fn canonical_header_and_independent_empty_envelope_vector_match() {
        let expected_header = decode_hex::<HEADER_LENGTH>(
            "4f54503141555448000100200000000000000000000000000000000000000000",
        );
        let expected_tag = decode_hex::<TAG_LENGTH>(
            "79d7d8f1c6a40e4e8470d583880a56719a640fafb8fe5e58882292474ca23362",
        );
        let header = encode_header(0);
        assert_eq!(header, expected_header);

        let mut mac = new_mac(&test_key());
        mac.update(MAC_DOMAIN);
        mac.update(&header);
        assert_eq!(mac.finalize().into_bytes().as_slice(), expected_tag);
    }

    #[test]
    fn independent_nonempty_envelope_vector_matches() {
        let payload = decode_hex::<8>("000102ff4f545031");
        let expected_header = decode_hex::<HEADER_LENGTH>(
            "4f54503141555448000100200000000000000000000000080000000000000000",
        );
        let expected_tag = decode_hex::<TAG_LENGTH>(
            "afed40bdbf8a1026ca9870db88d1b115f6933e9046fec7c3a5442edb05fba22a",
        );
        let header = encode_header(payload.len() as u64);
        assert_eq!(header, expected_header);

        let mut mac = new_mac(&test_key());
        mac.update(MAC_DOMAIN);
        mac.update(&header);
        mac.update(&payload);
        assert_eq!(mac.finalize().into_bytes().as_slice(), expected_tag);
    }

    #[test]
    fn rfc_4231_hmac_sha256_case_one_matches() {
        let mut mac = HmacSha256::new_from_slice(&[0x0b; 20]).unwrap();
        mac.update(b"Hi There");
        let expected = decode_hex::<TAG_LENGTH>(
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        );
        assert_eq!(mac.finalize().into_bytes().as_slice(), expected);
    }

    #[test]
    fn parser_rejects_every_noncanonical_fixed_header_field() {
        let path = Path::new("envelope.bin");
        let file_len = (HEADER_LENGTH + TAG_LENGTH) as u64;
        let mut cases = Vec::new();

        let mut bad_magic = encode_header(0);
        bad_magic[0] ^= 1;
        cases.push(bad_magic);
        let mut bad_version = encode_header(0);
        bad_version[9] = 2;
        cases.push(bad_version);
        let mut bad_header_length = encode_header(0);
        bad_header_length[11] = 31;
        cases.push(bad_header_length);
        let mut bad_flags = encode_header(0);
        bad_flags[15] = 1;
        cases.push(bad_flags);
        let mut bad_reserved = encode_header(0);
        bad_reserved[31] = 1;
        cases.push(bad_reserved);

        for header in cases {
            let error = parse_header(header, file_len, path).unwrap_err();
            assert!(error.is_authentication_failure(), "{error}");
        }
    }

    #[test]
    fn parser_rejects_length_mismatch_and_overflow_without_allocation() {
        let path = Path::new("envelope.bin");
        let error =
            parse_header(encode_header(1), (HEADER_LENGTH + TAG_LENGTH) as u64, path).unwrap_err();
        assert!(error.is_authentication_failure());

        let error = parse_header(encode_header(u64::MAX), u64::MAX, path).unwrap_err();
        assert!(error.is_authentication_failure());
        assert_eq!(envelope_length(u64::MAX), None);
    }

    #[cfg(unix)]
    #[test]
    fn unix_authentication_key_policy_requires_private_mode_and_ownership() {
        assert_eq!(
            unix_key_security_rejection_reason(0o100600, 1000, 1000),
            None
        );
        assert_eq!(
            unix_key_security_rejection_reason(0o100400, 1000, 1000),
            None
        );
        assert!(unix_key_security_rejection_reason(0o100640, 1000, 1000).is_some());
        assert!(unix_key_security_rejection_reason(0o100600, 1001, 1000).is_some());
    }

    #[test]
    fn every_seal_precommit_failpoint_preserves_the_original_transaction() {
        let points = [
            AuthTestFailPoint::AfterTempCreate,
            AuthTestFailPoint::AfterPayload,
            AuthTestFailPoint::AfterTag,
            AuthTestFailPoint::AfterPermissions,
            AuthTestFailPoint::BeforeTempSync,
            AuthTestFailPoint::BeforeRename,
        ];

        for point in points {
            let directory = TestDirectory::new("seal-precommit");
            let payload: Vec<_> = (0..150_013)
                .map(|index| (index as u8).wrapping_mul(37).wrapping_add(11))
                .collect();
            let (input, key) = write_fixture(&directory, &payload);
            let input_identity = identity_at_path(&input).unwrap();
            let entries = directory.entries();

            let _guard = fail_at(point);
            let error = seal_in_place(&input, &key).unwrap_err();

            assert!(error.to_string().contains("injected failure"));
            assert_eq!(fs::read(&input).unwrap(), payload, "point {point:?}");
            assert_eq!(fs::read(&key).unwrap(), test_key(), "point {point:?}");
            assert_eq!(identity_at_path(&input).unwrap(), input_identity);
            assert_eq!(directory.entries(), entries, "point {point:?}");
        }
    }

    #[test]
    fn every_unwrap_precommit_failpoint_preserves_the_valid_envelope() {
        let points = [
            AuthTestFailPoint::AfterTempCreate,
            AuthTestFailPoint::AfterPayload,
            AuthTestFailPoint::AfterPermissions,
            AuthTestFailPoint::BeforeTempSync,
            AuthTestFailPoint::BeforeRename,
        ];

        for point in points {
            let directory = TestDirectory::new("unwrap-precommit");
            let payload: Vec<_> = (0..150_013)
                .map(|index| (index as u8).wrapping_mul(53).wrapping_add(7))
                .collect();
            let (input, key) = write_fixture(&directory, &payload);
            assert_committed(seal_in_place(&input, &key).unwrap());
            let envelope = fs::read(&input).unwrap();
            let input_identity = identity_at_path(&input).unwrap();
            let entries = directory.entries();

            let _guard = fail_at(point);
            let error = unwrap_in_place(&input, &key).unwrap_err();

            assert!(error.to_string().contains("injected failure"));
            assert_eq!(fs::read(&input).unwrap(), envelope, "point {point:?}");
            assert_eq!(fs::read(&key).unwrap(), test_key(), "point {point:?}");
            assert_eq!(identity_at_path(&input).unwrap(), input_identity);
            assert_eq!(directory.entries(), entries, "point {point:?}");
        }
    }

    #[test]
    fn postcommit_directory_sync_failure_is_never_reported_as_precommit() {
        let directory = TestDirectory::new("postcommit");
        let payload = b"the replacement must already be visible";
        let (input, key) = write_fixture(&directory, payload);

        let _guard = fail_at(AuthTestFailPoint::ParentSync);
        let seal_outcome = seal_in_place(&input, &key).unwrap();
        assert!(matches!(
            seal_outcome,
            AuthOutcome::CommittedButDurabilityUncertain(_)
        ));
        verify_file(&input, &key).unwrap();

        let _guard = fail_at(AuthTestFailPoint::ParentSync);
        let unwrap_outcome = unwrap_in_place(&input, &key).unwrap();
        assert!(matches!(
            unwrap_outcome,
            AuthOutcome::CommittedButDurabilityUncertain(_)
        ));
        assert_eq!(fs::read(input).unwrap(), payload);
    }

    #[test]
    fn malformed_key_is_rejected_before_temporary_output_creation() {
        for length in [0, AUTH_KEY_LENGTH - 1, AUTH_KEY_LENGTH + 1] {
            let directory = TestDirectory::new("bad-key-order");
            let input = directory.join("payload.bin");
            let key = directory.join(AUTH_KEY_FILE_NAME);
            fs::write(&input, b"payload").unwrap();
            fs::write(&key, vec![0x55; length]).unwrap();
            let entries = directory.entries();

            let _guard = fail_at(AuthTestFailPoint::AfterTempCreate);
            let error = seal_in_place(&input, &key).unwrap_err();

            assert!(matches!(error, AuthError::InvalidKeyLength { .. }));
            assert_eq!(fs::read(&input).unwrap(), b"payload");
            assert_eq!(directory.entries(), entries);
        }
    }

    #[test]
    fn staged_envelope_corruption_is_detected_before_replacement() {
        let payload: Vec<_> = (0..150_013)
            .map(|index| (index as u8).wrapping_mul(29).wrapping_add(3))
            .collect();
        let envelope_len = envelope_length(payload.len() as u64).unwrap();
        let offsets = [
            0,
            HEADER_LENGTH as u64 + payload.len() as u64 / 2,
            envelope_len - 1,
        ];

        for offset in offsets {
            let directory = TestDirectory::new("corrupt-staged-envelope");
            let (input, key) = write_fixture(&directory, &payload);
            let original_identity = identity_at_path(&input).unwrap();
            let original_entries = directory.entries();

            let _guard = fail_at(AuthTestFailPoint::CorruptAfterSync(offset));
            let error = seal_in_place(&input, &key).unwrap_err();

            assert!(matches!(error, AuthError::StagedOutputInvalid { .. }));
            assert_eq!(fs::read(&input).unwrap(), payload, "offset {offset}");
            assert_eq!(identity_at_path(&input).unwrap(), original_identity);
            assert_eq!(fs::read(&key).unwrap(), test_key());
            assert_eq!(directory.entries(), original_entries);
        }
    }

    #[test]
    fn staged_unwrapped_payload_corruption_is_detected_before_replacement() {
        for payload in [
            Vec::new(),
            (0..150_013)
                .map(|index| (index as u8).wrapping_mul(41).wrapping_add(17))
                .collect(),
        ] {
            let offsets: Vec<u64> = if payload.is_empty() {
                vec![0]
            } else {
                vec![0, payload.len() as u64 / 2, payload.len() as u64 - 1]
            };
            for offset in offsets {
                let directory = TestDirectory::new("corrupt-staged-unwrapped");
                let (input, key) = write_fixture(&directory, &payload);
                assert_committed(seal_in_place(&input, &key).unwrap());
                let envelope = fs::read(&input).unwrap();
                let envelope_identity = identity_at_path(&input).unwrap();
                let original_entries = directory.entries();

                let _guard = fail_at(AuthTestFailPoint::CorruptAfterSync(offset));
                let error = unwrap_in_place(&input, &key).unwrap_err();

                assert!(matches!(error, AuthError::StagedOutputInvalid { .. }));
                assert_eq!(fs::read(&input).unwrap(), envelope, "offset {offset}");
                assert_eq!(identity_at_path(&input).unwrap(), envelope_identity);
                assert_eq!(fs::read(&key).unwrap(), test_key());
                assert_eq!(directory.entries(), original_entries);
            }
        }
    }

    #[test]
    fn virtual_multichunk_seal_stream_is_bounded_and_exact() {
        fn byte_at(position: u64) -> u8 {
            (position as u8)
                .wrapping_mul(73)
                .wrapping_add((position >> 11) as u8)
                .wrapping_add(19)
        }

        struct GeneratedReader {
            position: u64,
            length: u64,
            fail_at: Option<u64>,
            largest_request: usize,
        }

        impl Read for GeneratedReader {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                assert!(buffer.len() <= STREAM_BUFFER_SIZE);
                self.largest_request = self.largest_request.max(buffer.len());
                if self.fail_at == Some(self.position) {
                    return Err(io::Error::other("injected late generated-read failure"));
                }
                if self.position == self.length {
                    return Ok(0);
                }
                let amount = buffer
                    .len()
                    .min(4093)
                    .min((self.length - self.position) as usize);
                for (offset, byte) in buffer[..amount].iter_mut().enumerate() {
                    *byte = byte_at(self.position + offset as u64);
                }
                self.position += amount as u64;
                Ok(amount)
            }
        }

        struct VerifyingWriter {
            position: u64,
            largest_request: usize,
        }

        impl Write for VerifyingWriter {
            fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
                assert!(buffer.len() <= STREAM_BUFFER_SIZE);
                self.largest_request = self.largest_request.max(buffer.len());
                let amount = buffer.len().min(997);
                for (offset, byte) in buffer[..amount].iter().enumerate() {
                    assert_eq!(*byte, byte_at(self.position + offset as u64));
                }
                self.position += amount as u64;
                Ok(amount)
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let length = STREAM_BUFFER_SIZE as u64 * 32 + 137;
        let mut input = GeneratedReader {
            position: 0,
            length,
            fail_at: None,
            largest_request: 0,
        };
        let mut output = VerifyingWriter {
            position: 0,
            largest_request: 0,
        };
        let mut mac = new_mac(&test_key());
        stream_payload_for_seal(
            &mut input,
            &mut output,
            &mut mac,
            length,
            Path::new("virtual-input"),
            Path::new("virtual-output"),
        )
        .unwrap();
        assert_eq!(input.position, length);
        assert_eq!(output.position, length);
        assert_eq!(input.largest_request, STREAM_BUFFER_SIZE);
        assert_eq!(output.largest_request, STREAM_BUFFER_SIZE);

        let fail_at = STREAM_BUFFER_SIZE as u64 * 3;
        let mut input = GeneratedReader {
            position: 0,
            length,
            fail_at: Some(fail_at),
            largest_request: 0,
        };
        let mut output = VerifyingWriter {
            position: 0,
            largest_request: 0,
        };
        let error = stream_payload_for_seal(
            &mut input,
            &mut output,
            &mut new_mac(&test_key()),
            length,
            Path::new("virtual-input"),
            Path::new("virtual-output"),
        )
        .unwrap_err();
        assert!(matches!(error, AuthError::Io { .. }));
        assert_eq!(input.position, fail_at);
        assert_eq!(output.position, fail_at);
    }
}
