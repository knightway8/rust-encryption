//! Reliable, atomic, Linux-only one-time-pad-style file transformation.
//!
//! The transformation is deliberately simple: byte `n` of the input is XORed
//! with byte `n` of the key.  XOR is its own inverse, so running the program a
//! second time with the same key restores the original bytes.

#[cfg(not(target_os = "linux"))]
compile_error!("otp2 supports Linux targets only");

use std::env;
use std::error::Error;
use std::ffi::{CString, OsStr, OsString};
use std::fmt;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::SystemTime;
use zeroize::Zeroizing;

/// The key filename expected beside the running executable.
pub const KEY_FILE_NAME: &str = "key.key";

const BUFFER_SIZE: usize = 64 * 1024;
const TEMP_CREATE_ATTEMPTS: usize = 256;
// Some supported 32-bit Linux targets do not provide 64-bit atomics.
static TEMP_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

/// The result of a successful atomic replacement.
#[derive(Debug)]
pub enum EncryptOutcome {
    /// The replacement and Linux synchronization steps completed successfully.
    Committed,
    /// The replacement happened, but a syscall result or directory
    /// synchronization did not confirm crash durability.
    ///
    /// The caller must not blindly retry: applying the same XOR operation again
    /// would reverse the completed transformation.
    CommittedButDurabilityUncertain(io::Error),
}

/// An error from an attempted file transformation.
#[derive(Debug)]
pub enum OtpError {
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
    KeyTooShort {
        key_path: PathBuf,
        key_len: u64,
        input_len: u64,
    },
    InputIsKey {
        input_path: PathBuf,
        key_path: PathBuf,
    },
    ConcurrentModification {
        path: PathBuf,
    },
    /// A rename reported failure and the pinned namespace could not prove
    /// whether the staged output replaced the input.
    ///
    /// The caller must not retry blindly: another XOR could reverse a
    /// transformation which actually committed.
    CommitOutcomeUncertain {
        path: PathBuf,
        source: io::Error,
    },
    NoExecutableDirectory {
        executable: PathBuf,
    },
}

impl OtpError {
    fn io(action: &'static str, path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::Io {
            action,
            path: path.into(),
            source,
        }
    }
}

impl fmt::Display for OtpError {
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
            Self::KeyTooShort {
                key_path,
                key_len,
                input_len,
            } => write!(
                formatter,
                "key is too short: '{}' has {key_len} bytes but the input needs {input_len}",
                key_path.display()
            ),
            Self::InputIsKey {
                input_path,
                key_path,
            } => write!(
                formatter,
                "input '{}' and key '{}' refer to the same file",
                input_path.display(),
                key_path.display()
            ),
            Self::ConcurrentModification { path } => write!(
                formatter,
                "'{}' changed while it was being transformed; the original path was not replaced",
                path.display()
            ),
            Self::CommitOutcomeUncertain { path, source } => write!(
                formatter,
                "the atomic-replacement outcome for '{}' could not be determined: {source}; DO NOT RETRY automatically—inspect both the input and temporary entries first",
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

impl Error for OtpError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } | Self::CommitOutcomeUncertain { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Return the `key.key` path beside the executable reported by the operating
/// system for the current process.
pub fn key_path_next_to_current_exe() -> Result<PathBuf, OtpError> {
    let executable = env::current_exe()
        .map_err(|source| OtpError::io("cannot locate the running executable", "otp2", source))?;
    let directory = executable
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or_else(|| OtpError::NoExecutableDirectory {
            executable: executable.clone(),
        })?;
    Ok(directory.join(KEY_FILE_NAME))
}

/// XOR exactly `length` bytes from `input` and `key` into `output`.
///
/// The function uses bounded memory, accepts short reads/writes, and relies on
/// `read_exact`/`write_all` to retry interrupted operations.  An early EOF from
/// either reader is returned as an error.
pub fn xor_stream_exact<R, K, W>(
    input: &mut R,
    key: &mut K,
    output: &mut W,
    length: u64,
) -> io::Result<()>
where
    R: Read + ?Sized,
    K: Read + ?Sized,
    W: Write + ?Sized,
{
    // Both buffers can contain plaintext or key material. `Zeroizing` clears
    // their full stack allocations on every return path, including I/O errors.
    let mut input_buffer = Zeroizing::new([0_u8; BUFFER_SIZE]);
    let mut key_buffer = Zeroizing::new([0_u8; BUFFER_SIZE]);
    let mut remaining = length;

    while remaining != 0 {
        let amount = usize::try_from(remaining.min(BUFFER_SIZE as u64))
            .expect("the bounded chunk size always fits usize");
        input.read_exact(&mut input_buffer[..amount])?;
        key.read_exact(&mut key_buffer[..amount])?;

        for (input_byte, key_byte) in input_buffer[..amount].iter_mut().zip(&key_buffer[..amount]) {
            *input_byte ^= *key_byte;
        }

        output.write_all(&input_buffer[..amount])?;
        remaining -= amount as u64;
    }

    Ok(())
}

/// Atomically XOR-transform `input_path` using `key_path`.
///
/// No write is made to the input path until a complete sibling temporary file
/// has been written and synchronized.  A key shorter than the input is rejected
/// before a temporary file is created or any input content is read. If rename
/// reports an error, the pinned source and destination identities determine
/// whether the operation committed, did not commit, or has an uncertain
/// outcome. [`OtpError::CommitOutcomeUncertain`] must never be retried blindly.
pub fn encrypt_in_place(
    input_path: impl AsRef<Path>,
    key_path: impl AsRef<Path>,
) -> Result<EncryptOutcome, OtpError> {
    let input_path = anchor_parent(input_path.as_ref(), "input file")?;
    let key_path = anchor_parent(key_path.as_ref(), "key file")?;
    let input_path = input_path.as_path();
    let key_path = key_path.as_path();

    // Pin both containing directories before opening either file. Every later
    // pathname operation is relative to these descriptors, so renaming or
    // replacing an ancestor cannot redirect an in-flight transaction.
    let input_directory = ParentDirectory::open(usable_parent(input_path)).map_err(|source| {
        OtpError::io(
            "cannot open input directory",
            usable_parent(input_path),
            source,
        )
    })?;
    let key_directory = ParentDirectory::open(usable_parent(key_path)).map_err(|source| {
        OtpError::io("cannot open key directory", usable_parent(key_path), source)
    })?;

    let (mut input, input_metadata) =
        open_regular_file(&input_directory, "input file", input_path)?;
    let (mut key, key_metadata) = open_regular_file(&key_directory, "key file", key_path)?;

    if let Some(reason) = linux_key_security_rejection_reason(
        key_metadata.mode(),
        key_metadata.uid(),
        effective_uid(),
    ) {
        return Err(OtpError::InvalidFile {
            role: "key file",
            path: key_path.to_path_buf(),
            reason,
        });
    }
    if key_metadata.nlink() > 1 {
        return Err(OtpError::InvalidFile {
            role: "key file",
            path: key_path.to_path_buf(),
            reason: "must not have multiple hard links",
        });
    }

    let input_len = input_metadata.len();
    let key_len = key_metadata.len();
    if key_len < input_len {
        return Err(OtpError::KeyTooShort {
            key_path: key_path.to_path_buf(),
            key_len,
            input_len,
        });
    }

    let input_snapshot = FileSnapshot::from_open_file(&input, &input_metadata)
        .map_err(|source| OtpError::io("cannot identify open input file", input_path, source))?;
    let key_snapshot = FileSnapshot::from_open_file(&key, &key_metadata)
        .map_err(|source| OtpError::io("cannot identify open key file", key_path, source))?;

    ensure_path_still_refers_to(&input_directory, input_path, input_snapshot.identity())?;
    ensure_path_still_refers_to(&key_directory, key_path, key_snapshot.identity())?;

    if input_snapshot.identity() == key_snapshot.identity() {
        return Err(OtpError::InputIsKey {
            input_path: input_path.to_path_buf(),
            key_path: key_path.to_path_buf(),
        });
    }

    if input_snapshot.link_count() > 1 {
        return Err(OtpError::InvalidFile {
            role: "input file",
            path: input_path.to_path_buf(),
            reason: "must not have multiple hard links",
        });
    }

    let original_permissions = input_metadata.permissions();
    let parent = usable_parent(input_path);
    let mut temporary = SiblingTemp::create(&input_directory)
        .map_err(|source| OtpError::io("cannot create temporary output", parent, source))?;
    #[cfg(test)]
    inject_test_failure(TestFailPoint::AfterTempCreate).map_err(|source| {
        OtpError::io(
            "injected failure after temporary output creation",
            temporary.path.clone(),
            source,
        )
    })?;

    xor_stream_exact(&mut input, &mut key, &mut temporary.file, input_len).map_err(|source| {
        OtpError::io(
            "cannot create complete transformed output",
            temporary.path.clone(),
            source,
        )
    })?;
    #[cfg(test)]
    inject_test_failure(TestFailPoint::AfterTransform).map_err(|source| {
        OtpError::io(
            "injected failure after transforming output",
            temporary.path.clone(),
            source,
        )
    })?;

    ensure_input_has_no_extra_bytes(&mut input, input_path)?;
    ensure_unchanged(&input, &input_snapshot, input_path)?;
    ensure_unchanged(&key, &key_snapshot, key_path)?;

    temporary
        .file
        .set_permissions(original_permissions)
        .map_err(|source| {
            OtpError::io(
                "cannot preserve input permissions on temporary output",
                temporary.path.clone(),
                source,
            )
        })?;
    #[cfg(test)]
    inject_test_failure(TestFailPoint::AfterPermissions).map_err(|source| {
        OtpError::io(
            "injected failure after preserving permissions",
            temporary.path.clone(),
            source,
        )
    })?;
    temporary.file.flush().map_err(|source| {
        OtpError::io(
            "cannot flush transformed temporary output",
            temporary.path.clone(),
            source,
        )
    })?;
    #[cfg(test)]
    inject_test_failure(TestFailPoint::BeforeTempSync).map_err(|source| {
        OtpError::io(
            "injected failure before synchronizing temporary output",
            temporary.path.clone(),
            source,
        )
    })?;
    temporary.file.sync_all().map_err(|source| {
        OtpError::io(
            "cannot synchronize transformed temporary output",
            temporary.path.clone(),
            source,
        )
    })?;
    let temporary_metadata = temporary.file.metadata().map_err(|source| {
        OtpError::io(
            "cannot inspect synchronized temporary output",
            temporary.path.clone(),
            source,
        )
    })?;
    let temporary_snapshot = FileSnapshot::from_open_file(&temporary.file, &temporary_metadata)
        .map_err(|source| {
            OtpError::io(
                "cannot identify synchronized temporary output",
                temporary.path.clone(),
                source,
            )
        })?;
    if temporary_snapshot.len != input_len || temporary_snapshot.link_count() != 1 {
        return Err(OtpError::ConcurrentModification {
            path: temporary.path.clone(),
        });
    }

    // Repeat the checks as close to the commit point as possible. The pathname
    // checks and rename are relative to the same pinned directory descriptor,
    // so ancestor-directory replacement cannot redirect the transaction.
    ensure_unchanged(&input, &input_snapshot, input_path)?;
    ensure_unchanged(&key, &key_snapshot, key_path)?;
    ensure_unchanged(&temporary.file, &temporary_snapshot, &temporary.path)?;
    ensure_path_still_refers_to(&input_directory, input_path, input_snapshot.identity())?;
    ensure_path_still_refers_to(&key_directory, key_path, key_snapshot.identity())?;
    #[cfg(test)]
    inject_test_failure(TestFailPoint::BeforeRename).map_err(|source| {
        OtpError::io(
            "injected failure before atomic replacement",
            input_path,
            source,
        )
    })?;

    let commit_warning = match temporary.commit(input_path, input_snapshot.identity()) {
        Ok(warning) => warning,
        Err(CommitFailure::NotCommitted(source)) => {
            return Err(OtpError::io(
                "cannot atomically replace input file",
                input_path,
                source,
            ));
        }
        Err(CommitFailure::OutcomeUncertain(source)) => {
            return Err(OtpError::CommitOutcomeUncertain {
                path: input_path.to_path_buf(),
                source,
            });
        }
    };

    #[cfg(test)]
    let parent_sync_result =
        inject_test_failure(TestFailPoint::ParentSync).and_then(|()| input_directory.sync());
    #[cfg(not(test))]
    let parent_sync_result = input_directory.sync();

    Ok(committed_outcome(commit_warning, parent_sync_result))
}

fn committed_outcome(
    commit_warning: Option<io::Error>,
    directory_sync: io::Result<()>,
) -> EncryptOutcome {
    match (commit_warning, directory_sync) {
        (None, Ok(())) => EncryptOutcome::Committed,
        (Some(source), Ok(())) | (None, Err(source)) => {
            EncryptOutcome::CommittedButDurabilityUncertain(source)
        }
        (Some(commit_source), Err(sync_source)) => {
            EncryptOutcome::CommittedButDurabilityUncertain(io::Error::other(format!(
                "renameat reported an error after the transformed output appeared at its destination ({commit_source}); directory synchronization also failed ({sync_source})"
            )))
        }
    }
}

fn anchor_parent(path: &Path, role: &'static str) -> Result<PathBuf, OtpError> {
    if has_ambiguous_terminal_component(path) {
        return Err(OtpError::InvalidFile {
            role,
            path: path.to_path_buf(),
            reason: "must not end in a separator or '.' component",
        });
    }
    let Some(file_name) = path.file_name() else {
        return Err(OtpError::InvalidFile {
            role,
            path: path.to_path_buf(),
            reason: "must include a filename",
        });
    };
    let parent = usable_parent(path);
    let anchored_parent = fs::canonicalize(parent)
        .map_err(|source| OtpError::io("cannot resolve containing directory", parent, source))?;
    Ok(anchored_parent.join(file_name))
}

fn has_ambiguous_terminal_component(path: &Path) -> bool {
    let bytes = path.as_os_str().as_encoded_bytes();
    bytes.ends_with(b"/") || bytes.ends_with(b"/.")
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
        Ok(Some(FileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        }))
    }

    fn remove_name_if_same_identity(&self, name: &OsStr, identity: FileIdentity) {
        if self.identity_at_name(name).ok() == Some(Some(identity)) {
            let _ = self.unlink_at(name);
        }
    }

    fn replace(&self, source_name: &OsStr, destination: &Path) -> io::Result<()> {
        if usable_parent(destination) != self.path {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "replacement destination is outside the pinned directory",
            ));
        }
        #[cfg(test)]
        if take_test_fail_point(TestFailPoint::RenameReportedErrorWithoutCommit) {
            return Err(io::Error::from_raw_os_error(libc::EINTR));
        }
        #[cfg(test)]
        if take_test_fail_point(TestFailPoint::RenameReportedErrorWithAmbiguousNamespace) {
            let recovery = self.path.join(TEST_AMBIGUOUS_RECOVERY_NAME);
            self.replace_once(source_name, &recovery)?;
            return Err(io::Error::from_raw_os_error(libc::EINTR));
        }
        #[cfg(test)]
        let report_error_after_commit =
            take_test_fail_point(TestFailPoint::RenameCommittedButReportedError);

        let result = self.replace_once(source_name, destination);
        #[cfg(test)]
        if result.is_ok() && report_error_after_commit {
            return Err(io::Error::from_raw_os_error(libc::EINTR));
        }
        result
    }

    fn replace_once(&self, source_name: &OsStr, destination: &Path) -> io::Result<()> {
        if usable_parent(destination) != self.path {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "replacement destination is outside the pinned directory",
            ));
        }
        let source = os_string_to_cstring(source_name)?;
        let destination = os_string_to_cstring(path_file_name(destination)?)?;
        // Do not blindly retry an interrupted rename. Some filesystems can
        // report an error after committing the namespace operation, so the
        // caller must inspect both pinned names before deciding what happened.
        // SAFETY: both C strings are valid and live for the duration of the
        // call, and both directory descriptors remain owned by `self`.
        let result = unsafe {
            libc::renameat(
                self.handle.as_raw_fd(),
                source.as_ptr(),
                self.handle.as_raw_fd(),
                destination.as_ptr(),
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
            // SAFETY: `name` is a valid NUL-terminated pathname, the directory
            // descriptor remains open, and the returned descriptor is uniquely
            // transferred into `File` on success.
            let descriptor =
                unsafe { libc::openat(self.handle.as_raw_fd(), name.as_ptr(), flags, mode) };
            if descriptor >= 0 {
                // SAFETY: `openat` returned a new owned file descriptor.
                return Ok(unsafe { File::from_raw_fd(descriptor) });
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }

    fn unlink_at(&self, name: &OsStr) -> io::Result<()> {
        let encoded_name = os_string_to_cstring(name)?;
        #[cfg(test)]
        let recreate_after_unlink =
            take_test_fail_point(TestFailPoint::UnlinkCommittedButReportedError);
        // An error can be reported after unlink committed. Retrying could then
        // delete a different inode recreated under the same name.
        // SAFETY: `name` and the owned directory descriptor are valid for the
        // duration of the call. A zero flag removes only non-directories.
        let result = unsafe { libc::unlinkat(self.handle.as_raw_fd(), encoded_name.as_ptr(), 0) };
        if result == 0 {
            #[cfg(test)]
            if recreate_after_unlink {
                let mut substitute = self.open_at(
                    name,
                    libc::O_WRONLY
                        | libc::O_CLOEXEC
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW,
                    0o600,
                )?;
                substitute.write_all(TEST_UNLINK_SUBSTITUTE)?;
                return Err(io::Error::from_raw_os_error(libc::EINTR));
            }
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
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

fn linux_key_security_rejection_reason(
    mode: u32,
    owner_uid: u32,
    effective_uid: libc::uid_t,
) -> Option<&'static str> {
    if mode & 0o077 != 0 {
        Some("must not be accessible by group or other users; restrict it to mode 0600 or stricter")
    } else if owner_uid != effective_uid {
        Some("must be owned by the effective user running otp2")
    } else {
        None
    }
}

fn open_regular_file(
    directory: &ParentDirectory,
    role: &'static str,
    path: &Path,
) -> Result<(File, Metadata), OtpError> {
    let inspected = directory
        .inspect_nofollow(path)
        .map_err(|source| OtpError::io("cannot inspect file", path, source))?;
    let inspected_metadata = inspected
        .metadata()
        .map_err(|source| OtpError::io("cannot inspect file", path, source))?;
    if inspected_metadata.file_type().is_symlink() {
        return Err(OtpError::InvalidFile {
            role,
            path: path.to_path_buf(),
            reason: "must not be a symbolic link",
        });
    }
    require_regular_file(role, path, &inspected_metadata)?;
    let inspected_identity = FileIdentity {
        device: inspected_metadata.dev(),
        inode: inspected_metadata.ino(),
    };

    let file = match directory.open_readonly(path) {
        Ok(file) => file,
        Err(source) if is_symlink_open_error(&source) => {
            return Err(OtpError::InvalidFile {
                role,
                path: path.to_path_buf(),
                reason: "must not be a symbolic link",
            });
        }
        Err(source) => return Err(OtpError::io("cannot open file", path, source)),
    };
    let metadata = file
        .metadata()
        .map_err(|source| OtpError::io("cannot inspect open file", path, source))?;
    require_regular_file(role, path, &metadata)?;
    if metadata.dev() != inspected_identity.device || metadata.ino() != inspected_identity.inode {
        return Err(OtpError::ConcurrentModification {
            path: path.to_path_buf(),
        });
    }
    Ok((file, metadata))
}

fn require_regular_file(
    role: &'static str,
    path: &Path,
    metadata: &Metadata,
) -> Result<(), OtpError> {
    if metadata.is_file() {
        Ok(())
    } else {
        Err(OtpError::InvalidFile {
            role,
            path: path.to_path_buf(),
            reason: "must be a regular file",
        })
    }
}

fn usable_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn ensure_input_has_no_extra_bytes(input: &mut File, path: &Path) -> Result<(), OtpError> {
    let mut byte = [0_u8; 1];
    loop {
        match input.read(&mut byte) {
            Ok(0) => return Ok(()),
            Ok(_) => {
                return Err(OtpError::ConcurrentModification {
                    path: path.to_path_buf(),
                });
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(source) => {
                return Err(OtpError::io(
                    "cannot verify the final input length",
                    path,
                    source,
                ));
            }
        }
    }
}

fn ensure_unchanged(file: &File, snapshot: &FileSnapshot, path: &Path) -> Result<(), OtpError> {
    let metadata = file
        .metadata()
        .map_err(|source| OtpError::io("cannot recheck open file", path, source))?;
    let current = FileSnapshot::from_open_file(file, &metadata)
        .map_err(|source| OtpError::io("cannot re-identify open file", path, source))?;
    if &current == snapshot {
        Ok(())
    } else {
        Err(OtpError::ConcurrentModification {
            path: path.to_path_buf(),
        })
    }
}

fn ensure_path_still_refers_to(
    directory: &ParentDirectory,
    path: &Path,
    original: FileIdentity,
) -> Result<(), OtpError> {
    let current = directory
        .identity_at(path)
        .map_err(|source| OtpError::io("cannot recheck file path identity", path, source))?;
    if current == Some(original) {
        Ok(())
    } else {
        Err(OtpError::ConcurrentModification {
            path: path.to_path_buf(),
        })
    }
}

#[cfg(test)]
fn identity_at_path(path: &Path) -> io::Result<Option<FileIdentity>> {
    ParentDirectory::open(usable_parent(path))?.identity_at(path)
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
    platform: PlatformSnapshot,
}

impl FileSnapshot {
    fn from_open_file(file: &File, metadata: &Metadata) -> io::Result<Self> {
        Ok(Self {
            len: metadata.len(),
            modified: metadata.modified().ok(),
            readonly: metadata.permissions().readonly(),
            platform: PlatformSnapshot::from_open_file(file, metadata)?,
        })
    }

    fn identity(&self) -> FileIdentity {
        self.platform.identity()
    }

    fn link_count(&self) -> u64 {
        self.platform.link_count()
    }
}

#[derive(Debug, Eq, PartialEq)]
struct PlatformSnapshot {
    device: u64,
    inode: u64,
    links: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl PlatformSnapshot {
    fn from_open_file(_: &File, metadata: &Metadata) -> io::Result<Self> {
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            links: metadata.nlink(),
            mode: metadata.mode(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        })
    }

    fn identity(&self) -> FileIdentity {
        FileIdentity {
            device: self.device,
            inode: self.inode,
        }
    }

    fn link_count(&self) -> u64 {
        self.links
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
                    let identity = file.metadata().map(|metadata| FileIdentity {
                        device: metadata.dev(),
                        inode: metadata.ino(),
                    });
                    let identity = match identity {
                        Ok(identity) => identity,
                        Err(error) => {
                            drop(file);
                            // The identity could not be established, so avoid
                            // path-based cleanup that might remove a replacement.
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
        expected_destination: FileIdentity,
    ) -> Result<Option<io::Error>, CommitFailure> {
        if self
            .directory
            .identity_at_name(&self.name)
            .map_err(CommitFailure::NotCommitted)?
            != Some(self.identity)
        {
            return Err(CommitFailure::NotCommitted(io::Error::other(
                "temporary output path changed before commit",
            )));
        }
        if self
            .directory
            .identity_at(destination)
            .map_err(CommitFailure::NotCommitted)?
            != Some(expected_destination)
        {
            return Err(CommitFailure::NotCommitted(io::Error::other(
                "destination path changed before commit",
            )));
        }
        if let Err(source) = self.directory.replace(&self.name, destination) {
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
                    // When the pinned names do not prove either outcome,
                    // suppress cleanup. Deleting either name could destroy the
                    // only recoverable copy or a concurrently substituted file.
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
        ".otp2-{}-{sequence:016x}-{nonce:032x}.tmp",
        std::process::id()
    )))
}

#[cfg(test)]
const TEST_AMBIGUOUS_RECOVERY_NAME: &str = ".otp2-test-ambiguous-recovery";
#[cfg(test)]
const TEST_UNLINK_SUBSTITUTE: &[u8] = b"test substitute created after outcome-ambiguous unlink";

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TestFailPoint {
    AfterTempCreate,
    AfterTransform,
    AfterPermissions,
    BeforeTempSync,
    BeforeRename,
    RenameCommittedButReportedError,
    RenameReportedErrorWithoutCommit,
    RenameReportedErrorWithAmbiguousNamespace,
    UnlinkCommittedButReportedError,
    ParentSync,
}

#[cfg(test)]
thread_local! {
    static TEST_FAIL_POINT: std::cell::Cell<Option<TestFailPoint>> = const {
        std::cell::Cell::new(None)
    };
}

#[cfg(test)]
fn inject_test_failure(point: TestFailPoint) -> io::Result<()> {
    if take_test_fail_point(point) {
        Err(io::Error::other(format!(
            "test-injected failure at {point:?}"
        )))
    } else {
        Ok(())
    }
}

#[cfg(test)]
fn take_test_fail_point(point: TestFailPoint) -> bool {
    TEST_FAIL_POINT.with(|selected| {
        if selected.get() == Some(point) {
            selected.set(None);
            true
        } else {
            false
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT_TEST_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            for _ in 0..100 {
                let sequence = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
                let path = env::temp_dir().join(format!(
                    "otp2-lib-{label}-{}-{sequence}",
                    std::process::id()
                ));
                match fs::create_dir(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("cannot create test directory: {error}"),
                }
            }
            panic!("cannot allocate unique test directory")
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

    fn write_private_key(path: &Path, bytes: impl AsRef<[u8]>) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    struct FailPointGuard;

    fn fail_at(point: TestFailPoint) -> FailPointGuard {
        TEST_FAIL_POINT.with(|selected| {
            assert_eq!(selected.get(), None);
            selected.set(Some(point));
        });
        FailPointGuard
    }

    impl Drop for FailPointGuard {
        fn drop(&mut self) {
            TEST_FAIL_POINT.with(|selected| selected.set(None));
        }
    }

    #[test]
    fn zero_length_does_not_touch_any_stream() {
        struct PanicIo;
        impl Read for PanicIo {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                panic!("zero-length transformation read a stream")
            }
        }
        impl Write for PanicIo {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                panic!("zero-length transformation wrote a stream")
            }
            fn flush(&mut self) -> io::Result<()> {
                panic!("zero-length transformation flushed a stream")
            }
        }

        xor_stream_exact(&mut PanicIo, &mut PanicIo, &mut PanicIo, 0).unwrap();
    }

    #[test]
    fn known_answer() {
        let mut input = Cursor::new([0x00, 0x55, 0xaa, 0xff]);
        let mut key = Cursor::new([0xff, 0xaa, 0x55, 0xff]);
        let mut output = Vec::new();
        xor_stream_exact(&mut input, &mut key, &mut output, 4).unwrap();
        assert_eq!(output, [0xff, 0xff, 0xff, 0x00]);
    }

    #[test]
    fn display_for_short_key_is_actionable() {
        let error = OtpError::KeyTooShort {
            key_path: PathBuf::from("key.key"),
            key_len: 2,
            input_len: 3,
        };
        assert!(error.to_string().contains("key is too short"));
        assert!(error.to_string().contains("2"));
        assert!(error.to_string().contains("3"));
    }

    #[test]
    fn linux_raw_key_policy_requires_private_mode_and_ownership() {
        assert_eq!(
            linux_key_security_rejection_reason(0o100600, 1000, 1000),
            None
        );
        assert_eq!(
            linux_key_security_rejection_reason(0o100400, 1000, 1000),
            None
        );
        assert!(linux_key_security_rejection_reason(0o100640, 1000, 1000).is_some());
        assert!(linux_key_security_rejection_reason(0o100600, 1001, 1000).is_some());
    }

    #[test]
    fn multiply_hardlinked_raw_key_is_rejected_before_staging() {
        let directory = TestDirectory::new("hardlinked-key");
        let input_path = directory.join("input.bin");
        let key_path = directory.join("key.key");
        let key_alias = directory.join("key-alias.bin");
        fs::write(&input_path, b"plaintext").unwrap();
        write_private_key(&key_path, b"long-enough-key-material");
        fs::hard_link(&key_path, &key_alias).unwrap();
        let entries = directory.entries();

        let error = encrypt_in_place(&input_path, &key_path).unwrap_err();

        assert!(matches!(
            error,
            OtpError::InvalidFile {
                role: "key file",
                reason: "must not have multiple hard links",
                ..
            }
        ));
        assert_eq!(fs::read(&input_path).unwrap(), b"plaintext");
        assert_eq!(directory.entries(), entries);
    }

    #[test]
    fn every_injected_precommit_failure_preserves_the_original_transaction() {
        let points = [
            TestFailPoint::AfterTempCreate,
            TestFailPoint::AfterTransform,
            TestFailPoint::AfterPermissions,
            TestFailPoint::BeforeTempSync,
            TestFailPoint::BeforeRename,
        ];

        for point in points {
            let directory = TestDirectory::new("precommit-failure");
            let input_path = directory.join("input.bin");
            let key_path = directory.join("key.key");
            let input: Vec<_> = (0..150_000)
                .map(|index| (index as u8).wrapping_mul(37).wrapping_add(11))
                .collect();
            let key: Vec<_> = (0..input.len())
                .map(|index| (index as u8).wrapping_mul(73).wrapping_add(19))
                .collect();
            fs::write(&input_path, &input).unwrap();
            write_private_key(&key_path, &key);
            let input_identity = identity_at_path(&input_path).unwrap();
            let entries = directory.entries();

            let _guard = fail_at(point);
            let error = encrypt_in_place(&input_path, &key_path).unwrap_err();

            assert!(
                error.to_string().contains("injected failure"),
                "point {point:?}: {error}"
            );
            assert_eq!(fs::read(&input_path).unwrap(), input, "point {point:?}");
            assert_eq!(fs::read(&key_path).unwrap(), key, "point {point:?}");
            assert_eq!(
                identity_at_path(&input_path).unwrap(),
                input_identity,
                "point {point:?} replaced the input"
            );
            assert_eq!(
                directory.entries(),
                entries,
                "point {point:?} left a temporary file"
            );
        }
    }

    #[test]
    fn rename_error_after_commit_is_reported_as_committed_and_must_not_be_retried() {
        let directory = TestDirectory::new("rename-committed-error");
        let input_path = directory.join("input.bin");
        let key_path = directory.join("key.key");
        let input = b"an interrupted result can still mean rename committed";
        let key: Vec<_> = (0..input.len())
            .map(|index| (index as u8).wrapping_mul(29).wrapping_add(7))
            .collect();
        let expected: Vec<_> = input.iter().zip(&key).map(|(a, b)| a ^ b).collect();
        fs::write(&input_path, input).unwrap();
        write_private_key(&key_path, &key);
        let original_identity = identity_at_path(&input_path).unwrap();

        let _guard = fail_at(TestFailPoint::RenameCommittedButReportedError);
        let outcome = encrypt_in_place(&input_path, &key_path).unwrap();

        match outcome {
            EncryptOutcome::CommittedButDurabilityUncertain(error) => {
                assert_eq!(error.kind(), io::ErrorKind::Interrupted);
            }
            EncryptOutcome::Committed => panic!("the injected rename error was hidden"),
        }
        assert_eq!(fs::read(&input_path).unwrap(), expected);
        assert_ne!(identity_at_path(&input_path).unwrap(), original_identity);
        assert_eq!(directory.entries().len(), 2);
    }

    #[test]
    fn rename_error_with_staged_source_intact_is_an_ordinary_precommit_failure() {
        let directory = TestDirectory::new("rename-not-committed");
        let input_path = directory.join("input.bin");
        let key_path = directory.join("key.key");
        let input = b"the namespace proves this rename did not commit";
        let key = vec![0x9b; input.len()];
        fs::write(&input_path, input).unwrap();
        write_private_key(&key_path, &key);
        let original_identity = identity_at_path(&input_path).unwrap();
        let original_entries = directory.entries();

        let _guard = fail_at(TestFailPoint::RenameReportedErrorWithoutCommit);
        let error = encrypt_in_place(&input_path, &key_path).unwrap_err();

        match error {
            OtpError::Io { source, .. } => {
                assert_eq!(source.kind(), io::ErrorKind::Interrupted);
            }
            other => panic!("proven precommit failure was misclassified: {other}"),
        }
        assert_eq!(fs::read(&input_path).unwrap(), input);
        assert_eq!(identity_at_path(&input_path).unwrap(), original_identity);
        assert_eq!(directory.entries(), original_entries);
    }

    #[test]
    fn rename_error_with_ambiguous_namespace_is_exit_three_capable_and_preserves_recovery() {
        let directory = TestDirectory::new("rename-outcome-ambiguous");
        let input_path = directory.join("input.bin");
        let key_path = directory.join("key.key");
        let recovery_path = directory.join(TEST_AMBIGUOUS_RECOVERY_NAME);
        let input = b"an ambiguous namespace must never invite an automatic retry";
        let key: Vec<_> = (0..input.len())
            .map(|index| (index as u8).wrapping_mul(17).wrapping_add(3))
            .collect();
        let expected: Vec<_> = input.iter().zip(&key).map(|(a, b)| a ^ b).collect();
        fs::write(&input_path, input).unwrap();
        write_private_key(&key_path, &key);
        let original_identity = identity_at_path(&input_path).unwrap();

        let _guard = fail_at(TestFailPoint::RenameReportedErrorWithAmbiguousNamespace);
        let error = encrypt_in_place(&input_path, &key_path).unwrap_err();

        match error {
            OtpError::CommitOutcomeUncertain { source, .. } => {
                assert_eq!(source.kind(), io::ErrorKind::Interrupted);
            }
            other => panic!("ambiguous commit was misclassified: {other}"),
        }
        assert_eq!(fs::read(&input_path).unwrap(), input);
        assert_eq!(identity_at_path(&input_path).unwrap(), original_identity);
        assert_eq!(fs::read(&recovery_path).unwrap(), expected);
        assert_eq!(directory.entries().len(), 3);
    }

    #[test]
    fn cleanup_does_not_retry_outcome_ambiguous_unlink_or_delete_a_substitute() {
        let directory = TestDirectory::new("unlink-outcome-ambiguous");
        let parent = ParentDirectory::open(&directory.0).unwrap();
        let temporary = SiblingTemp::create(&parent).unwrap();
        let temporary_path = temporary.path.clone();
        let temporary_identity = temporary.identity;

        let _guard = fail_at(TestFailPoint::UnlinkCommittedButReportedError);
        drop(temporary);

        assert_eq!(fs::read(&temporary_path).unwrap(), TEST_UNLINK_SUBSTITUTE);
        assert_ne!(
            identity_at_path(&temporary_path).unwrap(),
            Some(temporary_identity)
        );
    }

    #[test]
    fn injected_parent_sync_failure_is_reported_as_already_committed() {
        let directory = TestDirectory::new("postcommit-failure");
        let input_path = directory.join("input.bin");
        let key_path = directory.join("key.key");
        let input = b"the rename must already be committed";
        let key: Vec<_> = (0..input.len()).map(|index| index as u8 ^ 0xa5).collect();
        let expected: Vec<_> = input.iter().zip(&key).map(|(a, b)| a ^ b).collect();
        fs::write(&input_path, input).unwrap();
        write_private_key(&key_path, &key);

        let _guard = fail_at(TestFailPoint::ParentSync);
        let outcome = encrypt_in_place(&input_path, &key_path).unwrap();

        match outcome {
            EncryptOutcome::CommittedButDurabilityUncertain(error) => {
                assert!(error.to_string().contains("test-injected failure"));
            }
            EncryptOutcome::Committed => panic!("postcommit sync failure was hidden"),
        }
        assert_eq!(fs::read(input_path).unwrap(), expected);
        assert_eq!(fs::read(key_path).unwrap(), key);
        assert_eq!(directory.entries().len(), 2);
    }

    #[test]
    fn short_key_is_rejected_before_the_temp_creation_failpoint() {
        let directory = TestDirectory::new("short-key-order");
        let input_path = directory.join("input.bin");
        let key_path = directory.join("key.key");
        fs::write(&input_path, b"four").unwrap();
        write_private_key(&key_path, b"key");
        let entries = directory.entries();

        let _guard = fail_at(TestFailPoint::AfterTempCreate);
        let error = encrypt_in_place(&input_path, &key_path).unwrap_err();

        assert!(matches!(error, OtpError::KeyTooShort { .. }));
        assert_eq!(fs::read(input_path).unwrap(), b"four");
        assert_eq!(directory.entries(), entries);
    }

    #[test]
    fn terminal_separator_or_dot_never_changes_a_file_paths_meaning() {
        let directory = TestDirectory::new("terminal-component");
        let input_path = directory.join("input.bin");
        let key_path = directory.join("key.key");
        let original = b"this regular file must not match a directory-shaped path";
        fs::write(&input_path, original).unwrap();
        write_private_key(&key_path, vec![0x77; original.len()]);
        let input_identity = identity_at_path(&input_path).unwrap();

        for suffix in ["/", "/."] {
            let mut ambiguous = input_path.clone().into_os_string();
            ambiguous.push(suffix);
            let error = encrypt_in_place(PathBuf::from(ambiguous), &key_path).unwrap_err();
            assert!(matches!(error, OtpError::InvalidFile { .. }));
            assert_eq!(fs::read(&input_path).unwrap(), original);
            assert_eq!(identity_at_path(&input_path).unwrap(), input_identity);
        }
    }
}
