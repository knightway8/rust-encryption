//! Reliable, atomic, one-time-pad-style file transformation.
//!
//! The transformation is deliberately simple: byte `n` of the input is XORed
//! with byte `n` of the key.  XOR is its own inverse, so running the program a
//! second time with the same key restores the original bytes.

pub mod auth;

#[cfg(not(any(unix, windows)))]
compile_error!("otp1 currently supports Unix and Windows targets");

use std::collections::hash_map::RandomState;
use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::fmt;
use std::fs::{self, File, Metadata, OpenOptions};
use std::hash::{BuildHasher, Hasher};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// The key filename expected beside the running executable.
pub const KEY_FILE_NAME: &str = "key.key";

const BUFFER_SIZE: usize = 64 * 1024;
const TEMP_CREATE_ATTEMPTS: usize = 256;
// Some supported 32-bit Unix targets do not provide 64-bit atomics.
static TEMP_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

/// The result of a successful atomic replacement.
#[derive(Debug)]
pub enum EncryptOutcome {
    /// The replacement and all platform-supported synchronization steps
    /// completed successfully.
    Committed,
    /// The replacement happened, but synchronizing the directory failed.
    ///
    /// The caller must not blindly retry: applying the same XOR operation again
    /// would reverse the completed transformation.
    CommittedButDurabilityUncertain(io::Error),
}

/// An error that happened before the atomic replacement was committed.
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
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Return the `key.key` path beside the executable reported by the operating
/// system for the current process.
pub fn key_path_next_to_current_exe() -> Result<PathBuf, OtpError> {
    let executable = env::current_exe()
        .map_err(|source| OtpError::io("cannot locate the running executable", "otp1", source))?;
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
    let mut input_buffer = [0_u8; BUFFER_SIZE];
    let mut key_buffer = [0_u8; BUFFER_SIZE];
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
/// before a temporary file is created or any input content is read.
pub fn encrypt_in_place(
    input_path: impl AsRef<Path>,
    key_path: impl AsRef<Path>,
) -> Result<EncryptOutcome, OtpError> {
    let input_path = anchor_parent(input_path.as_ref(), "input file")?;
    let key_path = anchor_parent(key_path.as_ref(), "key file")?;
    let input_path = input_path.as_path();
    let key_path = key_path.as_path();

    let input_link_metadata = fs::symlink_metadata(input_path)
        .map_err(|source| OtpError::io("cannot inspect input file", input_path, source))?;
    if input_link_metadata.file_type().is_symlink() {
        return Err(OtpError::InvalidFile {
            role: "input file",
            path: input_path.to_path_buf(),
            reason: "must not be a symbolic link",
        });
    }
    require_regular_file("input file", input_path, &input_link_metadata)?;

    let mut input = File::open(input_path)
        .map_err(|source| OtpError::io("cannot open input file", input_path, source))?;
    let input_metadata = input
        .metadata()
        .map_err(|source| OtpError::io("cannot inspect open input file", input_path, source))?;
    require_regular_file("input file", input_path, &input_metadata)?;

    let key_link_metadata = fs::symlink_metadata(key_path)
        .map_err(|source| OtpError::io("cannot inspect key file", key_path, source))?;
    if key_link_metadata.file_type().is_symlink() {
        return Err(OtpError::InvalidFile {
            role: "key file",
            path: key_path.to_path_buf(),
            reason: "must not be a symbolic link",
        });
    }
    require_regular_file("key file", key_path, &key_link_metadata)?;

    let mut key = File::open(key_path)
        .map_err(|source| OtpError::io("cannot open key file", key_path, source))?;
    let key_metadata = key
        .metadata()
        .map_err(|source| OtpError::io("cannot inspect open key file", key_path, source))?;
    require_regular_file("key file", key_path, &key_metadata)?;

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

    ensure_path_still_refers_to(input_path, input_snapshot.identity())?;
    ensure_path_still_refers_to(key_path, key_snapshot.identity())?;

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
    let parent_directory = ParentDirectory::open(parent)
        .map_err(|source| OtpError::io("cannot open input directory", parent, source))?;
    let mut temporary = SiblingTemp::create(parent)
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

    // Repeat the checks as close to the commit point as portable path-based
    // APIs allow. These checks catch many ordinary editors, truncation, chmod,
    // and path replacement races. An uncooperative process can still race the
    // final path-based rename after these checks.
    ensure_unchanged(&input, &input_snapshot, input_path)?;
    ensure_unchanged(&key, &key_snapshot, key_path)?;
    ensure_unchanged(&temporary.file, &temporary_snapshot, &temporary.path)?;
    ensure_path_still_refers_to(input_path, input_snapshot.identity())?;
    ensure_path_still_refers_to(key_path, key_snapshot.identity())?;
    #[cfg(test)]
    inject_test_failure(TestFailPoint::BeforeRename).map_err(|source| {
        OtpError::io(
            "injected failure before atomic replacement",
            input_path,
            source,
        )
    })?;

    temporary.commit(input_path).map_err(|source| {
        OtpError::io("cannot atomically replace input file", input_path, source)
    })?;

    #[cfg(test)]
    let parent_sync_result =
        inject_test_failure(TestFailPoint::ParentSync).and_then(|()| parent_directory.sync());
    #[cfg(not(test))]
    let parent_sync_result = parent_directory.sync();

    match parent_sync_result {
        Ok(()) => Ok(EncryptOutcome::Committed),
        Err(source) => Ok(EncryptOutcome::CommittedButDurabilityUncertain(source)),
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
    #[cfg(unix)]
    {
        bytes.ends_with(b"/") || bytes.ends_with(b"/.")
    }
    #[cfg(windows)]
    {
        bytes.ends_with(b"/")
            || bytes.ends_with(b"\\")
            || bytes.ends_with(b"/.")
            || bytes.ends_with(b"\\.")
    }
}

struct ParentDirectory {
    #[cfg(unix)]
    handle: File,
}

impl ParentDirectory {
    fn open(path: &Path) -> io::Result<Self> {
        #[cfg(unix)]
        {
            Ok(Self {
                handle: File::open(path)?,
            })
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            Ok(Self {})
        }
    }

    fn sync(&self) -> io::Result<()> {
        #[cfg(unix)]
        {
            self.handle.sync_all()
        }
        #[cfg(not(unix))]
        {
            Ok(())
        }
    }
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

fn ensure_path_still_refers_to(path: &Path, original: FileIdentity) -> Result<(), OtpError> {
    let current = identity_at_path(path)
        .map_err(|source| OtpError::io("cannot recheck file path identity", path, source))?;
    if current == Some(original) {
        Ok(())
    } else {
        Err(OtpError::ConcurrentModification {
            path: path.to_path_buf(),
        })
    }
}

fn identity_at_path(path: &Path) -> io::Result<Option<FileIdentity>> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Ok(None);
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(Some(FileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        }))
    }
    #[cfg(windows)]
    {
        let file = File::open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Ok(None);
        }
        Ok(Some(
            FileSnapshot::from_open_file(&file, &metadata)?.identity(),
        ))
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    volume: u64,
    identifier: [u8; 16],
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

#[cfg(unix)]
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

#[cfg(unix)]
impl PlatformSnapshot {
    fn from_open_file(_: &File, metadata: &Metadata) -> io::Result<Self> {
        use std::os::unix::fs::MetadataExt;

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

#[cfg(windows)]
#[derive(Debug, Eq, PartialEq)]
struct PlatformSnapshot {
    identity: FileIdentity,
    links: u32,
    attributes: u32,
    creation_time: u64,
    last_write_time: u64,
}

#[cfg(windows)]
impl PlatformSnapshot {
    fn from_open_file(file: &File, metadata: &Metadata) -> io::Result<Self> {
        use std::os::windows::fs::MetadataExt;

        let information = windows_file_information(file)?;
        let identity = windows_extended_file_identity(file)?;
        Ok(Self {
            identity,
            links: information.number_of_links,
            attributes: metadata.file_attributes(),
            creation_time: metadata.creation_time(),
            last_write_time: metadata.last_write_time(),
        })
    }

    fn identity(&self) -> FileIdentity {
        self.identity
    }

    fn link_count(&self) -> u64 {
        u64::from(self.links)
    }
}

#[cfg(windows)]
#[repr(C)]
struct WindowsFileTime {
    _low: u32,
    _high: u32,
}

#[cfg(windows)]
#[repr(C)]
struct WindowsFileInformation {
    _file_attributes: u32,
    _creation_time: WindowsFileTime,
    _last_access_time: WindowsFileTime,
    _last_write_time: WindowsFileTime,
    _volume_serial_number: u32,
    _file_size_high: u32,
    _file_size_low: u32,
    number_of_links: u32,
    _file_index_high: u32,
    _file_index_low: u32,
}

#[cfg(windows)]
#[repr(C)]
struct WindowsFileIdInformation {
    volume_serial_number: u64,
    identifier: [u8; 16],
}

#[cfg(windows)]
fn windows_file_information(file: &File) -> io::Result<WindowsFileInformation> {
    use std::ffi::c_void;
    use std::mem::MaybeUninit;
    use std::os::windows::io::AsRawHandle;

    #[link(name = "Kernel32")]
    unsafe extern "system" {
        fn GetFileInformationByHandle(
            file: *mut c_void,
            information: *mut WindowsFileInformation,
        ) -> i32;
    }

    let mut information = MaybeUninit::<WindowsFileInformation>::uninit();
    // SAFETY: the raw handle remains valid for the call and `information`
    // points to writable storage with the exact C structure layout expected by
    // GetFileInformationByHandle. A nonzero return initializes every field.
    let result = unsafe {
        GetFileInformationByHandle(file.as_raw_handle().cast(), information.as_mut_ptr())
    };
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: a successful GetFileInformationByHandle call initialized the
        // entire BY_HANDLE_FILE_INFORMATION-compatible structure.
        Ok(unsafe { information.assume_init() })
    }
}

#[cfg(windows)]
fn windows_extended_file_identity(file: &File) -> io::Result<FileIdentity> {
    use std::ffi::c_void;
    use std::mem::{MaybeUninit, size_of};
    use std::os::windows::io::AsRawHandle;

    const FILE_ID_INFO: i32 = 0x12;

    #[link(name = "Kernel32")]
    unsafe extern "system" {
        fn GetFileInformationByHandleEx(
            file: *mut c_void,
            information_class: i32,
            information: *mut c_void,
            buffer_size: u32,
        ) -> i32;
    }

    let mut information = MaybeUninit::<WindowsFileIdInformation>::uninit();
    // SAFETY: the handle and output buffer are valid for the duration of the
    // call, the class value is FileIdInfo, and the exact buffer size is passed.
    let result = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle().cast(),
            FILE_ID_INFO,
            information.as_mut_ptr().cast(),
            u32::try_from(size_of::<WindowsFileIdInformation>())
                .expect("FILE_ID_INFO structure size fits DWORD"),
        )
    };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: a successful GetFileInformationByHandleEx call initialized the
    // entire FILE_ID_INFO-compatible structure.
    let information = unsafe { information.assume_init() };
    let unusable = information.identifier.iter().all(|byte| *byte == 0)
        || information.identifier.iter().all(|byte| *byte == u8::MAX);
    if unusable {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the filesystem did not provide a stable 128-bit file identity",
        ))
    } else {
        Ok(FileIdentity {
            volume: information.volume_serial_number,
            identifier: information.identifier,
        })
    }
}

struct SiblingTemp {
    file: File,
    path: PathBuf,
    identity: FileIdentity,
    committed: bool,
}

impl SiblingTemp {
    fn create(parent: &Path) -> io::Result<Self> {
        for _ in 0..TEMP_CREATE_ATTEMPTS {
            let path = parent.join(unique_temp_name());
            let mut options = OpenOptions::new();
            options.read(true).write(true).create_new(true);

            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }

            match options.open(&path) {
                Ok(file) => {
                    let identity = file.metadata().and_then(|metadata| {
                        FileSnapshot::from_open_file(&file, &metadata)
                            .map(|snapshot| snapshot.identity())
                    });
                    let identity = match identity {
                        Ok(identity) => identity,
                        Err(error) => {
                            drop(file);
                            let _ = fs::remove_file(&path);
                            return Err(error);
                        }
                    };
                    return Ok(Self {
                        file,
                        path,
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

    fn commit(mut self, destination: &Path) -> io::Result<()> {
        if identity_at_path(&self.path)? != Some(self.identity) {
            return Err(io::Error::other(
                "temporary output path changed before commit",
            ));
        }
        atomic_replace(&self.path, destination)?;
        self.committed = true;
        Ok(())
    }
}

impl Drop for SiblingTemp {
    fn drop(&mut self) {
        if !self.committed && identity_at_path(&self.path).ok() == Some(Some(self.identity)) {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn unique_temp_name() -> OsString {
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let random_state = RandomState::new();
    let mut hasher = random_state.build_hasher();
    hasher.write_u32(std::process::id());
    hasher.write_usize(sequence);
    hasher.write_u128(now);
    let nonce = hasher.finish();
    OsString::from(format!(
        ".otp1-{}-{sequence:016x}-{nonce:016x}.tmp",
        std::process::id()
    ))
}

fn atomic_replace(source: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(source, destination)
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TestFailPoint {
    AfterTempCreate,
    AfterTransform,
    AfterPermissions,
    BeforeTempSync,
    BeforeRename,
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
    TEST_FAIL_POINT.with(|selected| {
        if selected.get() == Some(point) {
            selected.set(None);
            Err(io::Error::other(format!(
                "test-injected failure at {point:?}"
            )))
        } else {
            Ok(())
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT_TEST_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            for _ in 0..100 {
                let sequence = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
                let path = env::temp_dir().join(format!(
                    "otp1-lib-{label}-{}-{sequence}",
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
            fs::write(&key_path, &key).unwrap();
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
    fn injected_parent_sync_failure_is_reported_as_already_committed() {
        let directory = TestDirectory::new("postcommit-failure");
        let input_path = directory.join("input.bin");
        let key_path = directory.join("key.key");
        let input = b"the rename must already be committed";
        let key: Vec<_> = (0..input.len()).map(|index| index as u8 ^ 0xa5).collect();
        let expected: Vec<_> = input.iter().zip(&key).map(|(a, b)| a ^ b).collect();
        fs::write(&input_path, input).unwrap();
        fs::write(&key_path, &key).unwrap();

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
        fs::write(&key_path, b"key").unwrap();
        let entries = directory.entries();

        let _guard = fail_at(TestFailPoint::AfterTempCreate);
        let error = encrypt_in_place(&input_path, &key_path).unwrap_err();

        assert!(matches!(error, OtpError::KeyTooShort { .. }));
        assert_eq!(fs::read(input_path).unwrap(), b"four");
        assert_eq!(directory.entries(), entries);
    }

    #[cfg(unix)]
    #[test]
    fn terminal_separator_or_dot_never_changes_a_file_paths_meaning() {
        let directory = TestDirectory::new("terminal-component");
        let input_path = directory.join("input.bin");
        let key_path = directory.join("key.key");
        let original = b"this regular file must not match a directory-shaped path";
        fs::write(&input_path, original).unwrap();
        fs::write(&key_path, vec![0x77; original.len()]).unwrap();
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
