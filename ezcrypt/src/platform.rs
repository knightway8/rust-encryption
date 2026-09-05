use crate::error::EzError;
use rand_core::{OsRng, RngCore};
use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io;
use std::mem::{offset_of, size_of};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, IntoRawHandle};
use std::path::{Path, PathBuf};
use std::ptr;
use windows_sys::Win32::Foundation::{CloseHandle, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    GetSecurityInfo, SE_FILE_OBJECT, SetSecurityInfo,
};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorControl,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SE_DACL_PROTECTED,
    UNPROTECTED_DACL_SECURITY_INFORMATION,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, DELETE, FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_COMPRESSED,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_ENCRYPTED, FILE_ATTRIBUTE_HIDDEN,
    FILE_ATTRIBUTE_INTEGRITY_STREAM, FILE_ATTRIBUTE_NO_SCRUB_DATA, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, FILE_ATTRIBUTE_OFFLINE, FILE_ATTRIBUTE_READONLY,
    FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS, FILE_ATTRIBUTE_RECALL_ON_OPEN,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_SPARSE_FILE, FILE_ATTRIBUTE_SYSTEM,
    FILE_BASIC_INFO, FILE_DISPOSITION_FLAG_DELETE, FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE,
    FILE_DISPOSITION_FLAG_POSIX_SEMANTICS, FILE_DISPOSITION_INFO_EX, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_SEQUENTIAL_SCAN, FILE_FLAG_WRITE_THROUGH,
    FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES, FILE_RENAME_INFO, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FILE_STREAM_INFO, FILE_TRAVERSE, FILE_TYPE_DISK, FileBasicInfo,
    FileDispositionInfoEx, FileRenameInfo, FileStreamInfo, GetDriveTypeW,
    GetFileInformationByHandle, GetFileInformationByHandleEx, GetFileType,
    GetVolumeInformationByHandleW, GetVolumeNameForVolumeMountPointW, SYNCHRONIZE,
    SetFileInformationByHandle, SetFileTime, WRITE_DAC,
};

const ERROR_FILE_EXISTS: i32 = 80;
const ERROR_ALREADY_EXISTS: i32 = 183;
const ERROR_MORE_DATA: i32 = 234;
const DRIVE_FIXED: u32 = 3;
const TEMP_ATTEMPTS: usize = 64;
const UNSUPPORTED_STORAGE_ATTRIBUTES: u32 = FILE_ATTRIBUTE_ENCRYPTED
    | FILE_ATTRIBUTE_COMPRESSED
    | FILE_ATTRIBUTE_SPARSE_FILE
    | FILE_ATTRIBUTE_INTEGRITY_STREAM
    | FILE_ATTRIBUTE_NO_SCRUB_DATA
    | FILE_ATTRIBUTE_OFFLINE
    | FILE_ATTRIBUTE_RECALL_ON_OPEN
    | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS;

pub(crate) struct SourceFile {
    pub(crate) file: File,
    pub(crate) info: BY_HANDLE_FILE_INFORMATION,
}

pub(crate) struct ParentDirectory {
    // Every component from the volume root through the immediate parent is held
    // without FILE_SHARE_DELETE. This prevents an intermediate directory from
    // being swapped after validation while later lexical paths are opened.
    _handles: Vec<File>,
}

pub(crate) struct PendingOutput {
    file: Option<File>,
    path: PathBuf,
    published: bool,
    delete_pending: bool,
}

pub(crate) struct CommittedOutput {
    // Keeping this exclusive, no-sharing handle alive is the transaction's final
    // race barrier: nobody can remove or replace the published output before the
    // original source has been deleted.
    _file: File,
}

#[derive(Debug)]
pub(crate) enum SourceDeleteError {
    Retained(io::Error),
    RemovalUnconfirmed(io::Error),
}

impl SourceFile {
    pub(crate) fn open(path: &Path) -> Result<Self, EzError> {
        require_local_fixed_drive(path)?;
        let file = OpenOptions::new()
            .read(true)
            .access_mode(FILE_GENERIC_READ | DELETE)
            .share_mode(0)
            .custom_flags(
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_WRITE_THROUGH,
            )
            .open(path)
            .map_err(|source| EzError::io("open input exclusively", path, source))?;

        if file_type(&file) != FILE_TYPE_DISK {
            return Err(EzError::InputNotRegular(path.to_path_buf()));
        }
        let info = file_information(&file)
            .map_err(|source| EzError::io("inspect input handle", path, source))?;
        if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(EzError::ReparsePoint(path.to_path_buf()));
        }
        if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
            return Err(EzError::InputNotRegular(path.to_path_buf()));
        }
        let unsupported_attributes = info.dwFileAttributes & UNSUPPORTED_STORAGE_ATTRIBUTES;
        if unsupported_attributes != 0 {
            return Err(EzError::UnsupportedAttributes {
                path: path.to_path_buf(),
                attributes: unsupported_attributes,
            });
        }
        if info.nNumberOfLinks != 1 {
            return Err(EzError::MultipleHardLinks {
                path: path.to_path_buf(),
                links: info.nNumberOfLinks,
            });
        }
        if has_alternate_streams(&file)
            .map_err(|source| EzError::io("inspect alternate data streams on", path, source))?
        {
            return Err(EzError::AlternateDataStream(path.to_path_buf()));
        }
        require_supported_filesystem(&file, path)?;
        Ok(Self { file, info })
    }

    pub(crate) fn len(&self) -> u64 {
        (u64::from(self.info.nFileSizeHigh) << 32) | u64::from(self.info.nFileSizeLow)
    }

    pub(crate) fn verify_unchanged(&self, path: &Path) -> Result<(), EzError> {
        let current = file_information(&self.file)
            .map_err(|source| EzError::io("re-inspect input handle", path, source))?;
        let unchanged = current.dwVolumeSerialNumber == self.info.dwVolumeSerialNumber
            && current.nFileIndexHigh == self.info.nFileIndexHigh
            && current.nFileIndexLow == self.info.nFileIndexLow
            && current.nNumberOfLinks == 1
            && current.dwFileAttributes == self.info.dwFileAttributes
            && current.nFileSizeHigh == self.info.nFileSizeHigh
            && current.nFileSizeLow == self.info.nFileSizeLow
            && current.ftLastWriteTime.dwHighDateTime == self.info.ftLastWriteTime.dwHighDateTime
            && current.ftLastWriteTime.dwLowDateTime == self.info.ftLastWriteTime.dwLowDateTime;
        if unchanged {
            Ok(())
        } else {
            Err(EzError::InputChanged(path.to_path_buf()))
        }
    }

    pub(crate) fn delete(self) -> Result<(), SourceDeleteError> {
        let current = file_information(&self.file).map_err(SourceDeleteError::Retained)?;
        if current.dwVolumeSerialNumber != self.info.dwVolumeSerialNumber
            || current.nFileIndexHigh != self.info.nFileIndexHigh
            || current.nFileIndexLow != self.info.nFileIndexLow
            || current.nNumberOfLinks != 1
            || current.dwFileAttributes != self.info.dwFileAttributes
            || current.nFileSizeHigh != self.info.nFileSizeHigh
            || current.nFileSizeLow != self.info.nFileSizeLow
            || current.ftLastWriteTime.dwHighDateTime != self.info.ftLastWriteTime.dwHighDateTime
            || current.ftLastWriteTime.dwLowDateTime != self.info.ftLastWriteTime.dwLowDateTime
        {
            return Err(SourceDeleteError::Retained(io::Error::other(
                "source identity, metadata, or hard-link count changed before deletion",
            )));
        }
        mark_delete(&self.file).map_err(SourceDeleteError::Retained)?;
        // POSIX delete-pending blocks both new hard links and new alternate streams.
        // Its own pending name is excluded from nNumberOfLinks until disposition is
        // cleared, so zero is the expected count for a single-link source.
        let final_validation = (|| -> io::Result<()> {
            let final_info = file_information(&self.file)?;
            if final_info.dwVolumeSerialNumber != self.info.dwVolumeSerialNumber
                || final_info.nFileIndexHigh != self.info.nFileIndexHigh
                || final_info.nFileIndexLow != self.info.nFileIndexLow
                || final_info.nNumberOfLinks != 0
                || final_info.dwFileAttributes != self.info.dwFileAttributes
                || final_info.nFileSizeHigh != self.info.nFileSizeHigh
                || final_info.nFileSizeLow != self.info.nFileSizeLow
                || final_info.ftLastWriteTime.dwHighDateTime
                    != self.info.ftLastWriteTime.dwHighDateTime
                || final_info.ftLastWriteTime.dwLowDateTime
                    != self.info.ftLastWriteTime.dwLowDateTime
            {
                return Err(io::Error::other(
                    "source identity, metadata, or hard-link count changed at the deletion boundary",
                ));
            }
            if has_alternate_streams(&self.file)? {
                return Err(io::Error::other(
                    "an alternate data stream appeared at the deletion boundary",
                ));
            }
            Ok(())
        })();
        if let Err(validation_error) = final_validation {
            return Err(cancel_source_delete(&self.file, validation_error));
        }
        let SourceFile { file, .. } = self;
        let raw = file.into_raw_handle();
        // SAFETY: ownership of exactly this live handle was transferred by
        // into_raw_handle. No File destructor will close it a second time.
        let close_ok = unsafe { CloseHandle(raw) };
        if close_ok == 0 {
            Err(SourceDeleteError::RemovalUnconfirmed(
                io::Error::last_os_error(),
            ))
        } else {
            Ok(())
        }
    }
}

fn require_local_fixed_drive(path: &Path) -> Result<(), EzError> {
    use std::path::{Component, Prefix};

    let drive = match path.components().next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => letter,
            _ => return Err(EzError::UnsupportedDrive(path.to_path_buf())),
        },
        _ => return Err(EzError::UnsupportedDrive(path.to_path_buf())),
    };
    let root = [u16::from(drive), b':' as u16, b'\\' as u16, 0];
    // SAFETY: `root` is a valid NUL-terminated drive-root string.
    let kind = unsafe { GetDriveTypeW(root.as_ptr()) };
    if kind != DRIVE_FIXED {
        return Err(EzError::UnsupportedDrive(path.to_path_buf()));
    }
    let mut volume_name = [0u16; 64];
    // A real fixed volume root resolves to a stable volume GUID. SUBST-style DOS
    // aliases do not, so rejecting failures closes a retargetable namespace gap.
    let volume_ok = unsafe {
        GetVolumeNameForVolumeMountPointW(
            root.as_ptr(),
            volume_name.as_mut_ptr(),
            volume_name.len() as u32,
        )
    };
    if volume_ok == 0 {
        Err(EzError::UnsupportedDrive(path.to_path_buf()))
    } else {
        Ok(())
    }
}

impl ParentDirectory {
    pub(crate) fn open(path: &Path) -> Result<Self, EzError> {
        require_local_fixed_drive(path)?;
        let ancestors: Vec<&Path> = path.ancestors().collect();
        let mut handles = Vec::with_capacity(ancestors.len());
        for component_path in ancestors.into_iter().rev() {
            if component_path.as_os_str().is_empty() {
                continue;
            }
            let file = OpenOptions::new()
                .read(true)
                .access_mode(FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
                .open(component_path)
                .map_err(|source| {
                    EzError::io(
                        "open containing directory component",
                        component_path,
                        source,
                    )
                })?;
            let info = file_information(&file).map_err(|source| {
                EzError::io(
                    "inspect containing directory component",
                    component_path,
                    source,
                )
            })?;
            if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(EzError::ReparsePoint(component_path.to_path_buf()));
            }
            if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
                return Err(EzError::InvalidPath("containing path is not a directory"));
            }
            handles.push(file);
        }
        if handles.is_empty() {
            return Err(EzError::InvalidPath(
                "input has no openable parent directory",
            ));
        }
        Ok(Self { _handles: handles })
    }
}

impl PendingOutput {
    pub(crate) fn create(parent: &Path) -> Result<Self, EzError> {
        for _ in 0..TEMP_ATTEMPTS {
            let mut random = [0u8; 16];
            OsRng
                .try_fill_bytes(&mut random)
                .map_err(|_| EzError::Randomness)?;
            let name = format!(".ezcrypt-{}.tmp", hex(&random));
            let path = parent.join(name);
            let result = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE | WRITE_DAC)
                .share_mode(0)
                .custom_flags(
                    FILE_FLAG_OPEN_REPARSE_POINT
                        | FILE_FLAG_SEQUENTIAL_SCAN
                        | FILE_FLAG_WRITE_THROUGH
                        | FILE_ATTRIBUTE_HIDDEN,
                )
                .open(&path);
            match result {
                Ok(file) => {
                    // Make the temporary file delete-on-close before any transformed
                    // bytes are written. A crash or process kill then cannot strand
                    // plaintext. Publication briefly clears this state before rename.
                    if let Err(source) = mark_delete(&file) {
                        drop(file);
                        return Err(EzError::io(
                            "arm delete-on-close for temporary output",
                            &path,
                            source,
                        ));
                    }
                    let info = file_information(&file)
                        .map_err(|source| EzError::io("inspect temporary output", &path, source))?;
                    let unsupported_attributes =
                        info.dwFileAttributes & UNSUPPORTED_STORAGE_ATTRIBUTES;
                    if unsupported_attributes != 0 {
                        return Err(EzError::UnsupportedAttributes {
                            path,
                            attributes: unsupported_attributes,
                        });
                    }
                    if info.nNumberOfLinks != 0
                        || has_alternate_streams(&file).map_err(|source| {
                            EzError::io("inspect temporary output streams", &path, source)
                        })?
                    {
                        return Err(EzError::io(
                            "secure newly-created temporary output",
                            &path,
                            io::Error::other(
                                "temporary output acquired an unexpected link or stream",
                            ),
                        ));
                    }
                    return Ok(Self {
                        file: Some(file),
                        path,
                        published: false,
                        delete_pending: true,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(source) => {
                    return Err(EzError::io("create temporary output in", parent, source));
                }
            }
        }
        Err(EzError::io(
            "create collision-free temporary output in",
            parent,
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "too many temporary-name collisions",
            ),
        ))
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn file_mut(&mut self) -> &mut File {
        self.file.as_mut().expect("pending output owns a file")
    }

    pub(crate) fn sync(&self) -> Result<(), EzError> {
        self.file
            .as_ref()
            .expect("pending output owns a file")
            .sync_all()
            .map_err(|source| EzError::io("flush temporary output", &self.path, source))
    }

    pub(crate) fn apply_source_metadata(
        &self,
        source: &BY_HANDLE_FILE_INFORMATION,
    ) -> Result<(), EzError> {
        let file = self.file.as_ref().expect("pending output owns a file");
        let handle = file.as_raw_handle();
        // SAFETY: handle is a live file handle and all FILETIME pointers remain valid
        // for the duration of this synchronous call.
        let time_ok = unsafe {
            SetFileTime(
                handle,
                &source.ftCreationTime,
                &source.ftLastAccessTime,
                &source.ftLastWriteTime,
            )
        };
        if time_ok == 0 {
            return Err(EzError::io(
                "copy timestamps to",
                &self.path,
                io::Error::last_os_error(),
            ));
        }

        let preserved = source.dwFileAttributes
            & (FILE_ATTRIBUTE_READONLY
                | FILE_ATTRIBUTE_HIDDEN
                | FILE_ATTRIBUTE_SYSTEM
                | FILE_ATTRIBUTE_ARCHIVE
                | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED);
        let basic = FILE_BASIC_INFO {
            CreationTime: 0,
            LastAccessTime: 0,
            LastWriteTime: 0,
            ChangeTime: 0,
            FileAttributes: if preserved == 0 {
                FILE_ATTRIBUTE_NORMAL
            } else {
                preserved
            },
        };
        // SAFETY: `basic` has the exact ABI required by FileBasicInfo, and `handle`
        // remains owned by this object for the whole call.
        let attr_ok = unsafe {
            SetFileInformationByHandle(
                handle,
                FileBasicInfo,
                ptr::from_ref(&basic).cast(),
                size_of::<FILE_BASIC_INFO>() as u32,
            )
        };
        if attr_ok == 0 {
            return Err(EzError::io(
                "copy attributes to",
                &self.path,
                io::Error::last_os_error(),
            ));
        }
        Ok(())
    }

    pub(crate) fn apply_source_security(&self, source: &File) -> Result<(), EzError> {
        let destination = self.file.as_ref().expect("pending output owns a file");
        copy_dacl(source, destination)
            .map_err(|error| EzError::io("copy access controls to", &self.path, error))
    }

    pub(crate) fn publish(
        mut self,
        destination: &Path,
        _parent: &ParentDirectory,
    ) -> Result<CommittedOutput, EzError> {
        let file = self.file.as_ref().expect("pending output owns a file");
        clear_delete(file).map_err(|source| {
            EzError::io(
                "prepare temporary output for atomic publication",
                &self.path,
                source,
            )
        })?;
        self.delete_pending = false;
        let publish_info = file_information(file).map_err(|source| {
            EzError::io(
                "re-inspect temporary output before publication",
                &self.path,
                source,
            )
        })?;
        let unsupported_attributes = publish_info.dwFileAttributes & UNSUPPORTED_STORAGE_ATTRIBUTES;
        if publish_info.nNumberOfLinks != 1
            || unsupported_attributes != 0
            || has_alternate_streams(file).map_err(|source| {
                EzError::io("re-inspect temporary output streams", &self.path, source)
            })?
        {
            return Err(EzError::io(
                "validate temporary output before publication",
                &self.path,
                io::Error::other(
                    "temporary output acquired an unexpected link, stream, or storage attribute",
                ),
            ));
        }
        match rename_by_handle(file, destination) {
            Ok(()) => {
                self.published = true;
                self.path = destination.to_path_buf();
            }
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(ERROR_FILE_EXISTS | ERROR_ALREADY_EXISTS)
                ) =>
            {
                return Err(EzError::DestinationExists(destination.to_path_buf()));
            }
            Err(source) => {
                return Err(EzError::io(
                    "atomically publish output as",
                    destination,
                    source,
                ));
            }
        }
        file.sync_all()
            .map_err(|source| EzError::PublishedButSourceRetained {
                output: destination.to_path_buf(),
                source,
            })?;
        let file = self.file.take().expect("published output owns a file");
        Ok(CommittedOutput { _file: file })
    }
}

impl Drop for PendingOutput {
    fn drop(&mut self) {
        if self.published {
            return;
        }
        if let Some(file) = self.file.take() {
            if !self.delete_pending {
                let _ = mark_delete(&file);
            }
            drop(file);
        }
    }
}

fn absolute_rename_path(destination: &Path) -> io::Result<Vec<u16>> {
    use std::path::{Component, Prefix};

    let verbatim = match destination.components().next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(_) => false,
            Prefix::VerbatimDisk(_) => true,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "destination is not an absolute local drive path",
                ));
            }
        },
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "destination is not an absolute local drive path",
            ));
        }
    };

    let path: Vec<u16> = destination.as_os_str().encode_wide().collect();
    if verbatim {
        return Ok(path);
    }

    let mut extended = Vec::with_capacity(path.len() + 4);
    extended.extend([b'\\' as u16, b'\\' as u16, b'?' as u16, b'\\' as u16]);
    extended.extend(path.into_iter().map(|unit| {
        if unit == b'/' as u16 {
            b'\\' as u16
        } else {
            unit
        }
    }));
    Ok(extended)
}

fn rename_by_handle(file: &File, destination: &Path) -> io::Result<()> {
    let wide = absolute_rename_path(destination)?;
    if wide.is_empty() || wide.len() > (u32::MAX as usize) / 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "destination name is invalid",
        ));
    }
    // Match Rust std's Windows adapter exactly: bytes through the flexible FileName
    // field, the complete name, and one zero UTF-16 terminator. FileNameLength below
    // deliberately excludes that terminator.
    let buffer_len = offset_of!(FILE_RENAME_INFO, FileName)
        .checked_add(wide.len() * size_of::<u16>())
        .and_then(|value| value.checked_add(size_of::<u16>()))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "name is too long"))?;
    let words = buffer_len.div_ceil(size_of::<usize>());
    let mut storage = vec![0usize; words];
    let info = storage.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    // SAFETY: `storage` is pointer-aligned, large enough for FILE_RENAME_INFO plus
    // the complete UTF-16 name, and remains alive until the synchronous call returns.
    unsafe {
        (*info).Anonymous.ReplaceIfExists = false;
        // SetFileInformationByHandle returns ERROR_INVALID_PARAMETER for a nonnull
        // RootDirectory on supported Windows 11 builds, despite FILE_RENAME_INFO
        // exposing the field. Use an extended-length absolute path instead. The
        // retained ParentDirectory handles still pin every ancestor against swaps.
        (*info).RootDirectory = ptr::null_mut();
        (*info).FileNameLength = (wide.len() * size_of::<u16>()) as u32;
        let name_ptr = info
            .cast::<u8>()
            .add(offset_of!(FILE_RENAME_INFO, FileName));
        ptr::copy_nonoverlapping(wide.as_ptr(), name_ptr.cast::<u16>(), wide.len());
        let result = SetFileInformationByHandle(
            file.as_raw_handle(),
            FileRenameInfo,
            info.cast(),
            buffer_len as u32,
        );
        if result == 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn mark_delete(file: &File) -> io::Result<()> {
    let disposition = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_FLAG_DELETE
            | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS
            | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE,
    };
    // SAFETY: `disposition` has the exact ABI for FileDispositionInfoEx and the
    // handle was opened with DELETE access.
    let result = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileDispositionInfoEx,
            ptr::from_ref(&disposition).cast(),
            size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
        )
    };
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn clear_delete(file: &File) -> io::Result<()> {
    let disposition = FILE_DISPOSITION_INFO_EX { Flags: 0 };
    // SAFETY: zero flags cancel the matching extended disposition on this handle; the
    // handle was opened with DELETE access.
    let result = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileDispositionInfoEx,
            ptr::from_ref(&disposition).cast(),
            size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
        )
    };
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn cancel_source_delete(file: &File, cause: io::Error) -> SourceDeleteError {
    match clear_delete(file) {
        Ok(()) => SourceDeleteError::Retained(cause),
        Err(clear_error) => SourceDeleteError::RemovalUnconfirmed(io::Error::other(format!(
            "{cause}; additionally could not cancel pending source deletion: {clear_error}"
        ))),
    }
}

fn file_information(file: &File) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `info` is a valid writable output and the handle remains live.
    let result = unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) };
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(info)
    }
}

fn file_type(file: &File) -> u32 {
    // SAFETY: querying the type of a live owned handle has no additional preconditions.
    unsafe { GetFileType(file.as_raw_handle()) }
}

fn copy_dacl(source: &File, destination: &File) -> io::Result<()> {
    let mut dacl: *mut ACL = ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: unwanted optional outputs are null and Windows initializes the DACL
    // and allocated descriptor pointers on success.
    let get_error = unsafe {
        GetSecurityInfo(
            source.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if get_error != 0 {
        return Err(io::Error::from_raw_os_error(get_error as i32));
    }
    let descriptor_guard = LocalDescriptor(descriptor);
    let mut control = 0u16;
    let mut revision = 0u32;
    // SAFETY: the descriptor was returned by GetSecurityInfo and both outputs live
    // through this synchronous query.
    let control_ok =
        unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) };
    if control_ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let protection = if control & SE_DACL_PROTECTED != 0 {
        PROTECTED_DACL_SECURITY_INFORMATION
    } else {
        UNPROTECTED_DACL_SECURITY_INFORMATION
    };
    // SAFETY: the destination was opened with WRITE_DAC. A null DACL is valid;
    // otherwise descriptor_guard keeps the allocation containing it alive.
    let set_error = unsafe {
        SetSecurityInfo(
            destination.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | protection,
            ptr::null_mut(),
            ptr::null_mut(),
            dacl,
            ptr::null_mut(),
        )
    };
    drop(descriptor_guard);
    if set_error == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(set_error as i32))
    }
}

struct LocalDescriptor(PSECURITY_DESCRIPTOR);

impl Drop for LocalDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: GetSecurityInfo allocated this descriptor with LocalAlloc and
            // this guard owns exactly one matching release.
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

fn has_alternate_streams(file: &File) -> io::Result<bool> {
    const BUFFER_BYTES: usize = 64 * 1024;
    let words = BUFFER_BYTES.div_ceil(size_of::<usize>());
    let mut storage = vec![0usize; words];
    // SAFETY: storage is aligned and writable for BUFFER_BYTES, and the handle is live.
    let result = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileStreamInfo,
            storage.as_mut_ptr().cast(),
            BUFFER_BYTES as u32,
        )
    };
    if result == 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_MORE_DATA) {
            return Ok(true);
        }
        return Err(error);
    }
    let info = storage.as_ptr().cast::<FILE_STREAM_INFO>();
    // SAFETY: a successful FileStreamInfo call initialized the first entry in the
    // aligned buffer. We bounds-check the variable-length UTF-16 name before use.
    unsafe {
        if (*info).NextEntryOffset != 0 {
            return Ok(true);
        }
        let name_bytes = (*info).StreamNameLength as usize;
        if !name_bytes.is_multiple_of(2)
            || offset_of!(FILE_STREAM_INFO, StreamName) + name_bytes > BUFFER_BYTES
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid stream metadata returned by Windows",
            ));
        }
        let name = std::slice::from_raw_parts(
            info.cast::<u8>()
                .add(offset_of!(FILE_STREAM_INFO, StreamName))
                .cast::<u16>(),
            name_bytes / 2,
        );
        Ok(!wide_eq_ignore_ascii_case(name, OsStr::new("::$DATA")))
    }
}

fn require_supported_filesystem(file: &File, path: &Path) -> Result<(), EzError> {
    let mut fs_name = [0u16; 32];
    // SAFETY: optional output pointers are null; fs_name is a correctly-sized writable
    // UTF-16 buffer, and the source file handle remains live.
    let result = unsafe {
        GetVolumeInformationByHandleW(
            file.as_raw_handle(),
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            fs_name.as_mut_ptr(),
            fs_name.len() as u32,
        )
    };
    if result == 0 {
        return Err(EzError::io(
            "identify input filesystem for",
            path,
            io::Error::last_os_error(),
        ));
    }
    let end = fs_name
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(fs_name.len());
    let name = String::from_utf16_lossy(&fs_name[..end]);
    if name.eq_ignore_ascii_case("NTFS") {
        Ok(())
    } else {
        Err(EzError::UnsupportedFileSystem {
            path: path.to_path_buf(),
            name,
        })
    }
}

fn wide_eq_ignore_ascii_case(wide: &[u16], expected: &OsStr) -> bool {
    let other: Vec<u16> = expected.encode_wide().collect();
    wide.len() == other.len()
        && wide.iter().zip(other).all(|(left, right)| {
            let left = if (b'A' as u16..=b'Z' as u16).contains(left) {
                *left + u16::from(b'a' - b'A')
            } else {
                *left
            };
            let right = if (b'A' as u16..=b'Z' as u16).contains(&right) {
                right + u16::from(b'a' - b'A')
            } else {
                right
            };
            left == right
        })
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}
