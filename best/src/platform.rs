//! Small platform boundary: regular-file reads and private file creation.
use std::{
    fs::{File, OpenOptions},
    io,
    path::Path,
};

pub(crate) fn open_input(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        };
        options
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .share_mode(FILE_SHARE_READ);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "input must be a regular file",
        ));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "reparse-point inputs are not supported",
            ));
        }
    }
    Ok(file)
}

#[cfg(unix)]
pub(crate) fn create_private(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(windows)]
pub(crate) fn create_private(path: &Path) -> io::Result<File> {
    use std::{
        os::windows::{ffi::OsStrExt, io::FromRawHandle},
        ptr,
    };
    use windows_sys::Win32::{
        Foundation::{GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE, LocalFree},
        Security::{
            Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW,
            SECURITY_ATTRIBUTES,
        },
        Storage::FileSystem::{
            CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_SHARE_READ,
        },
    };
    let wide_path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    if wide_path[..wide_path.len() - 1].contains(&0) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "NUL in path"));
    }
    // Protected DACL: only the object owner and SYSTEM. No inherited group access.
    // The descriptor is supplied at creation, before even an empty file is visible.
    let sddl: Vec<u16> = "D:P(A;;FA;;;SY)(A;;FA;;;OW)"
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut descriptor = ptr::null_mut();
    // SAFETY: both strings are NUL-terminated, the output pointer is valid, and the
    // descriptor is released with LocalFree after CreateFileW has copied it.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut descriptor,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    // SAFETY: all pointers refer to live, correctly initialized values. CREATE_NEW
    // cannot follow or overwrite an existing path. The returned handle is owned.
    let handle = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            &attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        )
    };
    let error = io::Error::last_os_error();
    // SAFETY: this allocation came from the conversion API and is freed exactly once.
    unsafe {
        LocalFree(descriptor);
    }
    if handle == INVALID_HANDLE_VALUE {
        Err(error)
    } else {
        // SAFETY: CreateFileW returned a valid, unique owned file handle.
        Ok(unsafe { File::from_raw_handle(handle) })
    }
}

#[cfg(not(any(unix, windows)))]
compile_error!("best requires Unix or Windows private-file semantics");
