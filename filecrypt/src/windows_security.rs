//! Windows DACL construction and validation for key and staging files.

#![allow(unsafe_code)]

use std::ffi::c_void;
use std::fs::File;
use std::io;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::ptr::{self, null, null_mut};
use std::slice;

use windows_sys::Win32::Foundation::{ERROR_SUCCESS, INVALID_HANDLE_VALUE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    GetSecurityInfo, SE_FILE_OBJECT, SetSecurityInfo,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_REVISION, ACL_SIZE_INFORMATION, AclSizeInformation,
    AddAccessAllowedAceEx, CONTAINER_INHERIT_ACE, CopySid, DACL_SECURITY_INFORMATION, GetAce,
    GetAclInformation, GetLengthSid, GetSecurityDescriptorControl, GetTokenInformation,
    InitializeAcl, InitializeSecurityDescriptor, IsValidAcl, IsValidSid, OBJECT_INHERIT_ACE,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_DEFAULTED,
    SE_DACL_PRESENT, SE_DACL_PROTECTED, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR,
    SetSecurityDescriptorControl, SetSecurityDescriptorDacl, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, FILE_ALL_ACCESS, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    READ_CONTROL, ReOpenFile, WRITE_DAC,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const ACL_REVISION_BYTE: u8 = 2;
const ERROR_INSUFFICIENT_BUFFER_I32: i32 = 122;
const SECURITY_DESCRIPTOR_REVISION: u32 = 1;
const SID_OFFSET_IN_ALLOWED_ACE: usize = size_of::<ACCESS_ALLOWED_ACE>() - size_of::<u32>();

/// Atomically create a directory with one protected, inheritable full-control
/// ACE for the current process user.
pub(crate) fn create_protected_directory(path: &Path) -> io::Result<()> {
    let sid = current_process_user_sid()?;
    let mut dacl = DaclBuffer::for_user(&sid, OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)?;
    let mut descriptor = SECURITY_DESCRIPTOR::default();

    // SAFETY: `descriptor` is suitably aligned, writable storage for an
    // absolute security descriptor and remains alive through directory
    // creation.
    if unsafe {
        InitializeSecurityDescriptor(
            (&raw mut descriptor).cast::<c_void>(),
            SECURITY_DESCRIPTOR_REVISION,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `descriptor` was initialized above, and `dacl` owns a valid ACL
    // for the duration of this call and the subsequent synchronous create.
    if unsafe {
        SetSecurityDescriptorDacl(
            (&raw mut descriptor).cast::<c_void>(),
            1,
            dacl.as_mut_ptr(),
            0,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // Prevent the containing directory's inheritable entries from being
    // merged into the explicit owner-only DACL during object creation.
    // SAFETY: `descriptor` is the initialized descriptor above.
    if unsafe {
        SetSecurityDescriptorControl(
            (&raw mut descriptor).cast::<c_void>(),
            SE_DACL_PROTECTED,
            SE_DACL_PROTECTED,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }

    let wide_path = wide_path(path)?;
    let attributes_len = u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "the Windows security attributes type is too large",
        )
    })?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: attributes_len,
        lpSecurityDescriptor: (&raw mut descriptor).cast::<c_void>(),
        bInheritHandle: 0,
    };

    // SAFETY: `wide_path` is NUL-terminated. `attributes`, `descriptor`, and
    // the descriptor's DACL all remain alive through this synchronous call.
    if unsafe { CreateDirectoryW(wide_path.as_ptr(), &raw const attributes) } == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Replace an open file's DACL with one protected full-control ACE for the
/// current process user.
pub(crate) fn protect_file(file: &File) -> io::Result<()> {
    let sid = current_process_user_sid()?;
    let mut dacl = DaclBuffer::for_user(&sid, 0)?;
    let security_handle = reopen_for_dacl_write(file)?;

    // SAFETY: `security_handle` is a live file handle with `WRITE_DAC` access.
    // `dacl` owns a valid initialized ACL for the duration of this synchronous
    // call, and all optional SID/SACL pointers are null.
    let status = unsafe {
        SetSecurityInfo(
            security_handle.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            dacl.as_mut_ptr(),
            null(),
        )
    };
    win32_status(status)
}

/// Return whether an open file has exactly one explicit full-control ACE for
/// the current process user and a protected DACL.
pub(crate) fn has_protected_current_user_dacl(file: &File) -> io::Result<bool> {
    let sid = current_process_user_sid()?;
    let descriptor = FileSecurityDescriptor::read(file)?;
    descriptor.is_exact_private_dacl(&sid, 0)
}

struct OwnedSid {
    words: Vec<usize>,
    byte_len: usize,
}

impl OwnedSid {
    fn new_from(source: PSID) -> io::Result<Self> {
        // SAFETY: the caller obtains `source` from a successfully populated
        // `TOKEN_USER`, whose backing allocation remains alive for this call.
        if source.is_null() || unsafe { IsValidSid(source) } == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the process token contains an invalid user SID",
            ));
        }

        // SAFETY: `source` passed `IsValidSid` immediately above.
        let byte_len = usize::try_from(unsafe { GetLengthSid(source) })
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "the user SID is too large"))?;
        if byte_len == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the process token contains an empty user SID",
            ));
        }

        let word_count = words_for_bytes(byte_len)?;
        let mut words = vec![0_usize; word_count];
        let destination = words.as_mut_ptr().cast::<c_void>();
        let destination_len = u32::try_from(byte_len)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "the user SID is too large"))?;

        // SAFETY: `destination` addresses `word_count * size_of::<usize>()`
        // writable, suitably aligned bytes, which is at least `byte_len`.
        // `source` is a valid SID and remains alive during the copy.
        if unsafe { CopySid(destination_len, destination, source) } == 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(Self { words, byte_len })
    }

    fn as_psid(&self) -> PSID {
        self.words.as_ptr().cast_mut().cast::<c_void>()
    }

    fn as_bytes(&self) -> &[u8] {
        // SAFETY: `words` owns at least `byte_len` initialized bytes and cannot
        // move while this borrowed slice is alive.
        unsafe { slice::from_raw_parts(self.words.as_ptr().cast::<u8>(), self.byte_len) }
    }
}

fn current_process_user_sid() -> io::Result<OwnedSid> {
    let mut raw_token = null_mut();

    // SAFETY: `raw_token` is a valid out-pointer. `GetCurrentProcess` returns a
    // pseudo-handle that must not be closed; `OpenProcessToken` returns a new
    // owned handle on success.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut raw_token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a successful `OpenProcessToken` call returned a non-null owned
    // token handle, transferred here for automatic `CloseHandle` on drop.
    let token = unsafe { OwnedHandle::from_raw_handle(raw_token) };

    let mut required = 0_u32;
    // SAFETY: this is the documented sizing call: the information pointer is
    // null and its length is zero; `required` is a valid out-pointer.
    let sizing_result = unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            null_mut(),
            0,
            &raw mut required,
        )
    };
    if sizing_result != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the token sizing call unexpectedly succeeded",
        ));
    }
    let sizing_error = io::Error::last_os_error();
    if sizing_error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER_I32) {
        return Err(sizing_error);
    }

    let required_usize = usize::try_from(required).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "the token user data is too large",
        )
    })?;
    if required_usize < size_of::<TOKEN_USER>() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the token user data is too short",
        ));
    }
    let mut storage = vec![0_usize; words_for_bytes(required_usize)?];
    let mut returned = 0_u32;

    // SAFETY: `storage` is suitably aligned for `TOKEN_USER` and has at least
    // `required` writable bytes. The token handle and both out-pointers are
    // valid for the duration of the call.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            storage.as_mut_ptr().cast::<c_void>(),
            required,
            &raw mut returned,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if returned
        < u32::try_from(size_of::<TOKEN_USER>()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "the token user type is too large",
            )
        })?
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the returned token user data is too short",
        ));
    }

    // SAFETY: the successful call initialized a `TOKEN_USER` at the aligned
    // start of `storage`, and the length checks above cover the structure.
    let token_user = unsafe { ptr::read(storage.as_ptr().cast::<TOKEN_USER>()) };
    OwnedSid::new_from(token_user.User.Sid)
}

struct DaclBuffer {
    words: Vec<usize>,
}

impl DaclBuffer {
    fn for_user(sid: &OwnedSid, ace_flags: u32) -> io::Result<Self> {
        let ace_size = SID_OFFSET_IN_ALLOWED_ACE
            .checked_add(sid.byte_len)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "the ACL is too large"))?;
        let total_acl_size = size_of::<ACL>()
            .checked_add(ace_size)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "the ACL is too large"))?;
        let acl_size_u32 = u32::try_from(total_acl_size)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "the ACL is too large"))?;
        let mut words = vec![0_usize; words_for_bytes(total_acl_size)?];
        let acl = words.as_mut_ptr().cast::<ACL>();

        // SAFETY: `acl` points to `acl_size` writable, suitably aligned bytes.
        if unsafe { InitializeAcl(acl, acl_size_u32, ACL_REVISION) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `acl` was initialized successfully with enough room for one
        // access-allowed ACE containing `sid`; both allocations remain alive.
        if unsafe {
            AddAccessAllowedAceEx(acl, ACL_REVISION, ace_flags, FILE_ALL_ACCESS, sid.as_psid())
        } == 0
        {
            return Err(io::Error::last_os_error());
        }

        Ok(Self { words })
    }

    fn as_mut_ptr(&mut self) -> *mut ACL {
        self.words.as_mut_ptr().cast::<ACL>()
    }
}

struct FileSecurityDescriptor {
    allocation: PSECURITY_DESCRIPTOR,
    dacl: *mut ACL,
}

impl FileSecurityDescriptor {
    fn read(file: &File) -> io::Result<Self> {
        let mut dacl = null_mut();
        let mut allocation = null_mut();

        // SAFETY: the file handle is live and was opened for reading, which
        // includes `READ_CONTROL`. Optional owner/group/SACL outputs are null;
        // `dacl` and `allocation` are valid out-pointers.
        let status = unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                &raw mut dacl,
                null_mut(),
                &raw mut allocation,
            )
        };
        Self::from_security_info(status, dacl, allocation)
    }

    #[cfg(test)]
    fn read_path(path: &Path) -> io::Result<Self> {
        let wide_path = wide_path(path)?;
        let mut dacl = null_mut();
        let mut allocation = null_mut();

        // SAFETY: `wide_path` is NUL-terminated and both requested output
        // pointers are valid. Optional owner/group/SACL outputs are null.
        let status = unsafe {
            windows_sys::Win32::Security::Authorization::GetNamedSecurityInfoW(
                wide_path.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                &raw mut dacl,
                null_mut(),
                &raw mut allocation,
            )
        };
        Self::from_security_info(status, dacl, allocation)
    }

    fn from_security_info(
        status: u32,
        dacl: *mut ACL,
        allocation: PSECURITY_DESCRIPTOR,
    ) -> io::Result<Self> {
        if status != ERROR_SUCCESS {
            if !allocation.is_null() {
                // SAFETY: a non-null descriptor returned by `GetSecurityInfo`
                // is allocated with `LocalAlloc` and may be released here.
                unsafe {
                    LocalFree(allocation);
                }
            }
            return Err(error_from_win32(status));
        }
        if allocation.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Windows returned a null security descriptor",
            ));
        }

        Ok(Self { allocation, dacl })
    }

    fn is_exact_private_dacl(&self, sid: &OwnedSid, expected_ace_flags: u8) -> io::Result<bool> {
        let mut control = 0_u16;
        let mut revision = 0_u32;
        // SAFETY: `allocation` is a live security descriptor owned by `self`;
        // both scalar output pointers are valid.
        if unsafe {
            GetSecurityDescriptorControl(self.allocation, &raw mut control, &raw mut revision)
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let required_control = SE_DACL_PRESENT | SE_DACL_PROTECTED;
        if control & required_control != required_control
            || control & SE_DACL_DEFAULTED != 0
            || self.dacl.is_null()
        {
            return Ok(false);
        }

        // SAFETY: `dacl` points inside the live descriptor and is non-null.
        if unsafe { IsValidAcl(self.dacl) } == 0 {
            return Ok(false);
        }

        let mut information = ACL_SIZE_INFORMATION::default();
        let information_size = u32::try_from(size_of::<ACL_SIZE_INFORMATION>()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "the ACL information type is too large",
            )
        })?;
        // SAFETY: `dacl` is valid and `information` is a writable output buffer
        // of the exact size reported to Windows.
        if unsafe {
            GetAclInformation(
                self.dacl,
                (&raw mut information).cast::<c_void>(),
                information_size,
                AclSizeInformation,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if information.AceCount != 1 {
            return Ok(false);
        }

        // SAFETY: a valid ACL with `AceCount == 1` has an ACE at index zero;
        // `ace` is a valid out-pointer.
        let mut ace = null_mut();
        if unsafe { GetAce(self.dacl, 0, &raw mut ace) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if ace.is_null() {
            return Ok(false);
        }

        // SAFETY: `GetAce` returned a pointer to at least an `ACE_HEADER` in a
        // valid ACL. `read_unaligned` avoids imposing an extra Rust alignment
        // requirement on Windows-owned memory.
        let header = unsafe { ptr::read_unaligned(ace.cast::<ACE_HEADER>()) };
        let expected_ace_size = SID_OFFSET_IN_ALLOWED_ACE
            .checked_add(sid.byte_len)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "the ACE is too large"))?;
        if header.AceType != ACCESS_ALLOWED_ACE_TYPE
            || header.AceFlags != expected_ace_flags
            || usize::from(header.AceSize) != expected_ace_size
        {
            return Ok(false);
        }

        // SAFETY: the exact ACE-size check above guarantees that the complete
        // fixed `ACCESS_ALLOWED_ACE` prefix and expected SID bytes are present.
        let allowed = unsafe { ptr::read_unaligned(ace.cast::<ACCESS_ALLOWED_ACE>()) };
        if allowed.Mask != FILE_ALL_ACCESS {
            return Ok(false);
        }

        let expected_acl_bytes = size_of::<ACL>()
            .checked_add(expected_ace_size)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "the ACL is too large"))?;
        if usize::try_from(information.AclBytesInUse).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "the ACL byte count is too large",
            )
        })? != expected_acl_bytes
        {
            return Ok(false);
        }

        // SAFETY: the ACE-size check bounds this slice within the ACE returned
        // by Windows; the SID begins at `SID_OFFSET_IN_ALLOWED_ACE`.
        let ace_sid = unsafe {
            slice::from_raw_parts(
                ace.cast::<u8>().add(SID_OFFSET_IN_ALLOWED_ACE),
                sid.byte_len,
            )
        };
        // SAFETY: `dacl` is non-null and points to a valid ACL header.
        let acl_header = unsafe { ptr::read_unaligned(self.dacl) };
        Ok(acl_header.AclRevision == ACL_REVISION_BYTE && ace_sid == sid.as_bytes())
    }
}

impl Drop for FileSecurityDescriptor {
    fn drop(&mut self) {
        if !self.allocation.is_null() {
            // SAFETY: `allocation` is the unique descriptor allocation returned
            // by `GetSecurityInfo`; it is released exactly once here.
            unsafe {
                LocalFree(self.allocation);
            }
        }
    }
}

fn reopen_for_dacl_write(file: &File) -> io::Result<OwnedHandle> {
    // SAFETY: the source file handle is live. The requested access and sharing
    // masks are valid for `ReOpenFile`; a distinct owned handle is returned.
    let handle = unsafe {
        ReOpenFile(
            file.as_raw_handle(),
            READ_CONTROL | WRITE_DAC,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            0,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: `ReOpenFile` returned a valid distinct owned handle, transferred
    // to `OwnedHandle` for automatic `CloseHandle` on drop.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

fn wide_path(path: &Path) -> io::Result<Vec<u16>> {
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a Windows path cannot contain an embedded NUL",
        ));
    }
    wide.push(0);
    Ok(wide)
}

fn words_for_bytes(bytes: usize) -> io::Result<usize> {
    bytes
        .checked_add(size_of::<usize>() - 1)
        .map(|rounded| rounded / size_of::<usize>())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "buffer size overflow"))
}

fn win32_status(status: u32) -> io::Result<()> {
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(error_from_win32(status))
    }
}

fn error_from_win32(status: u32) -> io::Error {
    match i32::try_from(status) {
        Ok(code) => io::Error::from_raw_os_error(code),
        Err(_) => io::Error::other(format!(
            "Windows security operation failed with status {status}"
        )),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::fs::{self, OpenOptions};
    use std::os::windows::ffi::OsStringExt;
    use std::path::PathBuf;

    #[test]
    fn word_allocation_rounds_up_and_rejects_overflow() {
        let word = size_of::<usize>();
        assert_eq!(words_for_bytes(0).expect("zero bytes"), 0);
        assert_eq!(words_for_bytes(1).expect("one byte"), 1);
        assert_eq!(words_for_bytes(word).expect("one word"), 1);
        assert_eq!(words_for_bytes(word + 1).expect("partial second word"), 2);
        assert_eq!(
            words_for_bytes(usize::MAX)
                .expect_err("rounding must overflow")
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn wide_paths_are_terminated_and_reject_embedded_nuls() {
        let ordinary = Path::new(r"C:\directory\key.key");
        let wide = wide_path(ordinary).expect("encode ordinary path");
        assert_eq!(wide.last(), Some(&0));
        assert!(!wide[..wide.len() - 1].contains(&0));

        let embedded = PathBuf::from(OsString::from_wide(&[u16::from(b'a'), 0, u16::from(b'b')]));
        assert_eq!(
            wide_path(&embedded)
                .expect_err("embedded NUL must fail")
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn win32_status_conversion_preserves_success_and_error_codes() {
        assert!(win32_status(ERROR_SUCCESS).is_ok());
        assert_eq!(
            win32_status(5)
                .expect_err("access denied must be an error")
                .raw_os_error(),
            Some(5)
        );
        assert!(error_from_win32(u32::MAX).raw_os_error().is_none());
    }

    #[test]
    fn current_user_sid_and_acl_buffer_are_valid() {
        let sid = current_process_user_sid().expect("read current user SID");
        assert!(!sid.as_bytes().is_empty());
        let mut dacl = DaclBuffer::for_user(&sid, 0).expect("build current-user ACL");

        // SAFETY: `DaclBuffer::for_user` returned an initialized live ACL.
        assert_ne!(unsafe { IsValidAcl(dacl.as_mut_ptr()) }, 0);
        // SAFETY: the ACL pointer is aligned and contains its initialized
        // header for the lifetime of `dacl`.
        let header = unsafe { ptr::read(dacl.as_mut_ptr()) };
        assert_eq!(header.AclRevision, ACL_REVISION_BYTE);
        assert_eq!(header.AceCount, 1);
    }

    #[test]
    fn protected_file_round_trips_through_exact_dacl_validation() {
        let parent = tempfile::tempdir().expect("test parent");
        let path = parent.path().join("key.key");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .expect("create test file");

        protect_file(&file).expect("protect test file");

        assert!(has_protected_current_user_dacl(&file).expect("inspect protected file DACL"));
    }

    #[test]
    fn directory_is_created_with_protected_inheritable_user_only_dacl() {
        let parent = tempfile::tempdir().expect("test parent");
        let path = parent.path().join("private-directory");

        create_protected_directory(&path).expect("create protected directory");

        let sid = current_process_user_sid().expect("read current user SID");
        let descriptor =
            FileSecurityDescriptor::read_path(&path).expect("read protected directory DACL");
        let expected_flags = u8::try_from(OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)
            .expect("inheritance flags fit in ACE header");
        assert!(
            descriptor
                .is_exact_private_dacl(&sid, expected_flags)
                .expect("validate protected directory DACL")
        );

        let collision = create_protected_directory(&path)
            .expect_err("protected creation must not replace an existing directory");
        assert_eq!(collision.kind(), io::ErrorKind::AlreadyExists);
        assert!(fs::metadata(&path).expect("directory metadata").is_dir());
    }
}
