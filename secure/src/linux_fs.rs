use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io::{self, BufReader, BufWriter, Write},
    os::{
        fd::AsRawFd,
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Path, PathBuf},
};

use age::secrecy::SecretString;
use rustix::{
    fs::{self, AtFlags, Mode, OFlags, RenameFlags, ResolveFlags},
    io::Errno,
};

use crate::{
    Error,
    cancel::{CancelReader, Cancellation},
    crypto,
};

const BUFFER_SIZE: usize = 256 * 1024;
const TEMP_ATTEMPTS: usize = 128;
const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InputSnapshot {
    device: u64,
    inode: u64,
    length: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl InputSnapshot {
    fn capture(file: &File) -> io::Result<Self> {
        let metadata = file.metadata()?;
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            length: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        })
    }
}

#[cfg(test)]
pub(crate) fn encrypt_file(
    input_path: &Path,
    output_path: &Path,
    password: SecretString,
) -> Result<(), Error> {
    encrypt_file_cancellable(input_path, output_path, password, &Cancellation::never())
}

pub(crate) fn encrypt_file_cancellable(
    input_path: &Path,
    output_path: &Path,
    password: SecretString,
    cancellation: &Cancellation,
) -> Result<(), Error> {
    cancellation.check()?;
    let input = open_regular_input(input_path)?;
    let before = InputSnapshot::capture(&input).map_err(|source| Error::OpenInput {
        path: input_path.to_path_buf(),
        source,
    })?;
    let input = CancelReader::new(input, cancellation);
    let mut input = BufReader::with_capacity(BUFFER_SIZE, input);
    let mut output = AtomicOutput::new(output_path, TemporaryPolicy::AllowNamedFallback)?;

    let copied_result = {
        let mut buffered = BufWriter::with_capacity(BUFFER_SIZE, output.file_mut());
        crypto::encrypt_stream(&mut input, &mut buffered, password).and_then(|copied| {
            buffered
                .flush()
                .map_err(Error::EncryptionIo)
                .map(|()| copied)
        })
    };
    let copied = prefer_interruption(copied_result, cancellation)?;

    let after =
        InputSnapshot::capture(input.get_ref().get_ref()).map_err(|source| Error::OpenInput {
            path: input_path.to_path_buf(),
            source,
        })?;
    if before != after || copied != before.length {
        return Err(Error::InputChanged(input_path.to_path_buf()));
    }

    output.commit_cancellable(cancellation)
}

#[cfg(test)]
pub(crate) fn decrypt_file(
    input_path: &Path,
    output_path: &Path,
    password: SecretString,
) -> Result<(), Error> {
    decrypt_file_cancellable(input_path, output_path, password, &Cancellation::never())
}

pub(crate) fn decrypt_file_cancellable(
    input_path: &Path,
    output_path: &Path,
    password: SecretString,
    cancellation: &Cancellation,
) -> Result<(), Error> {
    cancellation.check()?;
    let input = open_regular_input(input_path)?;
    let input = CancelReader::new(input, cancellation);
    let input = BufReader::with_capacity(BUFFER_SIZE, input);
    let mut output = AtomicOutput::new(output_path, TemporaryPolicy::AnonymousOnly)?;

    let decrypt_result = {
        let mut buffered = BufWriter::with_capacity(BUFFER_SIZE, output.file_mut());
        crypto::decrypt_stream(input, &mut buffered, password)
            .and_then(|_| buffered.flush().map_err(|_| Error::DecryptionFailed))
    };
    prefer_interruption(decrypt_result, cancellation)?;

    output.commit_cancellable(cancellation)
}

fn prefer_interruption<T>(
    result: Result<T, Error>,
    cancellation: &Cancellation,
) -> Result<T, Error> {
    if cancellation.is_cancelled() {
        Err(Error::Interrupted)
    } else {
        result
    }
}

fn open_regular_input(path: &Path) -> Result<File, Error> {
    let fd = fs::openat2(
        fs::CWD,
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|error| Error::OpenInput {
        path: path.to_path_buf(),
        source: io::Error::from(error),
    })?;
    let file = File::from(fd);
    let metadata = file.metadata().map_err(|source| Error::OpenInput {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(Error::InputNotRegular(path.to_path_buf()));
    }
    Ok(file)
}

enum TemporaryBacking {
    Anonymous,
    Named(OsString),
}

#[derive(Clone, Copy)]
enum TemporaryPolicy {
    AnonymousOnly,
    AllowNamedFallback,
}

struct AtomicOutput {
    directory: File,
    target_name: OsString,
    target_path: PathBuf,
    backing: Option<TemporaryBacking>,
    file: Option<File>,
}

impl AtomicOutput {
    fn new(target_path: &Path, policy: TemporaryPolicy) -> Result<Self, Error> {
        validate_output_path_syntax(target_path)?;
        let target_name = target_path
            .file_name()
            .filter(|name| !name.is_empty())
            .ok_or_else(|| Error::InvalidOutputPath(target_path.to_path_buf()))?
            .to_os_string();
        if target_name == OsStr::new(".") || target_name == OsStr::new("..") {
            return Err(Error::InvalidOutputPath(target_path.to_path_buf()));
        }

        let parent = match target_path.parent() {
            Some(path) if !path.as_os_str().is_empty() => path,
            _ => Path::new("."),
        };
        let directory_fd = fs::openat2(
            fs::CWD,
            parent,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(|error| Error::OpenOutputDirectory {
            path: parent.to_path_buf(),
            source: io::Error::from(error),
        })?;
        let directory = File::from(directory_fd);

        match fs::statat(&directory, &target_name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => return Err(Error::OutputExists(target_path.to_path_buf())),
            Err(Errno::NOENT) => {}
            Err(error) => {
                return Err(Error::CreateTemporaryOutput {
                    path: target_path.to_path_buf(),
                    source: io::Error::from(error),
                });
            }
        }

        let (backing, file) = create_temporary(&directory, target_path, policy)?;
        Ok(Self {
            directory,
            target_name,
            target_path: target_path.to_path_buf(),
            backing: Some(backing),
            file: Some(file),
        })
    }

    fn file_mut(&mut self) -> &mut File {
        self.file
            .as_mut()
            .expect("temporary output file is present until commit")
    }

    #[cfg(test)]
    fn commit(self) -> Result<(), Error> {
        self.commit_inner(None)
    }

    fn commit_cancellable(self, cancellation: &Cancellation) -> Result<(), Error> {
        self.commit_inner(Some(cancellation))
    }

    fn commit_inner(mut self, cancellation: Option<&Cancellation>) -> Result<(), Error> {
        self.file_mut()
            .sync_all()
            .map_err(|source| Error::PublishOutput {
                path: self.target_path.clone(),
                source,
            })?;

        if let Some(cancellation) = cancellation {
            cancellation.check()?;
        }

        let publish_result = match self
            .backing
            .as_ref()
            .expect("temporary output backing is present until commit")
        {
            TemporaryBacking::Anonymous => self.publish_anonymous(),
            TemporaryBacking::Named(name) => fs::renameat_with(
                &self.directory,
                name,
                &self.directory,
                &self.target_name,
                RenameFlags::NOREPLACE,
            ),
        };
        match publish_result {
            Ok(()) => {}
            Err(Errno::EXIST) => return Err(Error::OutputExists(self.target_path.clone())),
            Err(error) => {
                return Err(Error::PublishOutput {
                    path: self.target_path.clone(),
                    source: io::Error::from(error),
                });
            }
        }

        self.backing = None;
        self.file = None;
        self.directory
            .sync_all()
            .map_err(|source| Error::DirectorySyncAfterPublish {
                path: self.target_path.clone(),
                source,
            })
    }

    fn publish_anonymous(&self) -> rustix::io::Result<()> {
        let file = self
            .file
            .as_ref()
            .expect("anonymous output file is present until commit");
        match fs::linkat(
            file,
            "",
            &self.directory,
            &self.target_name,
            AtFlags::EMPTY_PATH,
        ) {
            Ok(()) => Ok(()),
            Err(Errno::PERM | Errno::NOENT) => self.publish_anonymous_via_proc(),
            Err(error) => Err(error),
        }
    }

    fn publish_anonymous_via_proc(&self) -> rustix::io::Result<()> {
        let file = self
            .file
            .as_ref()
            .expect("anonymous output file is present until commit");
        let proc_path = format!("/proc/self/fd/{}", file.as_raw_fd());
        fs::linkat(
            fs::CWD,
            proc_path,
            &self.directory,
            &self.target_name,
            AtFlags::SYMLINK_FOLLOW,
        )
    }
}

fn validate_output_path_syntax(target_path: &Path) -> Result<(), Error> {
    let bytes = target_path.as_os_str().as_bytes();
    let final_component = bytes.rsplit(|byte| *byte == b'/').next().unwrap_or(bytes);
    if bytes.is_empty()
        || bytes.ends_with(b"/")
        || final_component == b"."
        || final_component == b".."
    {
        return Err(Error::InvalidOutputPath(target_path.to_path_buf()));
    }
    Ok(())
}

impl Drop for AtomicOutput {
    fn drop(&mut self) {
        if let Some(TemporaryBacking::Named(name)) = &self.backing {
            let _ = fs::unlinkat(&self.directory, name, AtFlags::empty());
        }
    }
}

fn create_temporary(
    directory: &File,
    target_path: &Path,
    policy: TemporaryPolicy,
) -> Result<(TemporaryBacking, File), Error> {
    match fs::openat(
        directory,
        ".",
        OFlags::WRONLY | OFlags::TMPFILE | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    ) {
        Ok(fd) => {
            let file = File::from(fd);
            set_private_mode(&file, target_path)?;
            return Ok((TemporaryBacking::Anonymous, file));
        }
        Err(error) if temporary_files_unsupported(error) => {}
        Err(error) => {
            return Err(Error::CreateTemporaryOutput {
                path: target_path.to_path_buf(),
                source: io::Error::from(error),
            });
        }
    }

    if matches!(policy, TemporaryPolicy::AnonymousOnly) {
        return Err(Error::CreateTemporaryOutput {
            path: target_path.to_path_buf(),
            source: io::Error::new(
                io::ErrorKind::Unsupported,
                "the output filesystem lacks O_TMPFILE; refusing to expose temporary plaintext",
            ),
        });
    }

    create_named_temporary(directory, target_path)
}

fn create_named_temporary(
    directory: &File,
    target_path: &Path,
) -> Result<(TemporaryBacking, File), Error> {
    require_safe_named_fallback(directory, target_path)?;
    for _ in 0..TEMP_ATTEMPTS {
        let name = random_temporary_name(target_path)?;
        match fs::openat(
            directory,
            &name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::RUSR | Mode::WUSR,
        ) {
            Ok(fd) => {
                let file = File::from(fd);
                if let Err(error) = set_private_mode(&file, target_path) {
                    let _ = fs::unlinkat(directory, &name, AtFlags::empty());
                    return Err(error);
                }
                return Ok((TemporaryBacking::Named(name), file));
            }
            Err(Errno::EXIST) => {}
            Err(error) => {
                return Err(Error::CreateTemporaryOutput {
                    path: target_path.to_path_buf(),
                    source: io::Error::from(error),
                });
            }
        }
    }

    Err(Error::CreateTemporaryOutput {
        path: target_path.to_path_buf(),
        source: io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique temporary filename",
        ),
    })
}

fn temporary_files_unsupported(error: Errno) -> bool {
    matches!(
        error,
        Errno::NOTSUP | Errno::ISDIR | Errno::INVAL | Errno::NOENT
    )
}

fn set_private_mode(file: &File, target_path: &Path) -> Result<(), Error> {
    fs::fchmod(file, Mode::RUSR | Mode::WUSR).map_err(|error| Error::CreateTemporaryOutput {
        path: target_path.to_path_buf(),
        source: io::Error::from(error),
    })
}

fn require_safe_named_fallback(directory: &File, target_path: &Path) -> Result<(), Error> {
    let metadata = directory
        .metadata()
        .map_err(|source| Error::CreateTemporaryOutput {
            path: target_path.to_path_buf(),
            source,
        })?;
    let effective_uid = rustix::process::geteuid().as_raw();
    if !named_fallback_permissions_are_safe(metadata.mode(), metadata.uid(), effective_uid) {
        return Err(Error::CreateTemporaryOutput {
            path: target_path.to_path_buf(),
            source: io::Error::new(
                io::ErrorKind::PermissionDenied,
                "filesystem lacks O_TMPFILE and the output directory is unsafe for a named temporary file",
            ),
        });
    }
    Ok(())
}

fn named_fallback_permissions_are_safe(mode: u32, owner: u32, effective_uid: u32) -> bool {
    let owner_is_trusted = owner == 0 || owner == effective_uid;
    let shared_writable = mode & 0o022 != 0;
    let sticky = mode & 0o1000 != 0;
    owner_is_trusted && (!shared_writable || sticky)
}

fn random_temporary_name(target_path: &Path) -> Result<OsString, Error> {
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(|error| Error::CreateTemporaryOutput {
        path: target_path.to_path_buf(),
        source: io::Error::other(error),
    })?;

    let mut name = String::with_capacity(13 + random.len() * 2);
    name.push_str(".secure-tmp-");
    for byte in random {
        name.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
        name.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
    }
    Ok(OsString::from(name))
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashSet,
        ffi::OsString,
        fs,
        io::{Cursor, Write},
        os::unix::{
            ffi::OsStringExt,
            fs::{PermissionsExt, symlink},
            net::UnixListener,
        },
        path::Path,
        sync::{Arc, Barrier},
        thread,
    };

    use age::secrecy::SecretString;
    use tempfile::TempDir;

    use super::*;

    const PASSWORD: &str = "correct horse battery staple";
    const TEST_WORK_FACTOR: u8 = 10;

    fn password() -> SecretString {
        SecretString::from(PASSWORD.to_owned())
    }

    fn cheap_ciphertext(plaintext: &[u8]) -> Vec<u8> {
        let passphrase = password();
        let mut recipient = age::scrypt::Recipient::new(passphrase);
        recipient.set_work_factor(TEST_WORK_FACTOR);
        let mut input = Cursor::new(plaintext);
        let mut encrypted = Vec::new();
        crypto::encrypt_stream_with_recipient(&mut input, &mut encrypted, &recipient).unwrap();
        encrypted
    }

    fn write_ciphertext(directory: &TempDir, plaintext: &[u8]) -> PathBuf {
        let path = directory.path().join("input.age");
        fs::write(&path, cheap_ciphertext(plaintext)).unwrap();
        path
    }

    fn temporary_artifacts(directory: &Path) -> Vec<OsString> {
        fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .filter(|name| name.to_string_lossy().starts_with(".secure-tmp-"))
            .collect()
    }

    fn named_atomic_output(target_path: &Path) -> AtomicOutput {
        validate_output_path_syntax(target_path).unwrap();
        let parent = target_path.parent().unwrap();
        let directory = File::open(parent).unwrap();
        let target_name = target_path.file_name().unwrap().to_os_string();
        let (backing, file) = create_named_temporary(&directory, target_path).unwrap();
        AtomicOutput {
            directory,
            target_name,
            target_path: target_path.to_path_buf(),
            backing: Some(backing),
            file: Some(file),
        }
    }

    #[test]
    fn atomic_output_is_invisible_until_commit() {
        let directory = TempDir::new().unwrap();
        let target = directory.path().join("result");
        let mut output = AtomicOutput::new(&target, TemporaryPolicy::AnonymousOnly).unwrap();
        output.file_mut().write_all(b"complete bytes").unwrap();

        assert!(!target.exists());
        output.commit().unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"complete bytes");
    }

    #[test]
    fn dropping_atomic_output_removes_all_temporary_state() {
        let directory = TempDir::new().unwrap();
        let target = directory.path().join("result");
        {
            let mut output = AtomicOutput::new(&target, TemporaryPolicy::AnonymousOnly).unwrap();
            output.file_mut().write_all(b"partial secret").unwrap();
        }

        assert!(!target.exists());
        assert!(temporary_artifacts(directory.path()).is_empty());
    }

    #[test]
    fn named_fallback_commits_privately_and_removes_its_temporary_name() {
        let directory = TempDir::new().unwrap();
        let target = directory.path().join("result");
        let mut output = named_atomic_output(&target);
        assert_eq!(temporary_artifacts(directory.path()).len(), 1);
        assert_eq!(output.file_mut().metadata().unwrap().mode() & 0o777, 0o600);
        output.file_mut().write_all(b"ciphertext only").unwrap();

        output.commit().unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"ciphertext only");
        assert_eq!(fs::metadata(&target).unwrap().mode() & 0o777, 0o600);
        assert!(temporary_artifacts(directory.path()).is_empty());
    }

    #[test]
    fn dropping_named_fallback_unlinks_partial_ciphertext() {
        let directory = TempDir::new().unwrap();
        let target = directory.path().join("result");
        {
            let mut output = named_atomic_output(&target);
            output.file_mut().write_all(b"partial ciphertext").unwrap();
            assert_eq!(temporary_artifacts(directory.path()).len(), 1);
        }

        assert!(!target.exists());
        assert!(temporary_artifacts(directory.path()).is_empty());
    }

    #[test]
    fn named_fallback_never_clobbers_a_racing_destination() {
        let directory = TempDir::new().unwrap();
        let target = directory.path().join("result");
        let mut output = named_atomic_output(&target);
        output.file_mut().write_all(b"ours").unwrap();
        fs::write(&target, b"racer").unwrap();

        assert!(matches!(output.commit(), Err(Error::OutputExists(_))));
        assert_eq!(fs::read(&target).unwrap(), b"racer");
        assert!(temporary_artifacts(directory.path()).is_empty());
    }

    #[test]
    fn proc_fd_fallback_publishes_the_held_anonymous_file() {
        let directory = TempDir::new().unwrap();
        let target = directory.path().join("result");
        let mut output = AtomicOutput::new(&target, TemporaryPolicy::AnonymousOnly).unwrap();
        output.file_mut().write_all(b"held file contents").unwrap();
        output.file_mut().sync_all().unwrap();

        output.publish_anonymous_via_proc().unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"held file contents");
        assert!(temporary_artifacts(directory.path()).is_empty());
    }

    #[test]
    fn destination_created_during_operation_wins_without_clobber() {
        let directory = TempDir::new().unwrap();
        let target = directory.path().join("result");
        let mut output = AtomicOutput::new(&target, TemporaryPolicy::AnonymousOnly).unwrap();
        output.file_mut().write_all(b"ours").unwrap();
        fs::write(&target, b"racer").unwrap();

        let error = output.commit().unwrap_err();
        assert!(matches!(error, Error::OutputExists(_)));
        assert_eq!(fs::read(&target).unwrap(), b"racer");
        assert!(temporary_artifacts(directory.path()).is_empty());
    }

    #[test]
    fn atomic_output_mode_is_exactly_private() {
        let directory = TempDir::new().unwrap();
        let target = directory.path().join("result");
        let output = AtomicOutput::new(&target, TemporaryPolicy::AnonymousOnly).unwrap();
        let mode = output.file.as_ref().unwrap().metadata().unwrap().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn random_temporary_names_are_well_formed_and_unique() {
        let path = Path::new("output");
        let names: HashSet<_> = (0..1_000)
            .map(|_| random_temporary_name(path).unwrap())
            .collect();

        assert_eq!(names.len(), 1_000);
        assert!(names.iter().all(|name| {
            let text = name.to_str().unwrap();
            text.len() == 44
                && text.starts_with(".secure-tmp-")
                && text[12..].bytes().all(|byte| byte.is_ascii_hexdigit())
        }));
    }

    #[test]
    fn unsafe_shared_directory_is_refused_for_named_fallback() {
        let directory = TempDir::new().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o777)).unwrap();
        let file = File::open(directory.path()).unwrap();

        let error = require_safe_named_fallback(&file, Path::new("out")).unwrap_err();
        assert!(matches!(error, Error::CreateTemporaryOutput { .. }));
    }

    #[test]
    fn owned_sticky_directory_is_safe_for_named_fallback() {
        let directory = TempDir::new().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o1777)).unwrap();
        let file = File::open(directory.path()).unwrap();

        require_safe_named_fallback(&file, Path::new("out")).unwrap();
    }

    #[test]
    fn private_directory_is_safe_for_named_fallback() {
        let directory = TempDir::new().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let file = File::open(directory.path()).unwrap();

        require_safe_named_fallback(&file, Path::new("out")).unwrap();
    }

    #[test]
    fn untrusted_directory_owner_is_never_safe_for_named_fallback() {
        assert!(!named_fallback_permissions_are_safe(0o700, 1_001, 1_000));
        assert!(!named_fallback_permissions_are_safe(0o755, 1_001, 1_000));
        assert!(!named_fallback_permissions_are_safe(0o1777, 1_001, 1_000));
    }

    #[test]
    fn trusted_named_fallback_permission_matrix_is_correct() {
        assert!(named_fallback_permissions_are_safe(0o700, 1_000, 1_000));
        assert!(named_fallback_permissions_are_safe(0o755, 1_000, 1_000));
        assert!(!named_fallback_permissions_are_safe(0o770, 1_000, 1_000));
        assert!(!named_fallback_permissions_are_safe(0o777, 1_000, 1_000));
        assert!(named_fallback_permissions_are_safe(0o1777, 1_000, 1_000));
        assert!(named_fallback_permissions_are_safe(0o1777, 0, 1_000));
    }

    #[test]
    fn decrypts_empty_file_atomically() {
        let directory = TempDir::new().unwrap();
        let input = write_ciphertext(&directory, b"");
        let output = directory.path().join("plain");

        decrypt_file(&input, &output, password()).unwrap();
        assert_eq!(fs::read(output).unwrap(), b"");
    }

    #[test]
    fn decrypts_multiple_chunks_exactly() {
        let directory = TempDir::new().unwrap();
        let plaintext: Vec<_> = (0_usize..(3 * 65_536 + 137))
            .map(|index| u8::try_from(index % 251).unwrap())
            .collect();
        let input = write_ciphertext(&directory, &plaintext);
        let output = directory.path().join("plain");

        decrypt_file(&input, &output, password()).unwrap();
        assert_eq!(fs::read(output).unwrap(), plaintext);
    }

    #[test]
    fn production_encrypt_and_decrypt_round_trip() {
        let directory = TempDir::new().unwrap();
        let plaintext = directory.path().join("plain");
        let encrypted = directory.path().join("encrypted.age");
        let recovered = directory.path().join("recovered");
        let data = b"production KDF integration check\0with binary bytes\xff";
        fs::write(&plaintext, data).unwrap();

        encrypt_file(&plaintext, &encrypted, password()).unwrap();
        let ciphertext = fs::read(&encrypted).unwrap();
        assert!(ciphertext.starts_with(b"age-encryption.org/v1\n"));
        assert!(!ciphertext.windows(data.len()).any(|window| window == data));
        let header_end = ciphertext
            .windows(5)
            .position(|window| window == b"\n--- ")
            .unwrap();
        let header = std::str::from_utf8(&ciphertext[..header_end]).unwrap();
        let stanza = header
            .lines()
            .find(|line| line.starts_with("-> scrypt "))
            .unwrap();
        assert_eq!(stanza.split_ascii_whitespace().last(), Some("18"));
        decrypt_file(&encrypted, &recovered, password()).unwrap();

        assert_eq!(fs::read(&plaintext).unwrap(), data);
        assert_eq!(fs::read(&recovered).unwrap(), data);
        assert_eq!(
            fs::metadata(&encrypted).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&recovered).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn wrong_password_never_publishes_plaintext() {
        let directory = TempDir::new().unwrap();
        let input = write_ciphertext(&directory, b"top secret");
        let output = directory.path().join("plain");

        let error = decrypt_file(
            &input,
            &output,
            SecretString::from("incorrect password".to_owned()),
        )
        .unwrap_err();

        assert!(matches!(error, Error::DecryptionFailed));
        assert!(!output.exists());
        assert!(temporary_artifacts(directory.path()).is_empty());
    }

    #[test]
    fn corrupted_payload_never_publishes_partial_plaintext() {
        let directory = TempDir::new().unwrap();
        let plaintext = vec![0x5a; 2 * 65_536 + 19];
        let mut ciphertext = cheap_ciphertext(&plaintext);
        let index = ciphertext.len() - 25;
        ciphertext[index] ^= 0x80;
        let input = directory.path().join("bad.age");
        let output = directory.path().join("plain");
        fs::write(&input, ciphertext).unwrap();

        assert!(matches!(
            decrypt_file(&input, &output, password()),
            Err(Error::DecryptionFailed)
        ));
        assert!(!output.exists());
        assert!(temporary_artifacts(directory.path()).is_empty());
    }

    #[test]
    fn truncated_payload_never_publishes_partial_plaintext() {
        let directory = TempDir::new().unwrap();
        let mut ciphertext = cheap_ciphertext(&vec![0xa5; 100_000]);
        ciphertext.truncate(ciphertext.len() - 1);
        let input = directory.path().join("truncated.age");
        let output = directory.path().join("plain");
        fs::write(&input, ciphertext).unwrap();

        assert!(decrypt_file(&input, &output, password()).is_err());
        assert!(!output.exists());
        assert!(temporary_artifacts(directory.path()).is_empty());
    }

    #[test]
    fn existing_regular_output_is_never_changed() {
        let directory = TempDir::new().unwrap();
        let input = write_ciphertext(&directory, b"new data");
        let output = directory.path().join("plain");
        fs::write(&output, b"keep me").unwrap();

        let error = decrypt_file(&input, &output, password()).unwrap_err();
        assert!(matches!(error, Error::OutputExists(_)));
        assert_eq!(fs::read(output).unwrap(), b"keep me");
    }

    #[test]
    fn dangling_output_symlink_is_never_replaced() {
        let directory = TempDir::new().unwrap();
        let input = write_ciphertext(&directory, b"new data");
        let referent = directory.path().join("missing");
        let output = directory.path().join("plain");
        symlink(&referent, &output).unwrap();

        let error = decrypt_file(&input, &output, password()).unwrap_err();
        assert!(matches!(error, Error::OutputExists(_)));
        assert_eq!(fs::read_link(output).unwrap(), referent);
    }

    #[test]
    fn output_hardlink_is_never_changed() {
        let directory = TempDir::new().unwrap();
        let input = write_ciphertext(&directory, b"new data");
        let referent = directory.path().join("valuable");
        let output = directory.path().join("plain");
        fs::write(&referent, b"keep me").unwrap();
        fs::hard_link(&referent, &output).unwrap();

        assert!(matches!(
            decrypt_file(&input, &output, password()),
            Err(Error::OutputExists(_))
        ));
        assert_eq!(fs::read(referent).unwrap(), b"keep me");
    }

    #[test]
    fn same_input_and_output_path_is_refused() {
        let directory = TempDir::new().unwrap();
        let input = write_ciphertext(&directory, b"data");
        let original = fs::read(&input).unwrap();

        assert!(matches!(
            decrypt_file(&input, &input, password()),
            Err(Error::OutputExists(_))
        ));
        assert_eq!(fs::read(input).unwrap(), original);
    }

    #[test]
    fn missing_input_does_not_create_output() {
        let directory = TempDir::new().unwrap();
        let input = directory.path().join("missing");
        let output = directory.path().join("plain");

        assert!(matches!(
            decrypt_file(&input, &output, password()),
            Err(Error::OpenInput { .. })
        ));
        assert!(!output.exists());
    }

    #[test]
    fn input_leaf_symlink_is_refused() {
        let directory = TempDir::new().unwrap();
        let real = write_ciphertext(&directory, b"data");
        let input = directory.path().join("link.age");
        let output = directory.path().join("plain");
        symlink(real, &input).unwrap();

        assert!(decrypt_file(&input, &output, password()).is_err());
        assert!(!output.exists());
    }

    #[test]
    fn input_ancestor_symlink_is_refused() {
        let directory = TempDir::new().unwrap();
        let real_directory = directory.path().join("real");
        fs::create_dir(&real_directory).unwrap();
        let real = real_directory.join("input.age");
        fs::write(&real, cheap_ciphertext(b"data")).unwrap();
        let linked_directory = directory.path().join("linked");
        symlink(&real_directory, &linked_directory).unwrap();
        let output = directory.path().join("plain");

        assert!(decrypt_file(&linked_directory.join("input.age"), &output, password()).is_err());
        assert!(!output.exists());
    }

    #[test]
    fn output_parent_symlink_is_refused() {
        let directory = TempDir::new().unwrap();
        let input = write_ciphertext(&directory, b"data");
        let real_directory = directory.path().join("real");
        fs::create_dir(&real_directory).unwrap();
        let linked_directory = directory.path().join("linked");
        symlink(&real_directory, &linked_directory).unwrap();
        let output = linked_directory.join("plain");

        assert!(matches!(
            decrypt_file(&input, &output, password()),
            Err(Error::OpenOutputDirectory { .. })
        ));
        assert!(!real_directory.join("plain").exists());
    }

    #[test]
    fn directory_input_is_refused() {
        let directory = TempDir::new().unwrap();
        let output = directory.path().join("plain");

        assert!(matches!(
            decrypt_file(directory.path(), &output, password()),
            Err(Error::InputNotRegular(_))
        ));
        assert!(!output.exists());
    }

    #[test]
    fn fifo_input_is_refused_without_blocking() {
        let directory = TempDir::new().unwrap();
        let fifo = directory.path().join("pipe");
        rustix::fs::mkfifoat(rustix::fs::CWD, &fifo, Mode::RUSR | Mode::WUSR).unwrap();
        let output = directory.path().join("plain");

        assert!(matches!(
            decrypt_file(&fifo, &output, password()),
            Err(Error::InputNotRegular(_))
        ));
        assert!(!output.exists());
    }

    #[test]
    fn unix_socket_input_is_refused() {
        let directory = TempDir::new().unwrap();
        let socket = directory.path().join("socket");
        let _listener = match UnixListener::bind(&socket) {
            Ok(listener) => listener,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
            Err(error) => panic!("could not create test socket: {error}"),
        };
        let output = directory.path().join("plain");

        assert!(decrypt_file(&socket, &output, password()).is_err());
        assert!(!output.exists());
    }

    #[test]
    fn missing_output_parent_is_refused() {
        let directory = TempDir::new().unwrap();
        let input = write_ciphertext(&directory, b"data");
        let output = directory.path().join("missing/child");

        assert!(matches!(
            decrypt_file(&input, &output, password()),
            Err(Error::OpenOutputDirectory { .. })
        ));
    }

    #[test]
    fn regular_file_as_output_parent_is_refused() {
        let directory = TempDir::new().unwrap();
        let input = write_ciphertext(&directory, b"data");
        let parent = directory.path().join("not-a-directory");
        fs::write(&parent, b"value").unwrap();

        assert!(matches!(
            decrypt_file(&input, &parent.join("child"), password()),
            Err(Error::OpenOutputDirectory { .. })
        ));
    }

    #[test]
    fn invalid_output_paths_are_refused() {
        for path in [
            Path::new("/"),
            Path::new("."),
            Path::new(".."),
            Path::new(""),
            Path::new("name/"),
            Path::new("name/."),
            Path::new("name/.."),
            Path::new("somewhere/name//"),
        ] {
            assert!(matches!(
                AtomicOutput::new(path, TemporaryPolicy::AnonymousOnly),
                Err(Error::InvalidOutputPath(_))
            ));
        }
    }

    #[test]
    fn cancellation_before_commit_never_publishes_output() {
        let directory = TempDir::new().unwrap();
        let target = directory.path().join("result");
        let mut output = AtomicOutput::new(&target, TemporaryPolicy::AnonymousOnly).unwrap();
        output
            .file_mut()
            .write_all(b"authenticated secret")
            .unwrap();
        let cancellation = Cancellation::never();
        cancellation.cancel_for_test();

        assert!(matches!(
            output.commit_cancellable(&cancellation),
            Err(Error::Interrupted)
        ));
        assert!(!target.exists());
        assert!(temporary_artifacts(directory.path()).is_empty());
    }

    #[test]
    fn pre_cancelled_decryption_does_not_open_or_create_paths() {
        let directory = TempDir::new().unwrap();
        let missing_input = directory.path().join("missing.age");
        let output = directory.path().join("plain");
        let cancellation = Cancellation::never();
        cancellation.cancel_for_test();

        assert!(matches!(
            decrypt_file_cancellable(&missing_input, &output, password(), &cancellation),
            Err(Error::Interrupted)
        ));
        assert!(!output.exists());
    }

    #[test]
    fn spaces_newlines_and_unicode_in_output_name_work() {
        let directory = TempDir::new().unwrap();
        let data = b"contents";
        let input = write_ciphertext(&directory, data);
        let output = directory.path().join("snowman \u{2603}\n file");

        decrypt_file(&input, &output, password()).unwrap();
        assert_eq!(fs::read(output).unwrap(), data);
    }

    #[test]
    fn non_utf8_input_and_output_names_work() {
        let directory = TempDir::new().unwrap();
        let input = directory
            .path()
            .join(OsString::from_vec(b"input-\xff.age".to_vec()));
        let output = directory
            .path()
            .join(OsString::from_vec(b"output-\xfe".to_vec()));
        fs::write(&input, cheap_ciphertext(b"binary path")).unwrap();

        decrypt_file(&input, &output, password()).unwrap();
        assert_eq!(fs::read(output).unwrap(), b"binary path");
    }

    #[test]
    fn concurrent_publish_has_exactly_one_winner() {
        let directory = TempDir::new().unwrap();
        let input = write_ciphertext(&directory, b"race-safe contents");
        let output = directory.path().join("plain");
        let barrier = Arc::new(Barrier::new(3));

        let handles: Vec<_> = (0..2)
            .map(|_| {
                let input = input.clone();
                let output = output.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    decrypt_file(&input, &output, password())
                })
            })
            .collect();
        barrier.wait();
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();

        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(Error::OutputExists(_))))
                .count(),
            1
        );
        assert_eq!(fs::read(output).unwrap(), b"race-safe contents");
        assert!(temporary_artifacts(directory.path()).is_empty());
    }

    #[test]
    fn input_snapshot_detects_content_and_length_changes() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("input");
        fs::write(&path, b"before").unwrap();
        let file = File::open(&path).unwrap();
        let before = InputSnapshot::capture(&file).unwrap();
        fs::write(&path, b"after and longer").unwrap();
        let after = InputSnapshot::capture(&file).unwrap();

        assert_ne!(before, after);
        assert_ne!(before.length, after.length);

        let same_length_before = InputSnapshot::capture(&file).unwrap();
        fs::write(&path, b"same-size-change").unwrap();
        let same_length_after = InputSnapshot::capture(&file).unwrap();
        assert_eq!(same_length_before.length, same_length_after.length);
        assert_ne!(same_length_before, same_length_after);
    }
}
