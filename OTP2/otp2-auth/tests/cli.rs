#![cfg(target_os = "linux")]

use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

const KEY_LENGTH: usize = 32;
const TAG_LENGTH: usize = 64;

static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        for _ in 0..1_000 {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path =
                env::temp_dir().join(format!("oac-{}-{sequence}-{label}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("create test directory {path:?}: {error}"),
            }
        }
        panic!("could not allocate a CLI-test directory")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Fixture {
    _temp: TempDir,
    bin: PathBuf,
    work: PathBuf,
    executable: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let temp = TempDir::new(label);
        let bin = temp.0.join("private binaries λ");
        let work = temp.0.join("unrelated working directory");
        fs::create_dir(&bin).expect("create binary directory");
        fs::create_dir(&work).expect("create working directory");
        let executable = bin.join("otp2-auth");
        fs::copy(env!("CARGO_BIN_EXE_otp2-auth"), &executable)
            .expect("copy standalone otp2-auth binary");
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))
            .expect("make copied binary executable");
        Self {
            _temp: temp,
            bin,
            work,
            executable,
        }
    }

    fn key(&self) -> PathBuf {
        self.bin.join("auth.key")
    }

    fn write_key(&self, bytes: &[u8]) {
        let path = self.key();
        fs::write(&path, bytes).expect("write auth key");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .expect("make auth key private");
    }

    fn file(&self, name: impl AsRef<Path>, bytes: &[u8]) -> PathBuf {
        let path = self.work.join(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create file parent");
        }
        fs::write(&path, bytes).expect("write test file");
        path
    }

    fn tag_path(&self, file: &Path) -> PathBuf {
        let mut path = file.as_os_str().to_os_string();
        path.push(".otp2auth");
        PathBuf::from(path)
    }

    fn run<I, S>(&self, arguments: I) -> Output
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.run_with_umask(None, arguments)
    }

    fn run_with_umask<I, S>(&self, mask: Option<libc::mode_t>, arguments: I) -> Output
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let arguments: Vec<OsString> = arguments
            .into_iter()
            .map(|argument| argument.as_ref().to_os_string())
            .collect();
        for attempt in 0..100 {
            let mut command = Command::new(&self.executable);
            command.current_dir(&self.work).args(&arguments);
            if let Some(mask) = mask {
                // SAFETY: the child-side closure only invokes async-signal-safe
                // `umask` before exec and does not access shared state.
                unsafe {
                    command.pre_exec(move || {
                        libc::umask(mask);
                        Ok(())
                    });
                }
            }
            match command.output() {
                Ok(output) => return output,
                Err(error)
                    if error.kind() == io::ErrorKind::ExecutableFileBusy && attempt != 99 =>
                {
                    thread::yield_now();
                }
                Err(error) => panic!("run isolated otp2-auth: {error}"),
            }
        }
        unreachable!("the final command attempt returns")
    }
}

#[derive(Debug, Eq, PartialEq)]
struct Fingerprint {
    len: u64,
    dev: u64,
    ino: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    links: u64,
    mtime: i64,
    mtime_nsec: i64,
}

fn fingerprint(path: &Path) -> Fingerprint {
    let metadata = fs::metadata(path).unwrap_or_else(|error| panic!("inspect {path:?}: {error}"));
    Fingerprint {
        len: metadata.len(),
        dev: metadata.dev(),
        ino: metadata.ino(),
        mode: metadata.mode(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        links: metadata.nlink(),
        mtime: metadata.mtime(),
        mtime_nsec: metadata.mtime_nsec(),
    }
}

fn assert_exit(output: &Output, code: i32) {
    assert_eq!(
        output.status.code(),
        Some(code),
        "unexpected exit\nstdout: {:?}\nstderr: {:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_success(output: &Output) {
    assert_exit(output, 0);
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

fn assert_runtime_failure(output: &Output) {
    assert_exit(output, 1);
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
}

fn assert_auth_failure(output: &Output) {
    assert_exit(output, 4);
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
}

fn deterministic_bytes(length: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    let mut result = Vec::with_capacity(length);
    for _ in 0..length {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        result.push((state >> 24) as u8);
    }
    result
}

fn create_fifo(path: &Path) {
    let name = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: the C string is valid and `mkfifo` does not access Rust memory.
    let result = unsafe { libc::mkfifo(name.as_ptr(), 0o600) };
    assert_eq!(result, 0, "mkfifo failed: {}", io::Error::last_os_error());
}

#[test]
fn tag_and_verify_are_quiet_and_never_modify_payload_or_key() {
    let fixture = Fixture::new("basic-nonmutation");
    fixture.write_key(&[0x73; KEY_LENGTH]);
    let bytes = deterministic_bytes(2 * 64 * 1024 + 97, 0x1234_5678);
    let file = fixture.file("payload with spaces λ.bin", &bytes);
    fs::set_permissions(&file, fs::Permissions::from_mode(0o440)).unwrap();
    let file_before = fingerprint(&file);
    let key_before = fingerprint(&fixture.key());

    assert_success(&fixture.run([OsStr::new("tag"), file.as_os_str()]));
    let tag = fixture.tag_path(&file);
    assert_eq!(fs::metadata(&tag).unwrap().len(), TAG_LENGTH as u64);
    assert_eq!(fs::metadata(&tag).unwrap().mode() & 0o777, 0o600);
    assert_eq!(fs::read(&file).unwrap(), bytes);
    assert_eq!(fingerprint(&file), file_before);
    assert_eq!(fingerprint(&fixture.key()), key_before);

    let tag_before = fingerprint(&tag);
    let tag_bytes = fs::read(&tag).unwrap();
    assert_success(&fixture.run([OsStr::new("verify"), file.as_os_str()]));
    assert_eq!(fs::read(&file).unwrap(), bytes);
    assert_eq!(fs::read(&tag).unwrap(), tag_bytes);
    assert_eq!(fingerprint(&file), file_before);
    assert_eq!(fingerprint(&tag), tag_before);
    assert_eq!(fingerprint(&fixture.key()), key_before);
}

#[test]
fn empty_binary_and_stream_boundary_files_round_trip_detached() {
    for (case, length) in [
        ("empty", 0),
        ("one", 1),
        ("thirty-one", 31),
        ("thirty-two", 32),
        ("sixty-three", 63),
        ("sixty-four", 64),
        ("sixty-five", 65),
        ("chunk-minus-one", 65_535),
        ("chunk", 65_536),
        ("chunk-plus-one", 65_537),
        ("multi-chunk", 3 * 65_536 + 19),
    ] {
        let fixture = Fixture::new(case);
        fixture.write_key(&[0x4b; KEY_LENGTH]);
        let bytes = deterministic_bytes(length, length as u64 + 91);
        let file = fixture.file("object.bin", &bytes);
        let before = fingerprint(&file);
        assert_success(&fixture.run([OsStr::new("tag"), file.as_os_str()]));
        assert_success(&fixture.run([OsStr::new("verify"), file.as_os_str()]));
        assert_eq!(fs::read(&file).unwrap(), bytes, "case {case}");
        assert_eq!(fingerprint(&file), before, "case {case}");
    }
}

#[test]
fn sidecar_magic_prefixed_and_every_byte_value_payloads_are_supported() {
    let fixture = Fixture::new("arbitrary-binary");
    fixture.write_key(&[0xc1; KEY_LENGTH]);
    let mut bytes = b"otp2TAG\0arbitrary payload bytes\0".to_vec();
    bytes.extend(0..=u8::MAX);
    bytes.extend((0..=u8::MAX).rev());
    let file = fixture.file("arbitrary.bin", &bytes);
    let before = fingerprint(&file);

    assert_success(&fixture.run([OsStr::new("tag"), file.as_os_str()]));
    assert_success(&fixture.run([OsStr::new("verify"), file.as_os_str()]));
    assert_eq!(fs::read(&file).unwrap(), bytes);
    assert_eq!(fingerprint(&file), before);
}

#[test]
fn explicit_sidecars_and_replace_have_stable_no_clobber_semantics() {
    let fixture = Fixture::new("explicit-replace");
    fixture.write_key(&[0x58; KEY_LENGTH]);
    let file = fixture.file("payload", b"first payload");
    let tag = fixture.work.join("selected detached tag");
    assert_success(&fixture.run([
        OsStr::new("tag"),
        OsStr::new("--output"),
        tag.as_os_str(),
        file.as_os_str(),
    ]));
    let old_tag = fs::read(&tag).unwrap();
    let old_identity = fingerprint(&tag);

    fs::write(&file, b"second payload with different bytes").unwrap();
    let output = fixture.run([
        OsStr::new("tag"),
        OsStr::new("--output"),
        tag.as_os_str(),
        file.as_os_str(),
    ]);
    assert_runtime_failure(&output);
    assert_eq!(fs::read(&tag).unwrap(), old_tag);
    assert_eq!(fingerprint(&tag), old_identity);

    assert_success(&fixture.run([
        OsStr::new("tag"),
        OsStr::new("--replace"),
        OsStr::new("--output"),
        tag.as_os_str(),
        file.as_os_str(),
    ]));
    assert_ne!(fs::read(&tag).unwrap(), old_tag);
    assert_ne!(fingerprint(&tag).ino, old_identity.ino);
    assert_eq!(fs::metadata(&tag).unwrap().mode() & 0o777, 0o600);
    assert_success(&fixture.run([
        OsStr::new("verify"),
        OsStr::new("--tag"),
        tag.as_os_str(),
        file.as_os_str(),
    ]));
}

#[test]
fn replace_rejects_symlink_hardlink_directory_fifo_and_socket_sidecars() {
    enum Kind {
        Symlink,
        Hardlink,
        Directory,
        Fifo,
        Socket,
    }
    for (label, kind) in [
        ("symlink", Kind::Symlink),
        ("hardlink", Kind::Hardlink),
        ("directory", Kind::Directory),
        ("fifo", Kind::Fifo),
        ("socket", Kind::Socket),
    ] {
        let fixture = Fixture::new(&format!("replace-{label}"));
        fixture.write_key(&[0x19; KEY_LENGTH]);
        let file = fixture.file("payload", b"payload remains unchanged");
        let tag = fixture.work.join("chosen-tag");
        let referent = fixture.file("referent", b"referent remains unchanged");
        let _listener = match kind {
            Kind::Symlink => {
                std::os::unix::fs::symlink(&referent, &tag).unwrap();
                None
            }
            Kind::Hardlink => {
                fs::hard_link(&referent, &tag).unwrap();
                None
            }
            Kind::Directory => {
                fs::create_dir(&tag).unwrap();
                None
            }
            Kind::Fifo => {
                create_fifo(&tag);
                None
            }
            Kind::Socket => match UnixListener::bind(&tag) {
                Ok(listener) => Some(listener),
                Err(error) if error.kind() == io::ErrorKind::PermissionDenied => continue,
                Err(error) => panic!("create Unix socket sidecar: {error}"),
            },
        };
        let file_before = fingerprint(&file);
        let referent_before = fs::read(&referent).unwrap();
        let output = fixture.run([
            OsStr::new("tag"),
            OsStr::new("--replace"),
            OsStr::new("--output"),
            tag.as_os_str(),
            file.as_os_str(),
        ]);
        assert_runtime_failure(&output);
        assert_eq!(fingerprint(&file), file_before);
        assert_eq!(fs::read(&referent).unwrap(), referent_before);
        assert!(visible_temp_files(&fixture.work).is_empty());
    }
}

fn visible_temp_files(path: &Path) -> Vec<PathBuf> {
    fs::read_dir(path)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            let name = path.file_name().unwrap().to_string_lossy();
            name.starts_with(".otp2-auth-") && name.ends_with(".tmp")
        })
        .collect()
}

#[test]
fn wrong_key_payload_corruption_and_sidecar_corruption_are_exit_four_and_nonmutating() {
    let fixture = Fixture::new("authentication-failures");
    fixture.write_key(&[0x22; KEY_LENGTH]);
    let original = deterministic_bytes(65_539, 0xcafe_babe);
    let file = fixture.file("payload", &original);
    assert_success(&fixture.run([OsStr::new("tag"), file.as_os_str()]));
    let tag = fixture.tag_path(&file);
    let valid_tag = fs::read(&tag).unwrap();

    fixture.write_key(&[0x23; KEY_LENGTH]);
    let file_before = fingerprint(&file);
    let tag_before = fingerprint(&tag);
    assert_auth_failure(&fixture.run([OsStr::new("verify"), file.as_os_str()]));
    assert_eq!(fingerprint(&file), file_before);
    assert_eq!(fingerprint(&tag), tag_before);

    fixture.write_key(&[0x22; KEY_LENGTH]);
    let mut changed_payload = original.clone();
    changed_payload[32_777] ^= 0x80;
    fs::write(&file, &changed_payload).unwrap();
    assert_auth_failure(&fixture.run([OsStr::new("verify"), file.as_os_str()]));
    assert_eq!(fs::read(&file).unwrap(), changed_payload);
    assert_eq!(fs::read(&tag).unwrap(), valid_tag);

    fs::write(&file, &original).unwrap();
    let mut changed_tag = valid_tag.clone();
    changed_tag[63] ^= 1;
    fs::write(&tag, &changed_tag).unwrap();
    assert_auth_failure(&fixture.run([OsStr::new("verify"), file.as_os_str()]));
    assert_eq!(fs::read(&file).unwrap(), original);
    assert_eq!(fs::read(&tag).unwrap(), changed_tag);
}

#[test]
fn missing_sidecar_is_operational_but_malformed_sidecars_are_auth_failures() {
    let fixture = Fixture::new("missing-malformed");
    fixture.write_key(&[0x31; KEY_LENGTH]);
    let file = fixture.file("payload", b"payload");
    assert_runtime_failure(&fixture.run([OsStr::new("verify"), file.as_os_str()]));

    let tag = fixture.tag_path(&file);
    for malformed in [Vec::new(), vec![0; 63], vec![0; 64], vec![0; 65]] {
        fs::write(&tag, malformed).unwrap();
        let output = fixture.run([OsStr::new("verify"), file.as_os_str()]);
        assert_auth_failure(&output);
    }
}

#[test]
fn key_length_permissions_links_and_aliases_fail_closed() {
    for length in [0, 31, 33] {
        let fixture = Fixture::new(&format!("key-length-{length}"));
        fixture.write_key(&vec![0x55; length]);
        let file = fixture.file("payload", b"unchanged");
        let before = fingerprint(&file);
        assert_runtime_failure(&fixture.run([OsStr::new("tag"), file.as_os_str()]));
        assert_eq!(fingerprint(&file), before);
        assert!(!fixture.tag_path(&file).exists());
    }

    for mode in [0o640, 0o604, 0o610, 0o601] {
        let fixture = Fixture::new(&format!("key-mode-{mode:o}"));
        fixture.write_key(&[0x55; KEY_LENGTH]);
        fs::set_permissions(fixture.key(), fs::Permissions::from_mode(mode)).unwrap();
        let file = fixture.file("payload", b"unchanged");
        assert_runtime_failure(&fixture.run([OsStr::new("tag"), file.as_os_str()]));
        assert!(!fixture.tag_path(&file).exists());
    }

    let fixture = Fixture::new("key-hardlink");
    fixture.write_key(&[0x55; KEY_LENGTH]);
    fs::hard_link(fixture.key(), fixture.bin.join("key-alias")).unwrap();
    let file = fixture.file("payload", b"unchanged");
    assert_runtime_failure(&fixture.run([OsStr::new("tag"), file.as_os_str()]));

    let fixture = Fixture::new("file-is-key");
    fixture.write_key(&[0x55; KEY_LENGTH]);
    let key_before = fingerprint(&fixture.key());
    assert_runtime_failure(&fixture.run([OsStr::new("tag"), fixture.key().as_os_str()]));
    assert_eq!(fingerprint(&fixture.key()), key_before);
}

#[test]
fn input_symlink_directory_fifo_socket_and_character_device_are_rejected_without_blocking() {
    let fixture = Fixture::new("invalid-input-types");
    fixture.write_key(&[0x67; KEY_LENGTH]);
    let referent = fixture.file("referent", b"referent");
    let symlink = fixture.work.join("symlink");
    std::os::unix::fs::symlink(&referent, &symlink).unwrap();
    let directory = fixture.work.join("directory");
    fs::create_dir(&directory).unwrap();
    let fifo = fixture.work.join("fifo");
    create_fifo(&fifo);
    let socket = fixture.work.join("socket");
    let listener = UnixListener::bind(&socket).ok();
    let mut paths = vec![symlink.as_path(), &directory, &fifo, Path::new("/dev/null")];
    if listener.is_some() {
        paths.push(&socket);
    }
    for path in paths {
        let output = fixture.run([OsStr::new("tag"), path.as_os_str()]);
        assert_runtime_failure(&output);
    }
    assert_eq!(fs::read(referent).unwrap(), b"referent");
}

#[test]
fn verify_accepts_regular_sidecar_hardlinks_but_rejects_every_nonregular_terminal() {
    let fixture = Fixture::new("sidecar-types");
    fixture.write_key(&[0x72; KEY_LENGTH]);
    let file = fixture.file("payload", b"payload");
    assert_success(&fixture.run([OsStr::new("tag"), file.as_os_str()]));
    let valid_tag = fixture.tag_path(&file);
    let hardlink = fixture.work.join("tag hardlink");
    fs::hard_link(&valid_tag, &hardlink).unwrap();
    assert_success(&fixture.run([
        OsStr::new("verify"),
        OsStr::new("--tag"),
        hardlink.as_os_str(),
        file.as_os_str(),
    ]));

    let symlink = fixture.work.join("tag symlink");
    std::os::unix::fs::symlink(&valid_tag, &symlink).unwrap();
    let directory = fixture.work.join("tag directory");
    fs::create_dir(&directory).unwrap();
    let fifo = fixture.work.join("tag fifo");
    create_fifo(&fifo);
    let socket = fixture.work.join("tag socket");
    let listener = UnixListener::bind(&socket).ok();
    let mut tags = vec![symlink.as_path(), &directory, &fifo, Path::new("/dev/null")];
    if listener.is_some() {
        tags.push(&socket);
    }
    for tag in tags {
        assert_runtime_failure(&fixture.run([
            OsStr::new("verify"),
            OsStr::new("--tag"),
            tag.as_os_str(),
            file.as_os_str(),
        ]));
    }
}

#[test]
fn symlink_directory_fifo_and_socket_authentication_keys_are_rejected_safely() {
    enum Kind {
        Symlink,
        Directory,
        Fifo,
        Socket,
    }
    for (label, kind) in [
        ("symlink", Kind::Symlink),
        ("directory", Kind::Directory),
        ("fifo", Kind::Fifo),
        ("socket", Kind::Socket),
    ] {
        let fixture = Fixture::new(&format!("key-type-{label}"));
        let file = fixture.file("payload", b"payload");
        let referent = fixture.file("key referent", &[0x66; KEY_LENGTH]);
        let _listener = match kind {
            Kind::Symlink => {
                std::os::unix::fs::symlink(&referent, fixture.key()).unwrap();
                None
            }
            Kind::Directory => {
                fs::create_dir(fixture.key()).unwrap();
                None
            }
            Kind::Fifo => {
                create_fifo(&fixture.key());
                None
            }
            Kind::Socket => match UnixListener::bind(fixture.key()) {
                Ok(listener) => Some(listener),
                Err(error) if error.kind() == io::ErrorKind::PermissionDenied => continue,
                Err(error) => panic!("create Unix socket key: {error}"),
            },
        };
        assert_runtime_failure(&fixture.run([OsStr::new("tag"), file.as_os_str()]));
        assert_eq!(fs::read(&file).unwrap(), b"payload");
        assert_eq!(fs::read(&referent).unwrap(), [0x66; KEY_LENGTH]);
        assert!(!fixture.tag_path(&file).exists());
    }
}

#[test]
fn keygen_is_private_random_quiet_and_never_overwrites_any_existing_path() {
    let first = Fixture::new("keygen-first");
    let second = Fixture::new("keygen-second");
    assert_success(&first.run_with_umask(Some(0), ["keygen"]));
    assert_success(&second.run_with_umask(Some(0), ["keygen"]));
    let first_bytes = fs::read(first.key()).unwrap();
    let second_bytes = fs::read(second.key()).unwrap();
    assert_eq!(first_bytes.len(), KEY_LENGTH);
    assert_eq!(second_bytes.len(), KEY_LENGTH);
    assert_ne!(first_bytes, second_bytes);
    assert_eq!(fs::metadata(first.key()).unwrap().mode() & 0o777, 0o600);

    let before = fingerprint(&first.key());
    assert_runtime_failure(&first.run(["keygen"]));
    assert_eq!(fingerprint(&first.key()), before);

    let symlink_fixture = Fixture::new("keygen-symlink");
    let referent = symlink_fixture.file("key-referent", b"irreplaceable");
    std::os::unix::fs::symlink(&referent, symlink_fixture.key()).unwrap();
    assert_runtime_failure(&symlink_fixture.run(["keygen"]));
    assert_eq!(fs::read(referent).unwrap(), b"irreplaceable");
}

#[test]
fn executable_relative_key_wins_and_working_directory_key_is_never_used() {
    let fixture = Fixture::new("key-location");
    fixture.write_key(&[0x89; KEY_LENGTH]);
    let decoy = vec![0xfe; KEY_LENGTH];
    fs::write(fixture.work.join("auth.key"), &decoy).unwrap();
    let file = fixture.file("payload", b"payload");
    assert_success(&fixture.run([OsStr::new("tag"), file.as_os_str()]));
    assert_eq!(fs::read(fixture.work.join("auth.key")).unwrap(), decoy);

    fs::write(fixture.key(), [0x90; 31]).unwrap();
    fs::set_permissions(fixture.key(), fs::Permissions::from_mode(0o600)).unwrap();
    assert_runtime_failure(&fixture.run([OsStr::new("verify"), file.as_os_str()]));
}

#[test]
fn dash_prefixed_and_non_utf8_filenames_use_byte_preserving_default_sidecars() {
    let fixture = Fixture::new("opaque-names");
    fixture.write_key(&[0xa2; KEY_LENGTH]);

    let dash = fixture.file("-payload", b"dash payload");
    assert_success(&fixture.run([OsStr::new("tag"), OsStr::new("--"), dash.as_os_str()]));
    assert_success(&fixture.run([OsStr::new("verify"), OsStr::new("--"), dash.as_os_str()]));

    let name = OsString::from_vec(b"payload-\xff.bin".to_vec());
    let opaque = fixture.file(PathBuf::from(&name), b"opaque payload");
    assert_success(&fixture.run([OsStr::new("tag"), opaque.as_os_str()]));
    let tag = fixture.tag_path(&opaque);
    assert!(tag.exists());
    assert_eq!(
        tag.file_name().unwrap().as_encoded_bytes(),
        b"payload-\xff.bin.otp2auth"
    );
    assert_success(&fixture.run([OsStr::new("verify"), opaque.as_os_str()]));
}

#[test]
fn help_usage_and_exit_stream_contracts_are_stable() {
    let fixture = Fixture::new("usage");
    for flag in ["-h", "--help"] {
        let output = fixture.run([flag]);
        assert_exit(&output, 0);
        assert!(!output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }
    for arguments in [
        vec![],
        vec!["unknown"],
        vec!["keygen", "extra"],
        vec!["tag"],
        vec!["verify"],
        vec!["tag", "--replace", "--replace", "file"],
        vec!["tag", "--output", "a", "--output", "b", "file"],
        vec!["verify", "--tag", "a", "--tag", "b", "file"],
    ] {
        let output = fixture.run(arguments);
        assert_exit(&output, 2);
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
    }
}

#[test]
fn diagnostics_never_disclose_authentication_key_material() {
    const CANARY: &[u8; 32] = b"otp2-AUTH-SECRET-CANARY-12345678";
    let fixture = Fixture::new("diagnostic-secrecy");
    fixture.write_key(CANARY);
    let file = fixture.file("payload", b"payload");
    assert_success(&fixture.run([OsStr::new("tag"), file.as_os_str()]));
    let mut tag = fs::read(fixture.tag_path(&file)).unwrap();
    tag[63] ^= 1;
    fs::write(fixture.tag_path(&file), tag).unwrap();
    let output = fixture.run([OsStr::new("verify"), file.as_os_str()]);
    assert_auth_failure(&output);
    assert!(
        !output
            .stdout
            .windows(CANARY.len())
            .any(|window| window == CANARY)
    );
    assert!(
        !output
            .stderr
            .windows(CANARY.len())
            .any(|window| window == CANARY)
    );
}

#[test]
fn sidecar_file_and_key_aliases_are_rejected_without_mutation() {
    let fixture = Fixture::new("sidecar-aliases");
    fixture.write_key(&[0xb4; KEY_LENGTH]);
    let file = fixture.file("payload", b"payload");
    let file_before = fingerprint(&file);
    let key_before = fingerprint(&fixture.key());

    assert_runtime_failure(&fixture.run([
        OsStr::new("tag"),
        OsStr::new("--replace"),
        OsStr::new("--output"),
        file.as_os_str(),
        file.as_os_str(),
    ]));
    assert_runtime_failure(&fixture.run([
        OsStr::new("tag"),
        OsStr::new("--replace"),
        OsStr::new("--output"),
        fixture.key().as_os_str(),
        file.as_os_str(),
    ]));
    assert_eq!(fingerprint(&file), file_before);
    assert_eq!(fingerprint(&fixture.key()), key_before);
}

#[test]
fn verification_accepts_owner_private_read_only_keys() {
    let fixture = Fixture::new("read-only-key");
    fixture.write_key(&[0xd5; KEY_LENGTH]);
    let file = fixture.file("payload", b"payload");
    assert_success(&fixture.run([OsStr::new("tag"), file.as_os_str()]));
    fs::set_permissions(fixture.key(), fs::Permissions::from_mode(0o400)).unwrap();
    let key_before = fingerprint(&fixture.key());
    assert_success(&fixture.run([OsStr::new("verify"), file.as_os_str()]));
    assert_eq!(fingerprint(&fixture.key()), key_before);
}

#[test]
fn terminal_directory_spellings_are_rejected_without_touching_regular_files() {
    let fixture = Fixture::new("terminal-components");
    fixture.write_key(&[0xe6; KEY_LENGTH]);
    let file = fixture.file("payload", b"payload");
    let before = fingerprint(&file);
    for suffix in ["/", "/."] {
        let mut ambiguous = file.clone().into_os_string();
        ambiguous.push(suffix);
        let output = fixture.run([OsStr::new("tag"), ambiguous.as_os_str()]);
        assert_runtime_failure(&output);
    }
    assert_eq!(fingerprint(&file), before);
    assert!(!fixture.tag_path(&file).exists());
}
