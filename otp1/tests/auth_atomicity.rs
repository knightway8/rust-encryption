#![cfg(unix)]

use std::collections::BTreeSet;
use std::env;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{self as unix_fs, FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

const AUTH_KEY: [u8; 32] = [0xa7; 32];
const OTHER_AUTH_KEY: [u8; 32] = [0x3c; 32];

static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_os = "linux")]
static BARRIER_TEST_LOCK: Mutex<()> = Mutex::new(());

struct ScratchDirectory(PathBuf);

impl ScratchDirectory {
    fn new(label: &str) -> io::Result<Self> {
        for _ in 0..1_000 {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let candidate = env::temp_dir().join(format!(
                "otp1-auth-atomicity-{label}-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&candidate) {
                Ok(()) => return Ok(Self(candidate)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not create a unique authentication-test directory",
        ))
    }
}

impl Drop for ScratchDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Fixture {
    _scratch: ScratchDirectory,
    bin_dir: PathBuf,
    work_dir: PathBuf,
    data_dir: PathBuf,
    executable: PathBuf,
    target: PathBuf,
    key: PathBuf,
}

impl Fixture {
    fn new(label: &str, bytes: &[u8]) -> io::Result<Self> {
        let scratch = ScratchDirectory::new(label)?;
        let bin_dir = scratch.0.join("executable directory");
        let work_dir = scratch.0.join("unrelated working directory");
        let data_dir = scratch.0.join("data directory");
        fs::create_dir(&bin_dir)?;
        fs::create_dir(&work_dir)?;
        fs::create_dir(&data_dir)?;

        let executable = bin_dir.join("otp1-auth-under-test");
        fs::copy(env!("CARGO_BIN_EXE_otp1-auth"), &executable)?;
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))?;
        let key = bin_dir.join("auth.key");
        fs::write(&key, AUTH_KEY)?;
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600))?;
        let target = data_dir.join("ciphertext.bin");
        fs::write(&target, bytes)?;

        Ok(Self {
            _scratch: scratch,
            bin_dir,
            work_dir,
            data_dir,
            executable,
            target,
            key,
        })
    }

    fn command(&self, operation: &str, path: &Path) -> Command {
        let mut command = Command::new(&self.executable);
        command.arg(operation).arg(path).current_dir(&self.work_dir);
        command
    }

    fn run(&self, operation: &str) -> io::Result<Output> {
        self.run_path(operation, &self.target)
    }

    fn run_path(&self, operation: &str, path: &Path) -> io::Result<Output> {
        for attempt in 0..100 {
            match self.command(operation, path).output() {
                Ok(output) => return Ok(output),
                Err(error)
                    if error.kind() == io::ErrorKind::ExecutableFileBusy && attempt != 99 =>
                {
                    thread::yield_now();
                }
                Err(error) => return Err(error),
            }
        }
        unreachable!("the final process-launch attempt returns")
    }

    fn spawn(&self, operation: &str) -> io::Result<ManagedChild> {
        self.spawn_path(operation, &self.target)
    }

    fn spawn_path(&self, operation: &str, path: &Path) -> io::Result<ManagedChild> {
        for attempt in 0..100 {
            let mut command = self.command(operation, path);
            command.stdout(Stdio::piped()).stderr(Stdio::piped());
            match command.spawn() {
                Ok(child) => return Ok(ManagedChild(Some(child))),
                Err(error)
                    if error.kind() == io::ErrorKind::ExecutableFileBusy && attempt != 99 =>
                {
                    thread::yield_now();
                }
                Err(error) => return Err(error),
            }
        }
        unreachable!("the final process-launch attempt returns")
    }
}

struct ManagedChild(Option<Child>);

impl ManagedChild {
    fn child(&self) -> &Child {
        self.0.as_ref().expect("managed child is present")
    }

    fn child_mut(&mut self) -> &mut Child {
        self.0.as_mut().expect("managed child is present")
    }

    fn wait_with_timeout(mut self, timeout: Duration) -> io::Result<Output> {
        let started = Instant::now();
        loop {
            if self.child_mut().try_wait()?.is_some() {
                let child = self.0.take().expect("managed child is present");
                return child.wait_with_output();
            }
            if started.elapsed() >= timeout {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "otp1-auth did not exit before the test timeout",
                ));
            }
            thread::yield_now();
        }
    }
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[track_caller]
fn assert_success(output: &Output) {
    assert_eq!(
        output.status.code(),
        Some(0),
        "unexpected status\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty(), "success wrote to stdout");
    assert!(output.stderr.is_empty(), "success wrote to stderr");
}

#[track_caller]
fn assert_runtime_failure(output: &Output) {
    assert_eq!(
        output.status.code(),
        Some(1),
        "expected a runtime failure\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty(), "failure wrote to stdout");
    assert!(!output.stderr.is_empty(), "failure did not explain itself");
}

#[track_caller]
fn assert_authentication_failure(output: &Output) {
    assert_eq!(
        output.status.code(),
        Some(4),
        "expected an authentication failure\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty(), "failure wrote to stdout");
    assert!(!output.stderr.is_empty(), "failure did not explain itself");
}

fn identity(path: &Path) -> io::Result<(u64, u64)> {
    let metadata = fs::metadata(path)?;
    Ok((metadata.dev(), metadata.ino()))
}

fn mode(path: &Path) -> io::Result<u32> {
    Ok(fs::metadata(path)?.permissions().mode() & 0o7777)
}

fn entries(path: &Path) -> io::Result<BTreeSet<OsString>> {
    fs::read_dir(path)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect()
}

fn visible_temp_files(path: &Path) -> io::Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(".otp1-") && name.ends_with(".tmp") {
            paths.push(entry.path());
        }
    }
    paths.sort();
    Ok(paths)
}

fn read_open_file(file: &mut File) -> io::Result<Vec<u8>> {
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn pseudo_random_bytes(length: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    let mut output = Vec::with_capacity(length);
    for _ in 0..length {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        output.push((state >> 24) as u8);
    }
    output
}

fn write_repeated(path: &Path, byte: u8, length: usize) -> io::Result<()> {
    let mut file = File::create(path)?;
    let buffer = [byte; 64 * 1024];
    let mut remaining = length;
    while remaining != 0 {
        let amount = remaining.min(buffer.len());
        file.write_all(&buffer[..amount])?;
        remaining -= amount;
    }
    file.sync_all()
}

fn create_fifo(path: &Path) -> io::Result<()> {
    let status = Command::new("mkfifo").arg(path).status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!("mkfifo failed with {status}")))
    }
}

#[test]
fn seal_and_unwrap_replace_inodes_preserve_mode_and_keep_old_views_complete() -> io::Result<()> {
    let raw = pseudo_random_bytes(512 * 1024 + 37, 0x6c9e_81b2);
    let fixture = Fixture::new("successful-transactions", &raw)?;
    fs::set_permissions(&fixture.target, fs::Permissions::from_mode(0o640))?;
    let initial_entries = entries(&fixture.data_dir)?;
    let initial_identity = identity(&fixture.target)?;
    let mut held_raw = File::open(&fixture.target)?;

    let seal_output = fixture.run("seal")?;
    assert_success(&seal_output);
    let sealed_identity = identity(&fixture.target)?;
    let sealed = fs::read(&fixture.target)?;
    assert_ne!(sealed_identity, initial_identity);
    assert_eq!(mode(&fixture.target)?, 0o640);
    assert_eq!(&sealed[..8], b"OTP1AUTH");
    assert_eq!(&sealed[32..sealed.len() - 32], raw);
    assert_eq!(read_open_file(&mut held_raw)?, raw);
    assert_eq!(entries(&fixture.data_dir)?, initial_entries);
    assert!(visible_temp_files(&fixture.data_dir)?.is_empty());

    let mut held_envelope = File::open(&fixture.target)?;
    let unwrap_output = fixture.run("unwrap")?;
    assert_success(&unwrap_output);
    assert_ne!(identity(&fixture.target)?, sealed_identity);
    assert_eq!(mode(&fixture.target)?, 0o640);
    assert_eq!(fs::read(&fixture.target)?, raw);
    assert_eq!(read_open_file(&mut held_envelope)?, sealed);
    assert_eq!(entries(&fixture.data_dir)?, initial_entries);
    assert!(visible_temp_files(&fixture.data_dir)?.is_empty());
    assert_eq!(fs::read(&fixture.key)?, AUTH_KEY);
    Ok(())
}

#[test]
fn invalid_tag_unwrap_preserves_exact_file_identity_mode_and_directory() -> io::Result<()> {
    let raw = pseudo_random_bytes(192 * 1024 + 11, 0x73b4_005d);
    let fixture = Fixture::new("invalid-tag", &raw)?;
    assert_success(&fixture.run("seal")?);

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&fixture.target)?;
    file.seek(SeekFrom::End(-1))?;
    let mut last = [0_u8; 1];
    file.read_exact(&mut last)?;
    file.seek(SeekFrom::End(-1))?;
    file.write_all(&[last[0] ^ 0x80])?;
    file.sync_all()?;
    drop(file);
    fs::set_permissions(&fixture.target, fs::Permissions::from_mode(0o440))?;

    let before = fs::read(&fixture.target)?;
    let before_identity = identity(&fixture.target)?;
    let before_entries = entries(&fixture.data_dir)?;
    let output = fixture.run("unwrap")?;

    assert_authentication_failure(&output);
    assert_eq!(identity(&fixture.target)?, before_identity);
    assert_eq!(mode(&fixture.target)?, 0o440);
    assert_eq!(fs::read(&fixture.target)?, before);
    assert_eq!(entries(&fixture.data_dir)?, before_entries);
    assert!(visible_temp_files(&fixture.data_dir)?.is_empty());
    Ok(())
}

#[test]
fn wrong_key_unwrap_preserves_exact_envelope_and_leaves_no_temp() -> io::Result<()> {
    let fixture = Fixture::new("wrong-key", b"authenticated ciphertext")?;
    assert_success(&fixture.run("seal")?);
    let before = fs::read(&fixture.target)?;
    let before_identity = identity(&fixture.target)?;
    let before_mode = mode(&fixture.target)?;
    let before_entries = entries(&fixture.data_dir)?;
    fs::write(&fixture.key, OTHER_AUTH_KEY)?;

    let output = fixture.run("unwrap")?;

    assert_authentication_failure(&output);
    assert_eq!(identity(&fixture.target)?, before_identity);
    assert_eq!(mode(&fixture.target)?, before_mode);
    assert_eq!(fs::read(&fixture.target)?, before);
    assert_eq!(fs::read(&fixture.key)?, OTHER_AUTH_KEY);
    assert_eq!(entries(&fixture.data_dir)?, before_entries);
    assert!(visible_temp_files(&fixture.data_dir)?.is_empty());
    Ok(())
}

#[test]
fn multiply_hardlinked_targets_are_rejected_for_both_mutating_operations() -> io::Result<()> {
    let raw = b"raw ciphertext with a second name";
    let fixture = Fixture::new("hardlinked-target", raw)?;
    let alias = fixture.data_dir.join("other-name.bin");
    fs::hard_link(&fixture.target, &alias)?;
    let original_identity = identity(&fixture.target)?;

    let seal_output = fixture.run("seal")?;
    assert_runtime_failure(&seal_output);
    assert_eq!(identity(&fixture.target)?, original_identity);
    assert_eq!(identity(&alias)?, original_identity);
    assert_eq!(fs::read(&fixture.target)?, raw);
    assert_eq!(fs::read(&alias)?, raw);
    assert!(visible_temp_files(&fixture.data_dir)?.is_empty());

    fs::remove_file(&alias)?;
    assert_success(&fixture.run("seal")?);
    let envelope = fs::read(&fixture.target)?;
    fs::hard_link(&fixture.target, &alias)?;
    let envelope_identity = identity(&fixture.target)?;

    let unwrap_output = fixture.run("unwrap")?;
    assert_runtime_failure(&unwrap_output);
    assert_eq!(identity(&fixture.target)?, envelope_identity);
    assert_eq!(identity(&alias)?, envelope_identity);
    assert_eq!(fs::read(&fixture.target)?, envelope);
    assert_eq!(fs::read(&alias)?, envelope);
    assert!(visible_temp_files(&fixture.data_dir)?.is_empty());
    Ok(())
}

#[test]
fn symbolic_link_targets_are_rejected_for_both_mutating_operations() -> io::Result<()> {
    let fixture = Fixture::new("symlink-target", b"raw target")?;
    let link = fixture.data_dir.join("link.bin");
    unix_fs::symlink(&fixture.target, &link)?;
    let raw_identity = identity(&fixture.target)?;

    let seal_output = fixture.run_path("seal", &link)?;
    assert_runtime_failure(&seal_output);
    assert!(fs::symlink_metadata(&link)?.file_type().is_symlink());
    assert_eq!(identity(&fixture.target)?, raw_identity);
    assert_eq!(fs::read(&fixture.target)?, b"raw target");

    assert_success(&fixture.run("seal")?);
    let envelope = fs::read(&fixture.target)?;
    let envelope_identity = identity(&fixture.target)?;
    let unwrap_output = fixture.run_path("unwrap", &link)?;
    assert_runtime_failure(&unwrap_output);
    assert!(fs::symlink_metadata(&link)?.file_type().is_symlink());
    assert_eq!(identity(&fixture.target)?, envelope_identity);
    assert_eq!(fs::read(&fixture.target)?, envelope);
    assert!(visible_temp_files(&fixture.data_dir)?.is_empty());
    Ok(())
}

#[test]
fn directory_fifo_and_socket_targets_are_rejected_without_blocking() -> io::Result<()> {
    let fixture = Fixture::new("nonregular-targets", b"neighbor must survive")?;
    let directory = fixture.data_dir.join("directory");
    let fifo = fixture.data_dir.join("fifo");
    let socket = fixture.data_dir.join("socket");
    fs::create_dir(&directory)?;
    create_fifo(&fifo)?;
    let listener = match UnixListener::bind(&socket) {
        Ok(listener) => Some(listener),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::PermissionDenied | io::ErrorKind::Unsupported
            ) =>
        {
            None
        }
        Err(error) => return Err(error),
    };
    let target_identity = identity(&fixture.target)?;

    let mut paths = vec![&directory, &fifo];
    if listener.is_some() {
        paths.push(&socket);
    }
    for path in paths {
        for operation in ["seal", "unwrap"] {
            let output = fixture
                .spawn_path(operation, path)?
                .wait_with_timeout(Duration::from_secs(3))?;
            assert_runtime_failure(&output);
        }
    }

    assert!(fs::metadata(&fifo)?.file_type().is_fifo());
    if listener.is_some() {
        assert!(fs::metadata(&socket)?.file_type().is_socket());
    }
    assert_eq!(identity(&fixture.target)?, target_identity);
    assert_eq!(fs::read(&fixture.target)?, b"neighbor must survive");
    assert!(visible_temp_files(&fixture.data_dir)?.is_empty());
    drop(listener);
    Ok(())
}

#[test]
fn symlink_hardlink_directory_and_fifo_auth_keys_are_rejected_safely() -> io::Result<()> {
    {
        let fixture = Fixture::new("symlink-key", b"target")?;
        let real_key = fixture.bin_dir.join("real-auth.key");
        fs::rename(&fixture.key, &real_key)?;
        unix_fs::symlink(&real_key, &fixture.key)?;
        let target_identity = identity(&fixture.target)?;
        let output = fixture.run("seal")?;
        assert_runtime_failure(&output);
        assert_eq!(identity(&fixture.target)?, target_identity);
        assert_eq!(fs::read(&fixture.target)?, b"target");
        assert_eq!(fs::read(&real_key)?, AUTH_KEY);
    }

    {
        let fixture = Fixture::new("hardlink-key", b"target")?;
        let key_alias = fixture.bin_dir.join("auth-key-alias");
        fs::hard_link(&fixture.key, &key_alias)?;
        let target_identity = identity(&fixture.target)?;
        let output = fixture.run("seal")?;
        assert_runtime_failure(&output);
        assert_eq!(identity(&fixture.target)?, target_identity);
        assert_eq!(fs::read(&fixture.target)?, b"target");
        assert_eq!(fs::read(&fixture.key)?, AUTH_KEY);
        assert_eq!(fs::read(&key_alias)?, AUTH_KEY);
    }

    {
        let fixture = Fixture::new("directory-key", b"target")?;
        fs::remove_file(&fixture.key)?;
        fs::create_dir(&fixture.key)?;
        let target_identity = identity(&fixture.target)?;
        let output = fixture.run("seal")?;
        assert_runtime_failure(&output);
        assert_eq!(identity(&fixture.target)?, target_identity);
        assert_eq!(fs::read(&fixture.target)?, b"target");
    }

    {
        let fixture = Fixture::new("fifo-key", b"target")?;
        fs::remove_file(&fixture.key)?;
        create_fifo(&fixture.key)?;
        let target_identity = identity(&fixture.target)?;
        let output = fixture
            .spawn("seal")?
            .wait_with_timeout(Duration::from_secs(3))?;
        assert_runtime_failure(&output);
        assert_eq!(identity(&fixture.target)?, target_identity);
        assert_eq!(fs::read(&fixture.target)?, b"target");
    }
    Ok(())
}

#[derive(Default)]
struct ObserverReport {
    old: usize,
    new: usize,
}

fn observe_atomic_transition(
    fixture: &Fixture,
    operation: &'static str,
    old: Vec<u8>,
    new: Vec<u8>,
) -> io::Result<ObserverReport> {
    let path = fixture.target.clone();
    let old = Arc::new(old);
    let new = Arc::new(new);
    let running = Arc::new(AtomicBool::new(true));
    let (ready_sender, ready_receiver) = mpsc::channel();
    let observer_running = Arc::clone(&running);
    let observer_old = Arc::clone(&old);
    let observer_new = Arc::clone(&new);
    let observer = thread::spawn(move || -> io::Result<ObserverReport> {
        let mut report = ObserverReport::default();
        let mut first = true;
        while observer_running.load(Ordering::Acquire) {
            let bytes = fs::read(&path)?;
            if bytes == *observer_old {
                report.old += 1;
            } else if bytes == *observer_new {
                report.new += 1;
            } else {
                return Err(io::Error::other(format!(
                    "observer saw a partial or mixed file of {} bytes",
                    bytes.len()
                )));
            }
            if first {
                ready_sender
                    .send(())
                    .map_err(|_| io::Error::other("observer readiness receiver disappeared"))?;
                first = false;
            }
            thread::yield_now();
        }
        Ok(report)
    });

    ready_receiver
        .recv_timeout(Duration::from_secs(3))
        .map_err(|_| io::Error::other("observer did not become ready"))?;
    let output = fixture.run(operation)?;
    running.store(false, Ordering::Release);
    assert_success(&output);
    let mut report = observer
        .join()
        .map_err(|_| io::Error::other("observer thread panicked"))??;
    let final_bytes = fs::read(&fixture.target)?;
    if final_bytes == *old {
        report.old += 1;
    } else if final_bytes == *new {
        report.new += 1;
    } else {
        return Err(io::Error::other("final file was neither old nor new"));
    }
    Ok(report)
}

#[test]
fn observers_see_only_complete_old_or_new_files_during_seal_and_unwrap() -> io::Result<()> {
    let raw = pseudo_random_bytes(4 * 1024 * 1024 + 29, 0xc819_723f);
    let fixture = Fixture::new("observer", &raw)?;

    assert_success(&fixture.run("seal")?);
    let envelope = fs::read(&fixture.target)?;
    assert_success(&fixture.run("unwrap")?);
    assert_eq!(fs::read(&fixture.target)?, raw);

    let seal_report = observe_atomic_transition(&fixture, "seal", raw.clone(), envelope.clone())?;
    assert!(seal_report.old > 0);
    assert!(seal_report.new > 0);
    let unwrap_report = observe_atomic_transition(&fixture, "unwrap", envelope, raw)?;
    assert!(unwrap_report.old > 0);
    assert!(unwrap_report.new > 0);
    assert!(visible_temp_files(&fixture.data_dir)?.is_empty());
    Ok(())
}

#[cfg(target_os = "linux")]
fn signal_child(child: &Child, signal: i32) -> io::Result<()> {
    unsafe extern "C" {
        fn kill(process: i32, signal: i32) -> i32;
    }
    // SAFETY: the PID belongs to the managed child, and `signal` is one of the
    // standard signal constants supplied by the callers below.
    if unsafe { kill(child.id() as i32, signal) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
fn stop_child(child: &mut ManagedChild) -> io::Result<()> {
    const SIGSTOP: i32 = 19;
    const WUNTRACED: i32 = 2;
    unsafe extern "C" {
        fn waitpid(process: i32, status: *mut i32, options: i32) -> i32;
    }

    signal_child(child.child(), SIGSTOP)?;
    let mut status = 0_i32;
    // SAFETY: the child PID is live, `status` is writable, and WUNTRACED makes
    // waitpid return after SIGSTOP takes effect without reaping the process.
    let waited = unsafe { waitpid(child.child().id() as i32, &mut status, WUNTRACED) };
    if waited < 0 {
        return Err(io::Error::last_os_error());
    }
    if waited != child.child().id() as i32 || status & 0xff != 0x7f {
        Err(io::Error::other(
            "otp1-auth exited before the stop signal took effect",
        ))
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn continue_child(child: &ManagedChild) -> io::Result<()> {
    const SIGCONT: i32 = 18;
    signal_child(child.child(), SIGCONT)
}

#[cfg(target_os = "linux")]
fn wait_for_temp(child: &mut ManagedChild, directory: &Path) -> io::Result<PathBuf> {
    let started = Instant::now();
    loop {
        if let Some(path) = visible_temp_files(directory)?.into_iter().next() {
            return Ok(path);
        }
        if let Some(status) = child.child_mut().try_wait()? {
            return Err(io::Error::other(format!(
                "otp1-auth exited with {status} before a temp became visible"
            )));
        }
        if started.elapsed() >= Duration::from_secs(5) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "otp1-auth did not expose a temp before the timeout",
            ));
        }
        thread::yield_now();
    }
}

#[cfg(target_os = "linux")]
#[test]
fn replacing_target_path_during_seal_aborts_and_preserves_replacement() -> io::Result<()> {
    const LARGE_FILE: usize = 32 * 1024 * 1024;
    let _serial = BARRIER_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let fixture = Fixture::new("replace-during-seal", b"")?;
    write_repeated(&fixture.target, 0x51, LARGE_FILE)?;
    let key_before = fs::read(&fixture.key)?;
    let mut child = fixture.spawn("seal")?;
    let _temp = wait_for_temp(&mut child, &fixture.data_dir)?;
    stop_child(&mut child)?;

    let replacement = fixture.data_dir.join("external-replacement");
    let replacement_bytes = b"external writer owns this path";
    fs::write(&replacement, replacement_bytes)?;
    let replacement_identity = identity(&replacement)?;
    fs::rename(&replacement, &fixture.target)?;

    continue_child(&child)?;
    let output = child.wait_with_timeout(Duration::from_secs(10))?;
    assert_runtime_failure(&output);
    assert_eq!(identity(&fixture.target)?, replacement_identity);
    assert_eq!(fs::read(&fixture.target)?, replacement_bytes);
    assert_eq!(fs::read(&fixture.key)?, key_before);
    assert!(visible_temp_files(&fixture.data_dir)?.is_empty());
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn in_place_target_mutation_during_seal_aborts_without_losing_changes() -> io::Result<()> {
    const LARGE_FILE: usize = 32 * 1024 * 1024;
    const OVERWRITE: &[u8] = b"external same-inode overwrite";
    const APPEND: &[u8] = b"external same-inode append";
    let _serial = BARRIER_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let fixture = Fixture::new("mutate-inode-during-seal", b"")?;
    write_repeated(&fixture.target, 0x68, LARGE_FILE)?;
    let target_identity = identity(&fixture.target)?;
    let key_before = fs::read(&fixture.key)?;
    let mut child = fixture.spawn("seal")?;
    let _temp = wait_for_temp(&mut child, &fixture.data_dir)?;
    stop_child(&mut child)?;

    let mut target = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&fixture.target)?;
    target.seek(SeekFrom::Start(0))?;
    target.write_all(OVERWRITE)?;
    target.seek(SeekFrom::End(0))?;
    target.write_all(APPEND)?;
    target.sync_all()?;
    drop(target);

    continue_child(&child)?;
    let output = child.wait_with_timeout(Duration::from_secs(10))?;
    assert_runtime_failure(&output);
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("changed while"),
        "failure did not report the concurrent mutation: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(identity(&fixture.target)?, target_identity);
    assert_eq!(
        fs::metadata(&fixture.target)?.len(),
        (LARGE_FILE + APPEND.len()) as u64
    );
    let mut target = File::open(&fixture.target)?;
    let mut overwritten = vec![0_u8; OVERWRITE.len()];
    target.read_exact(&mut overwritten)?;
    assert_eq!(overwritten, OVERWRITE);
    target.seek(SeekFrom::End(-(APPEND.len() as i64)))?;
    let mut appended = vec![0_u8; APPEND.len()];
    target.read_exact(&mut appended)?;
    assert_eq!(appended, APPEND);
    assert_eq!(fs::read(&fixture.key)?, key_before);
    assert!(visible_temp_files(&fixture.data_dir)?.is_empty());
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn rotating_auth_key_during_unwrap_aborts_and_preserves_envelope() -> io::Result<()> {
    const LARGE_FILE: usize = 32 * 1024 * 1024;
    let _serial = BARRIER_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let fixture = Fixture::new("rotate-key-during-unwrap", b"")?;
    write_repeated(&fixture.target, 0x26, LARGE_FILE)?;
    assert_success(&fixture.run("seal")?);
    let envelope_identity = identity(&fixture.target)?;
    let envelope_size = fs::metadata(&fixture.target)?.len();
    let mut child = fixture.spawn("unwrap")?;
    let _temp = wait_for_temp(&mut child, &fixture.data_dir)?;
    stop_child(&mut child)?;

    let old_key = fixture.bin_dir.join("old-auth.key");
    fs::rename(&fixture.key, &old_key)?;
    fs::write(&fixture.key, OTHER_AUTH_KEY)?;
    fs::set_permissions(&fixture.key, fs::Permissions::from_mode(0o600))?;
    let replacement_key_identity = identity(&fixture.key)?;

    continue_child(&child)?;
    let output = child.wait_with_timeout(Duration::from_secs(10))?;
    assert_runtime_failure(&output);
    assert_eq!(identity(&fixture.target)?, envelope_identity);
    assert_eq!(fs::metadata(&fixture.target)?.len(), envelope_size);
    assert_eq!(fs::read(&old_key)?, AUTH_KEY);
    assert_eq!(identity(&fixture.key)?, replacement_key_identity);
    assert_eq!(fs::read(&fixture.key)?, OTHER_AUTH_KEY);
    assert!(visible_temp_files(&fixture.data_dir)?.is_empty());
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn overwriting_open_auth_key_during_unwrap_preserves_envelope_and_mutated_key() -> io::Result<()> {
    const LARGE_FILE: usize = 32 * 1024 * 1024;
    let _serial = BARRIER_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let fixture = Fixture::new("mutate-key-inode-during-unwrap", b"")?;
    write_repeated(&fixture.target, 0x2d, LARGE_FILE)?;
    assert_success(&fixture.run("seal")?);
    let envelope = fs::read(&fixture.target)?;
    let envelope_identity = identity(&fixture.target)?;
    let key_identity = identity(&fixture.key)?;
    let mut child = fixture.spawn("unwrap")?;
    let _temp = wait_for_temp(&mut child, &fixture.data_dir)?;
    stop_child(&mut child)?;

    let mut key = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&fixture.key)?;
    key.seek(SeekFrom::Start(0))?;
    key.write_all(&OTHER_AUTH_KEY)?;
    key.write_all(&[0xef])?;
    key.set_len(AUTH_KEY.len() as u64)?;
    key.sync_all()?;
    drop(key);

    continue_child(&child)?;
    let output = child.wait_with_timeout(Duration::from_secs(10))?;
    assert_runtime_failure(&output);
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("changed while"),
        "failure did not report the concurrent key mutation: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(identity(&fixture.target)?, envelope_identity);
    assert_eq!(fs::read(&fixture.target)?, envelope);
    assert_eq!(identity(&fixture.key)?, key_identity);
    assert_eq!(fs::read(&fixture.key)?, OTHER_AUTH_KEY);
    assert!(visible_temp_files(&fixture.data_dir)?.is_empty());
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn substituting_visible_temp_cannot_commit_or_delete_the_substitute() -> io::Result<()> {
    const LARGE_FILE: usize = 32 * 1024 * 1024;
    let _serial = BARRIER_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let fixture = Fixture::new("substitute-temp", b"")?;
    write_repeated(&fixture.target, 0xb3, LARGE_FILE)?;
    let target_identity = identity(&fixture.target)?;
    let mut child = fixture.spawn("seal")?;
    let temp = wait_for_temp(&mut child, &fixture.data_dir)?;
    stop_child(&mut child)?;
    assert_eq!(mode(&temp)?, 0o600);

    let displaced = fixture.data_dir.join("displaced-real-temp");
    fs::rename(&temp, &displaced)?;
    let substitute_bytes = b"external temp-path substitute";
    fs::write(&temp, substitute_bytes)?;
    let substitute_identity = identity(&temp)?;

    continue_child(&child)?;
    let output = child.wait_with_timeout(Duration::from_secs(10))?;
    assert_runtime_failure(&output);
    assert_eq!(identity(&fixture.target)?, target_identity);
    assert_eq!(fs::metadata(&fixture.target)?.len(), LARGE_FILE as u64);
    assert_eq!(identity(&temp)?, substitute_identity);
    assert_eq!(fs::read(&temp)?, substitute_bytes);
    assert!(
        displaced.exists(),
        "the displaced real temp should not be lost"
    );
    Ok(())
}
