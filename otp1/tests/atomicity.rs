#![cfg(unix)]

use std::collections::BTreeSet;
use std::env;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{self as unix_fs, FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

static NEXT_TEST_DIRECTORY: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_os = "linux")]
static BARRIER_TEST_LOCK: Mutex<()> = Mutex::new(());

struct ScratchDirectory {
    path: PathBuf,
}

impl ScratchDirectory {
    fn new(label: &str) -> io::Result<Self> {
        let base = env::temp_dir();

        for _ in 0..1_000 {
            let sequence = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let candidate = base.join(format!(
                "otp1-atomicity-{label}-{}-{sequence}",
                std::process::id()
            ));

            match fs::create_dir(&candidate) {
                Ok(()) => return Ok(Self { path: candidate }),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }

        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique atomicity-test directory",
        ))
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for ScratchDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct Fixture {
    directory: ScratchDirectory,
    executable: PathBuf,
    working_directory: PathBuf,
    input: PathBuf,
    key: PathBuf,
}

impl Fixture {
    fn new(label: &str, input: &[u8], key: Option<&[u8]>) -> io::Result<Self> {
        let directory = ScratchDirectory::new(label)?;
        let executable = directory.path().join("otp1-under-test");
        let working_directory = directory.path().join("unrelated-working-directory");
        let input_path = directory.path().join("data.bin");
        let key_path = directory.path().join("key.key");

        fs::copy(env!("CARGO_BIN_EXE_otp1"), &executable)?;
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))?;
        fs::create_dir(&working_directory)?;
        fs::write(&input_path, input)?;
        if let Some(key_bytes) = key {
            fs::write(&key_path, key_bytes)?;
        }

        Ok(Self {
            directory,
            executable,
            working_directory,
            input: input_path,
            key: key_path,
        })
    }

    fn run(&self) -> io::Result<Output> {
        for attempt in 0..100 {
            match Command::new(&self.executable)
                .arg(&self.input)
                .current_dir(&self.working_directory)
                .output()
            {
                Ok(output) => return Ok(output),
                Err(error)
                    if error.kind() == io::ErrorKind::ExecutableFileBusy && attempt != 99 =>
                {
                    // Some overlay filesystems briefly report ETXTBSY when
                    // several freshly copied test executables start in parallel.
                    thread::yield_now();
                }
                Err(error) => return Err(error),
            }
        }
        unreachable!("the final launch attempt always returns or errors")
    }

    fn spawn(&self) -> io::Result<Child> {
        for attempt in 0..100 {
            match Command::new(&self.executable)
                .arg(&self.input)
                .current_dir(&self.working_directory)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
            {
                Ok(child) => return Ok(child),
                Err(error)
                    if error.kind() == io::ErrorKind::ExecutableFileBusy && attempt != 99 =>
                {
                    thread::yield_now();
                }
                Err(error) => return Err(error),
            }
        }
        unreachable!("the final launch attempt always returns or errors")
    }
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "otp1 unexpectedly failed ({:?})\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_failure(output: &Output) {
    assert!(
        !output.status.success(),
        "otp1 unexpectedly succeeded\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_concurrent_change_failure(output: &Output) {
    assert_eq!(
        output.status.code(),
        Some(1),
        "concurrent change did not produce a runtime-error exit\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("changed while") || stderr.contains("temporary output path changed"),
        "failure did not identify a concurrent change: {stderr}"
    );
}

fn xor(input: &[u8], key: &[u8]) -> Vec<u8> {
    input
        .iter()
        .zip(key)
        .map(|(&input_byte, &key_byte)| input_byte ^ key_byte)
        .collect()
}

fn directory_entries(path: &Path) -> io::Result<BTreeSet<OsString>> {
    fs::read_dir(path)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect()
}

fn file_identity(path: &Path) -> io::Result<(u64, u64)> {
    let metadata = fs::metadata(path)?;
    Ok((metadata.dev(), metadata.ino()))
}

fn wait_for_exit(mut child: Child, timeout: Duration) -> io::Result<Output> {
    let started = Instant::now();
    loop {
        if child.try_wait()?.is_some() {
            return child.wait_with_output();
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "otp1 did not exit before the test timeout",
            ));
        }
        thread::yield_now();
    }
}

fn visible_otp_temp(directory: &Path) -> io::Result<Option<PathBuf>> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(".otp1-") && name.ends_with(".tmp") {
            return Ok(Some(entry.path()));
        }
    }
    Ok(None)
}

fn wait_for_otp_temp(child: &mut Child, directory: &Path) -> io::Result<PathBuf> {
    let started = Instant::now();
    loop {
        if let Some(path) = visible_otp_temp(directory)? {
            return Ok(path);
        }
        if let Some(status) = child.try_wait()? {
            return Err(io::Error::other(format!(
                "otp1 exited with {status} before creating its temporary output"
            )));
        }
        if started.elapsed() >= Duration::from_secs(5) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "otp1 did not expose its temporary output before the timeout",
            ));
        }
        thread::yield_now();
    }
}

#[cfg(target_os = "linux")]
fn signal_child(child: &Child, signal: i32) -> io::Result<()> {
    unsafe extern "C" {
        fn kill(process: i32, signal: i32) -> i32;
    }

    // SAFETY: `kill` is called with the live child's numeric PID and a standard
    // signal constant. It does not access Rust memory.
    if unsafe { kill(child.id() as i32, signal) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
fn stop_child(child: &mut Child) -> io::Result<()> {
    const SIGSTOP: i32 = 19;
    const WUNTRACED: i32 = 2;

    unsafe extern "C" {
        fn waitpid(process: i32, status: *mut i32, options: i32) -> i32;
    }

    signal_child(child, SIGSTOP)?;
    let mut status = 0_i32;
    // SAFETY: the PID names this live child, `status` is writable, and
    // WUNTRACED asks waitpid to return once SIGSTOP has actually taken effect.
    let waited = unsafe { waitpid(child.id() as i32, &mut status, WUNTRACED) };
    if waited < 0 {
        return Err(io::Error::last_os_error());
    }
    if waited != child.id() as i32 || status & 0xff != 0x7f {
        Err(io::Error::other(
            "otp1 exited before the stop signal took effect",
        ))
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn continue_child(child: &Child) -> io::Result<()> {
    const SIGCONT: i32 = 18;
    signal_child(child, SIGCONT)
}

fn assert_file_is_byte(path: &Path, expected: u8, expected_length: usize) -> io::Result<()> {
    let mut reader = BufReader::new(File::open(path)?);
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_usize;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        assert!(
            buffer[..read].iter().all(|byte| *byte == expected),
            "{path:?} contains a byte other than 0x{expected:02x}"
        );
        total += read;
    }
    assert_eq!(total, expected_length, "unexpected length for {path:?}");
    Ok(())
}

fn create_fifo(path: &Path) -> io::Result<()> {
    let status = Command::new("mkfifo").arg(path).status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!("mkfifo failed with {status}")))
    }
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

fn create_sparse_file(path: &Path, length: u64) -> io::Result<()> {
    let file = OpenOptions::new().write(true).truncate(true).open(path)?;
    file.set_len(length)?;
    file.sync_all()
}

fn mutate_file_in_place(
    path: &Path,
    overwrite_offset: u64,
    overwrite: &[u8],
    suffix: &[u8],
) -> io::Result<()> {
    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    file.seek(SeekFrom::Start(overwrite_offset))?;
    file.write_all(overwrite)?;
    file.seek(SeekFrom::End(0))?;
    file.write_all(suffix)?;
    file.sync_all()
}

fn assert_bytes_at(path: &Path, offset: u64, expected: &[u8]) -> io::Result<()> {
    let mut file = File::open(path)?;
    file.seek(SeekFrom::Start(offset))?;
    let mut actual = vec![0_u8; expected.len()];
    file.read_exact(&mut actual)?;
    assert_eq!(actual, expected, "unexpected bytes in {path:?} at {offset}");
    Ok(())
}

#[test]
fn atomic_replace_leaves_an_already_open_descriptor_on_the_old_inode() -> io::Result<()> {
    let plaintext: Vec<u8> = (0..256_u16)
        .cycle()
        .take(256 * 1024)
        .map(|value| value as u8)
        .collect();
    let key: Vec<u8> = (0..plaintext.len())
        .map(|index| (index as u8).wrapping_mul(73).wrapping_add(19))
        .collect();
    let expected = xor(&plaintext, &key);
    let fixture = Fixture::new("held-fd", &plaintext, Some(&key))?;

    let mut held_open = File::open(&fixture.input)?;
    let old_metadata = held_open.metadata()?;
    assert_eq!(
        old_metadata.nlink(),
        1,
        "test input unexpectedly hardlinked"
    );

    let output = fixture.run()?;
    assert_success(&output);

    let replacement_metadata = fs::metadata(&fixture.input)?;
    assert_ne!(
        (old_metadata.dev(), old_metadata.ino()),
        (replacement_metadata.dev(), replacement_metadata.ino()),
        "the path still names the original inode; content was rewritten in place"
    );
    assert_eq!(fs::read(&fixture.input)?, expected);

    held_open.seek(SeekFrom::Start(0))?;
    let mut bytes_from_old_descriptor = Vec::new();
    held_open.read_to_end(&mut bytes_from_old_descriptor)?;
    assert_eq!(bytes_from_old_descriptor, plaintext);
    assert_eq!(held_open.metadata()?.ino(), old_metadata.ino());
    assert_eq!(
        held_open.metadata()?.nlink(),
        0,
        "the replaced inode should no longer have a directory entry"
    );

    Ok(())
}

#[test]
fn atomic_replace_preserves_a_read_only_unix_mode() -> io::Result<()> {
    let plaintext = b"permissions must survive an inode replacement";
    let key = vec![0x9d; plaintext.len() + 32];
    let expected = xor(plaintext, &key);
    let fixture = Fixture::new("mode", plaintext, Some(&key))?;
    let original_mode = 0o554;
    fs::set_permissions(&fixture.input, fs::Permissions::from_mode(original_mode))?;

    let output = fixture.run()?;
    assert_success(&output);

    assert_eq!(fs::read(&fixture.input)?, expected);
    assert_eq!(
        fs::metadata(&fixture.input)?.permissions().mode() & 0o7777,
        original_mode,
        "replacement changed the input's Unix mode"
    );

    Ok(())
}

#[test]
fn short_key_fails_without_replacing_input_or_leaving_a_temp_file() -> io::Result<()> {
    let plaintext: Vec<u8> = (0..8_193)
        .map(|index| (index as u8).wrapping_mul(31))
        .collect();
    let key = vec![0x42; plaintext.len() - 1];
    let fixture = Fixture::new("short-key", &plaintext, Some(&key))?;
    fs::set_permissions(&fixture.input, fs::Permissions::from_mode(0o540))?;
    let original_identity = file_identity(&fixture.input)?;
    let entries_before = directory_entries(fixture.directory.path())?;

    let output = fixture.run()?;
    assert_failure(&output);

    assert_eq!(fs::read(&fixture.input)?, plaintext);
    assert_eq!(file_identity(&fixture.input)?, original_identity);
    assert_eq!(
        fs::metadata(&fixture.input)?.permissions().mode() & 0o7777,
        0o540
    );
    assert_eq!(
        directory_entries(fixture.directory.path())?,
        entries_before,
        "short-key validation left a sibling temporary artifact"
    );

    Ok(())
}

#[test]
fn huge_sparse_input_with_tiny_key_is_rejected_before_output_creation() -> io::Result<()> {
    const INPUT_LENGTH: u64 = (4_u64 * 1024 * 1024 * 1024) + 17;
    const TIMEOUT: Duration = Duration::from_secs(3);

    let key = b"tiny key";
    let fixture = Fixture::new("huge-sparse-short-key", &[], Some(key))?;
    create_sparse_file(&fixture.input, INPUT_LENGTH)?;
    let original_metadata = fs::metadata(&fixture.input)?;
    let original_identity = file_identity(&fixture.input)?;
    let original_entries = directory_entries(fixture.directory.path())?;
    assert_eq!(original_metadata.len(), INPUT_LENGTH);
    assert_bytes_at(&fixture.input, INPUT_LENGTH - 1, &[0])?;

    let started = Instant::now();
    let output = wait_for_exit(fixture.spawn()?, TIMEOUT)?;
    let elapsed = started.elapsed();

    assert_eq!(
        output.status.code(),
        Some(1),
        "short-key preflight did not produce a runtime-error exit"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("key is too short"),
        "failure was not the key-length preflight: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        elapsed < TIMEOUT,
        "short-key preflight took unexpectedly long: {elapsed:?}"
    );
    let final_metadata = fs::metadata(&fixture.input)?;
    assert_eq!(file_identity(&fixture.input)?, original_identity);
    assert_eq!(final_metadata.len(), INPUT_LENGTH);
    assert_eq!(
        final_metadata.blocks(),
        original_metadata.blocks(),
        "short-key handling allocated or rewrote sparse input data"
    );
    assert_bytes_at(&fixture.input, INPUT_LENGTH - 1, &[0])?;
    assert_eq!(fs::read(&fixture.key)?, key);
    assert_eq!(
        directory_entries(fixture.directory.path())?,
        original_entries,
        "short-key preflight created a sibling output artifact"
    );
    assert!(visible_otp_temp(fixture.directory.path())?.is_none());

    Ok(())
}

#[test]
fn missing_key_fails_without_replacing_input_or_leaving_a_temp_file() -> io::Result<()> {
    let plaintext = b"this input must remain byte-for-byte intact";
    let fixture = Fixture::new("missing-key", plaintext, None)?;
    let original_identity = file_identity(&fixture.input)?;
    let entries_before = directory_entries(fixture.directory.path())?;

    let output = fixture.run()?;
    assert_failure(&output);

    assert_eq!(fs::read(&fixture.input)?, plaintext);
    assert_eq!(file_identity(&fixture.input)?, original_identity);
    assert_eq!(
        directory_entries(fixture.directory.path())?,
        entries_before,
        "missing-key handling left a sibling temporary artifact"
    );

    Ok(())
}

#[test]
fn hardlinked_input_is_rejected_without_changing_either_name() -> io::Result<()> {
    let plaintext = b"hard links would retain a plaintext inode";
    let key = vec![0xa7; plaintext.len()];
    let fixture = Fixture::new("hardlink", plaintext, Some(&key))?;
    let alias = fixture.directory.path().join("alias.bin");
    fs::hard_link(&fixture.input, &alias)?;
    let original_identity = file_identity(&fixture.input)?;
    assert_eq!(file_identity(&alias)?, original_identity);
    assert_eq!(fs::metadata(&fixture.input)?.nlink(), 2);
    let entries_before = directory_entries(fixture.directory.path())?;

    let output = fixture.run()?;
    assert_failure(&output);

    assert_eq!(fs::read(&fixture.input)?, plaintext);
    assert_eq!(fs::read(&alias)?, plaintext);
    assert_eq!(file_identity(&fixture.input)?, original_identity);
    assert_eq!(file_identity(&alias)?, original_identity);
    assert_eq!(
        directory_entries(fixture.directory.path())?,
        entries_before,
        "hardlink rejection left a sibling temporary artifact"
    );

    Ok(())
}

#[test]
fn symlink_input_is_rejected_without_touching_its_target() -> io::Result<()> {
    let plaintext = b"the symlink target must stay plaintext and untouched";
    let key = vec![0xd3; plaintext.len() + 8];
    let fixture = Fixture::new("input-symlink", plaintext, Some(&key))?;
    let target = fixture.directory.path().join("real-input.bin");
    fs::rename(&fixture.input, &target)?;
    unix_fs::symlink(&target, &fixture.input)?;
    let target_identity = file_identity(&target)?;
    let entries_before = directory_entries(fixture.directory.path())?;

    let output = fixture.run()?;
    assert_failure(&output);

    assert!(
        fs::symlink_metadata(&fixture.input)?
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read_link(&fixture.input)?, target);
    assert_eq!(fs::read(&target)?, plaintext);
    assert_eq!(file_identity(&target)?, target_identity);
    assert_eq!(
        directory_entries(fixture.directory.path())?,
        entries_before,
        "symlink rejection left a sibling temporary artifact"
    );

    Ok(())
}

#[test]
fn symlink_key_is_rejected_without_touching_input_or_key_target() -> io::Result<()> {
    let plaintext = b"key path policy must fail closed";
    let key_bytes = vec![0x6e; plaintext.len() + 16];
    let fixture = Fixture::new("key-symlink", plaintext, None)?;
    let real_key = fixture.directory.path().join("real-key.bin");
    fs::write(&real_key, &key_bytes)?;
    unix_fs::symlink(&real_key, &fixture.key)?;
    let original_identity = file_identity(&fixture.input)?;
    let entries_before = directory_entries(fixture.directory.path())?;

    let output = fixture.run()?;
    assert_failure(&output);

    assert_eq!(fs::read(&fixture.input)?, plaintext);
    assert_eq!(file_identity(&fixture.input)?, original_identity);
    assert!(fs::symlink_metadata(&fixture.key)?.file_type().is_symlink());
    assert_eq!(fs::read_link(&fixture.key)?, real_key);
    assert_eq!(fs::read(&real_key)?, key_bytes);
    assert_eq!(
        directory_entries(fixture.directory.path())?,
        entries_before,
        "key-symlink rejection left a sibling temporary artifact"
    );

    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Snapshot {
    Old,
    New,
}

fn classify_snapshot(
    path: &Path,
    expected_length: usize,
    old_byte: u8,
    new_byte: u8,
) -> Result<Snapshot, String> {
    let file = File::open(path).map_err(|error| format!("open failed: {error}"))?;
    let length = file
        .metadata()
        .map_err(|error| format!("metadata failed: {error}"))?
        .len();
    if length != expected_length as u64 {
        return Err(format!(
            "observer saw length {length}, expected {expected_length}"
        ));
    }

    let mut reader = BufReader::with_capacity(128 * 1024, file);
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_usize;
    let mut classification = None;

    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|error| format!("read failed: {error}"))?;
        if read == 0 {
            break;
        }
        total += read;

        for &byte in &buffer[..read] {
            let byte_classification = if byte == old_byte {
                Snapshot::Old
            } else if byte == new_byte {
                Snapshot::New
            } else {
                return Err(format!("observer saw unexpected byte 0x{byte:02x}"));
            };

            if let Some(previous) = classification {
                if previous != byte_classification {
                    return Err("observer saw a mixture of old and new bytes".to_owned());
                }
            } else {
                classification = Some(byte_classification);
            }
        }
    }

    if total != expected_length {
        return Err(format!(
            "observer read {total} bytes, expected {expected_length}"
        ));
    }

    classification.ok_or_else(|| "observer was given an empty test file".to_owned())
}

#[derive(Debug)]
struct ObserverReport {
    observations: usize,
    saw_old: bool,
    saw_new: bool,
}

#[test]
fn repeated_opening_observer_sees_only_complete_old_or_new_files() -> io::Result<()> {
    const FILE_SIZE: usize = 16 * 1024 * 1024;
    const OLD_BYTE: u8 = 0x35;
    const KEY_BYTE: u8 = 0xa6;
    const NEW_BYTE: u8 = OLD_BYTE ^ KEY_BYTE;

    let plaintext = vec![OLD_BYTE; FILE_SIZE];
    let key = vec![KEY_BYTE; FILE_SIZE + 4_096];
    let fixture = Fixture::new("observer", &plaintext, Some(&key))?;
    let observed_path = fixture.input.clone();
    let stop = Arc::new(AtomicBool::new(false));
    let observer_stop = Arc::clone(&stop);
    let (ready_sender, ready_receiver) = mpsc::sync_channel::<Result<(), String>>(1);

    let observer = thread::spawn(move || -> Result<ObserverReport, String> {
        let mut report = ObserverReport {
            observations: 0,
            saw_old: false,
            saw_new: false,
        };
        let mut observations_after_stop = 0;

        loop {
            let snapshot = match classify_snapshot(&observed_path, FILE_SIZE, OLD_BYTE, NEW_BYTE) {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    if report.observations == 0 {
                        let _ = ready_sender.send(Err(error.clone()));
                    }
                    return Err(error);
                }
            };

            report.observations += 1;
            match snapshot {
                Snapshot::Old => {
                    if report.saw_new {
                        return Err("observer saw old content after seeing new content".to_owned());
                    }
                    report.saw_old = true;
                }
                Snapshot::New => report.saw_new = true,
            }

            if report.observations == 1 {
                if snapshot != Snapshot::Old {
                    let error = "input was not old before otp1 started".to_owned();
                    let _ = ready_sender.send(Err(error.clone()));
                    return Err(error);
                }
                ready_sender
                    .send(Ok(()))
                    .map_err(|_| "test stopped before observer became ready".to_owned())?;
            }

            if observer_stop.load(Ordering::Acquire) {
                observations_after_stop += 1;
                if report.saw_new || observations_after_stop >= 3 {
                    break;
                }
            }
        }

        Ok(report)
    });

    match ready_receiver.recv_timeout(Duration::from_secs(5)) {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            stop.store(true, Ordering::Release);
            let _ = observer.join();
            panic!("observer could not start: {error}");
        }
        Err(error) => {
            stop.store(true, Ordering::Release);
            let _ = observer.join();
            panic!("observer did not become ready: {error}");
        }
    }

    let output_result = fixture.run();
    stop.store(true, Ordering::Release);
    let report = observer
        .join()
        .map_err(|_| io::Error::other("observer thread panicked"))?
        .map_err(io::Error::other)?;
    let output = output_result?;
    assert_success(&output);

    assert!(report.saw_old, "observer never saw the original inode");
    assert!(report.saw_new, "observer never saw the replacement inode");
    assert!(
        report.observations >= 2,
        "observer made too few observations: {report:?}"
    );
    assert_eq!(fs::read(&fixture.input)?, vec![NEW_BYTE; FILE_SIZE]);

    Ok(())
}

#[test]
fn guessed_temp_name_files_and_symlinks_are_never_overwritten() -> io::Result<()> {
    let plaintext = b"temporary-name collisions must fail safely or be retried";
    let key = vec![0xc7; plaintext.len() + 64];
    let expected = xor(plaintext, &key);
    let fixture = Fixture::new("temp-collisions", plaintext, Some(&key))?;

    let victim = fixture.directory.path().join("temp-symlink-victim.bin");
    let victim_bytes = b"do not follow a guessed temporary-file symlink";
    fs::write(&victim, victim_bytes)?;
    let symlink_candidate = fixture.directory.path().join(".otp1.tmp");
    unix_fs::symlink(&victim, &symlink_candidate)?;

    let regular_candidates = [
        ".data.bin.otp1.tmp",
        "data.bin.otp1.tmp",
        ".otp1-data.bin.tmp",
        ".data.bin.tmp",
        "data.bin.tmp",
    ];
    let sentinel = b"pre-existing guessed temporary path";
    for candidate in regular_candidates {
        fs::write(fixture.directory.path().join(candidate), sentinel)?;
    }
    let entries_before = directory_entries(fixture.directory.path())?;

    let output = fixture.run()?;

    assert!(
        fs::symlink_metadata(&symlink_candidate)?
            .file_type()
            .is_symlink(),
        "a pre-existing temporary-name symlink was replaced"
    );
    assert_eq!(fs::read_link(&symlink_candidate)?, victim);
    assert_eq!(fs::read(&victim)?, victim_bytes);
    for candidate in regular_candidates {
        assert_eq!(
            fs::read(fixture.directory.path().join(candidate))?,
            sentinel,
            "pre-existing guessed temp file {candidate:?} was modified"
        );
    }
    assert_eq!(
        directory_entries(fixture.directory.path())?,
        entries_before,
        "the run created or removed an entry besides atomically replacing the input"
    );

    if output.status.success() {
        assert_eq!(fs::read(&fixture.input)?, expected);
    } else {
        assert_eq!(
            fs::read(&fixture.input)?,
            plaintext,
            "a temp-name collision failure partially changed the input"
        );
    }

    Ok(())
}

#[test]
fn fifo_input_is_rejected_without_blocking_or_creating_output() -> io::Result<()> {
    let fixture = Fixture::new("fifo-input", b"placeholder", Some(b"a long enough key"))?;
    fs::remove_file(&fixture.input)?;
    create_fifo(&fixture.input)?;
    let entries = directory_entries(fixture.directory.path())?;

    let output = wait_for_exit(fixture.spawn()?, Duration::from_secs(2))?;

    assert_failure(&output);
    assert!(fs::symlink_metadata(&fixture.input)?.file_type().is_fifo());
    assert_eq!(directory_entries(fixture.directory.path())?, entries);
    Ok(())
}

#[test]
fn fifo_key_is_rejected_without_blocking_or_modifying_input() -> io::Result<()> {
    let plaintext = b"a FIFO key must never be opened and block the process";
    let fixture = Fixture::new("fifo-key", plaintext, Some(b"placeholder"))?;
    fs::remove_file(&fixture.key)?;
    create_fifo(&fixture.key)?;
    let input_identity = file_identity(&fixture.input)?;
    let entries = directory_entries(fixture.directory.path())?;

    let output = wait_for_exit(fixture.spawn()?, Duration::from_secs(2))?;

    assert_failure(&output);
    assert_eq!(fs::read(&fixture.input)?, plaintext);
    assert_eq!(file_identity(&fixture.input)?, input_identity);
    assert!(fs::symlink_metadata(&fixture.key)?.file_type().is_fifo());
    assert_eq!(directory_entries(fixture.directory.path())?, entries);
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn rotating_key_path_during_transform_aborts_without_replacing_input() -> io::Result<()> {
    const FILE_SIZE: usize = 64 * 1024 * 1024;
    const PLAINTEXT: u8 = 0x39;
    const OLD_KEY: u8 = 0xa7;
    const NEW_KEY: u8 = 0x52;

    let _serial = BARRIER_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let fixture = Fixture::new("key-rotation", &[], Some(&[]))?;
    write_repeated(&fixture.input, PLAINTEXT, FILE_SIZE)?;
    write_repeated(&fixture.key, OLD_KEY, FILE_SIZE)?;
    let replacement_key = fixture.directory.path().join("replacement-key.key");
    let original_key_backup = fixture.directory.path().join("original-key.key");
    write_repeated(&replacement_key, NEW_KEY, FILE_SIZE)?;
    let input_identity = file_identity(&fixture.input)?;

    let mut child = fixture.spawn()?;
    let temporary = wait_for_otp_temp(&mut child, fixture.directory.path())?;
    stop_child(&mut child)?;
    assert!(
        fs::metadata(&temporary)?.len() < FILE_SIZE as u64,
        "the key-rotation barrier was reached too late"
    );
    fs::rename(&fixture.key, &original_key_backup)?;
    fs::rename(&replacement_key, &fixture.key)?;
    continue_child(&child)?;
    let output = wait_for_exit(child, Duration::from_secs(30))?;

    assert_concurrent_change_failure(&output);
    assert_eq!(file_identity(&fixture.input)?, input_identity);
    assert_file_is_byte(&fixture.input, PLAINTEXT, FILE_SIZE)?;
    assert_file_is_byte(&fixture.key, NEW_KEY, FILE_SIZE)?;
    assert_file_is_byte(&original_key_backup, OLD_KEY, FILE_SIZE)?;
    assert!(visible_otp_temp(fixture.directory.path())?.is_none());
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn replacing_input_path_during_transform_is_never_overwritten() -> io::Result<()> {
    const FILE_SIZE: usize = 64 * 1024 * 1024;
    const PLAINTEXT: u8 = 0x46;
    const KEY: u8 = 0xd3;

    let _serial = BARRIER_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let fixture = Fixture::new("input-replacement", &[], Some(&[]))?;
    write_repeated(&fixture.input, PLAINTEXT, FILE_SIZE)?;
    write_repeated(&fixture.key, KEY, FILE_SIZE)?;
    let replacement = fixture.directory.path().join("newer-input.bin");
    let backup = fixture.directory.path().join("original-input.bin");
    let replacement_bytes = b"new data atomically saved by another process";
    fs::write(&replacement, replacement_bytes)?;

    let mut child = fixture.spawn()?;
    let temporary = wait_for_otp_temp(&mut child, fixture.directory.path())?;
    stop_child(&mut child)?;
    assert!(
        fs::metadata(&temporary)?.len() < FILE_SIZE as u64,
        "the input-replacement barrier was reached too late"
    );
    fs::rename(&fixture.input, &backup)?;
    fs::rename(&replacement, &fixture.input)?;
    let replacement_identity = file_identity(&fixture.input)?;
    continue_child(&child)?;
    let output = wait_for_exit(child, Duration::from_secs(30))?;

    assert_concurrent_change_failure(&output);
    assert_eq!(file_identity(&fixture.input)?, replacement_identity);
    assert_eq!(fs::read(&fixture.input)?, replacement_bytes);
    assert_file_is_byte(&backup, PLAINTEXT, FILE_SIZE)?;
    assert_file_is_byte(&fixture.key, KEY, FILE_SIZE)?;
    assert!(visible_otp_temp(fixture.directory.path())?.is_none());
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn substituting_visible_temp_path_cannot_commit_or_delete_substitute() -> io::Result<()> {
    const FILE_SIZE: usize = 64 * 1024 * 1024;
    const PLAINTEXT: u8 = 0x5b;
    const KEY: u8 = 0xe1;

    let _serial = BARRIER_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let fixture = Fixture::new("temp-substitution", &[], Some(&[]))?;
    write_repeated(&fixture.input, PLAINTEXT, FILE_SIZE)?;
    write_repeated(&fixture.key, KEY, FILE_SIZE)?;
    let input_identity = file_identity(&fixture.input)?;

    let mut child = fixture.spawn()?;
    let temporary = wait_for_otp_temp(&mut child, fixture.directory.path())?;
    stop_child(&mut child)?;
    assert!(
        fs::metadata(&temporary)?.len() < FILE_SIZE as u64,
        "the temp-substitution barrier was reached too late"
    );
    let captured_temporary = fixture.directory.path().join("captured-real-temp.bin");
    let sentinel = b"this substituted path must not be committed or unlinked";
    fs::rename(&temporary, &captured_temporary)?;
    fs::write(&temporary, sentinel)?;
    let sentinel_identity = file_identity(&temporary)?;
    continue_child(&child)?;
    let output = wait_for_exit(child, Duration::from_secs(30))?;

    assert_concurrent_change_failure(&output);
    assert_eq!(file_identity(&fixture.input)?, input_identity);
    assert_file_is_byte(&fixture.input, PLAINTEXT, FILE_SIZE)?;
    assert_eq!(file_identity(&temporary)?, sentinel_identity);
    assert_eq!(fs::read(&temporary)?, sentinel);
    assert!(captured_temporary.exists());
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn forced_termination_before_rename_leaves_original_inode_and_restrictive_temp() -> io::Result<()> {
    const FILE_SIZE: usize = 64 * 1024 * 1024;
    const PLAINTEXT: u8 = 0x68;
    const KEY: u8 = 0x9d;

    let _serial = BARRIER_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let fixture = Fixture::new("forced-termination", &[], Some(&[]))?;
    write_repeated(&fixture.input, PLAINTEXT, FILE_SIZE)?;
    write_repeated(&fixture.key, KEY, FILE_SIZE)?;
    fs::set_permissions(&fixture.input, fs::Permissions::from_mode(0o644))?;
    let input_identity = file_identity(&fixture.input)?;

    let mut child = fixture.spawn()?;
    let temporary = wait_for_otp_temp(&mut child, fixture.directory.path())?;
    stop_child(&mut child)?;
    let temporary_metadata = fs::metadata(&temporary)?;
    assert!(
        temporary_metadata.len() < FILE_SIZE as u64,
        "the forced-termination barrier was reached too late"
    );
    assert_eq!(
        temporary_metadata.mode() & 0o077,
        0,
        "temporary output was accessible to group or other users"
    );
    child.kill()?;
    let output = child.wait_with_output()?;

    assert!(!output.status.success());
    assert_eq!(file_identity(&fixture.input)?, input_identity);
    assert_file_is_byte(&fixture.input, PLAINTEXT, FILE_SIZE)?;
    assert_file_is_byte(&fixture.key, KEY, FILE_SIZE)?;
    assert!(temporary.exists(), "forced termination should bypass Drop");
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn in_place_input_mutation_during_transform_is_preserved_and_aborts_commit() -> io::Result<()> {
    const FILE_SIZE: u64 = 64 * 1024 * 1024;
    const MUTATION_OFFSET: u64 = 2 * 1024 * 1024 + 37;
    const OVERWRITE: &[u8] = b"external-input-overwrite";
    const SUFFIX: &[u8] = b"external-input-append";

    let _serial = BARRIER_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let fixture = Fixture::new("input-in-place-mutation", &[], Some(&[]))?;
    create_sparse_file(&fixture.input, FILE_SIZE)?;
    create_sparse_file(&fixture.key, FILE_SIZE)?;
    let original_input_identity = file_identity(&fixture.input)?;
    let original_key_identity = file_identity(&fixture.key)?;
    let original_entries = directory_entries(fixture.directory.path())?;

    let mut child = fixture.spawn()?;
    let temporary = wait_for_otp_temp(&mut child, fixture.directory.path())?;
    stop_child(&mut child)?;
    assert!(
        fs::metadata(&temporary)?.len() < FILE_SIZE,
        "the input-mutation barrier was reached after transformation completed"
    );

    mutate_file_in_place(&fixture.input, MUTATION_OFFSET, OVERWRITE, SUFFIX)?;
    assert_eq!(file_identity(&fixture.input)?, original_input_identity);
    continue_child(&child)?;
    let output = wait_for_exit(child, Duration::from_secs(30))?;

    assert_concurrent_change_failure(&output);
    assert_eq!(file_identity(&fixture.input)?, original_input_identity);
    assert_eq!(
        fs::metadata(&fixture.input)?.len(),
        FILE_SIZE + SUFFIX.len() as u64
    );
    assert_bytes_at(&fixture.input, MUTATION_OFFSET, OVERWRITE)?;
    assert_bytes_at(&fixture.input, FILE_SIZE, SUFFIX)?;
    assert_eq!(file_identity(&fixture.key)?, original_key_identity);
    assert_eq!(fs::metadata(&fixture.key)?.len(), FILE_SIZE);
    assert_bytes_at(&fixture.key, MUTATION_OFFSET, &[0])?;
    assert_eq!(
        directory_entries(fixture.directory.path())?,
        original_entries,
        "aborting after input mutation left a temporary output"
    );
    assert!(visible_otp_temp(fixture.directory.path())?.is_none());
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn in_place_key_mutation_during_transform_is_preserved_and_aborts_commit() -> io::Result<()> {
    const FILE_SIZE: u64 = 64 * 1024 * 1024;
    const MUTATION_OFFSET: u64 = 3 * 1024 * 1024 + 19;
    const OVERWRITE: &[u8] = b"external-key-overwrite";
    const SUFFIX: &[u8] = b"external-key-append";

    let _serial = BARRIER_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let fixture = Fixture::new("key-in-place-mutation", &[], Some(&[]))?;
    create_sparse_file(&fixture.input, FILE_SIZE)?;
    create_sparse_file(&fixture.key, FILE_SIZE)?;
    let original_input_identity = file_identity(&fixture.input)?;
    let original_key_identity = file_identity(&fixture.key)?;
    let original_entries = directory_entries(fixture.directory.path())?;

    let mut child = fixture.spawn()?;
    let temporary = wait_for_otp_temp(&mut child, fixture.directory.path())?;
    stop_child(&mut child)?;
    assert!(
        fs::metadata(&temporary)?.len() < FILE_SIZE,
        "the key-mutation barrier was reached after transformation completed"
    );

    mutate_file_in_place(&fixture.key, MUTATION_OFFSET, OVERWRITE, SUFFIX)?;
    assert_eq!(file_identity(&fixture.key)?, original_key_identity);
    continue_child(&child)?;
    let output = wait_for_exit(child, Duration::from_secs(30))?;

    assert_concurrent_change_failure(&output);
    assert_eq!(file_identity(&fixture.input)?, original_input_identity);
    assert_eq!(fs::metadata(&fixture.input)?.len(), FILE_SIZE);
    assert_bytes_at(&fixture.input, MUTATION_OFFSET, &[0])?;
    assert_eq!(file_identity(&fixture.key)?, original_key_identity);
    assert_eq!(
        fs::metadata(&fixture.key)?.len(),
        FILE_SIZE + SUFFIX.len() as u64
    );
    assert_bytes_at(&fixture.key, MUTATION_OFFSET, OVERWRITE)?;
    assert_bytes_at(&fixture.key, FILE_SIZE, SUFFIX)?;
    assert_eq!(
        directory_entries(fixture.directory.path())?,
        original_entries,
        "aborting after key mutation left a temporary output"
    );
    assert!(visible_otp_temp(fixture.directory.path())?.is_none());
    Ok(())
}
