#![cfg(target_os = "linux")]

use std::collections::BTreeSet;
use std::env;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{self as unix_fs, MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const KEY: [u8; 32] = [0xa7; 32];
const OTHER_KEY: [u8; 32] = [0x39; 32];
const TAG_SUFFIX: &str = ".otp2auth";

static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);
static RACE_LOCK: Mutex<()> = Mutex::new(());

struct Scratch(PathBuf);

impl Scratch {
    fn new(label: &str) -> io::Result<Self> {
        for _ in 0..1_000 {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = env::temp_dir().join(format!(
                "otp2-auth-detached-atomicity-{label}-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate an atomicity-test directory",
        ))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Fixture {
    _scratch: Scratch,
    root: PathBuf,
    work: PathBuf,
    data: PathBuf,
    executable: PathBuf,
    key: PathBuf,
    file: PathBuf,
}

impl Fixture {
    fn new(label: &str, contents: &[u8]) -> io::Result<Self> {
        let scratch = Scratch::new(label)?;
        let root = scratch.0.clone();
        let bin = root.join("private executable directory");
        let work = root.join("unrelated working directory");
        let data = root.join("data directory");
        fs::create_dir(&bin)?;
        fs::create_dir(&work)?;
        fs::create_dir(&data)?;

        let executable = bin.join("otp2-auth-under-test");
        fs::copy(env!("CARGO_BIN_EXE_otp2-auth"), &executable)?;
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))?;
        let key = bin.join("auth.key");
        fs::write(&key, KEY)?;
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600))?;
        let file = data.join("payload.bin");
        fs::write(&file, contents)?;

        Ok(Self {
            _scratch: scratch,
            root,
            work,
            data,
            executable,
            key,
            file,
        })
    }

    fn tag_path(&self) -> PathBuf {
        default_tag_path(&self.file)
    }

    fn command(&self, arguments: &[&Path]) -> Command {
        let mut command = Command::new(&self.executable);
        command.current_dir(&self.work);
        for argument in arguments {
            command.arg(argument);
        }
        command
    }

    fn run(&self, arguments: &[&Path]) -> io::Result<Output> {
        run_command(self.command(arguments))
    }

    fn spawn(&self, arguments: &[&Path]) -> io::Result<ManagedChild> {
        spawn_command(self.command(arguments), None)
    }

    fn spawn_with_umask(
        &self,
        arguments: &[&Path],
        mask: libc::mode_t,
    ) -> io::Result<ManagedChild> {
        spawn_command(self.command(arguments), Some(mask))
    }

    fn tag(&self) -> io::Result<Output> {
        self.run(&[Path::new("tag"), &self.file])
    }

    fn verify_path(&self, file: &Path, tag: &Path) -> io::Result<Output> {
        self.run(&[Path::new("verify"), Path::new("--tag"), tag, file])
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

    fn wait(mut self, timeout: Duration) -> io::Result<Output> {
        let started = Instant::now();
        loop {
            if self.child_mut().try_wait()?.is_some() {
                return self
                    .0
                    .take()
                    .expect("managed child is present")
                    .wait_with_output();
            }
            if started.elapsed() >= timeout {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "otp2-auth child did not exit before timeout",
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

fn run_command(mut command: Command) -> io::Result<Output> {
    for attempt in 0..100 {
        match command.output() {
            Ok(output) => return Ok(output),
            Err(error) if error.kind() == io::ErrorKind::ExecutableFileBusy && attempt != 99 => {
                thread::yield_now();
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!("the last launch attempt returns")
}

fn spawn_command(mut command: Command, mask: Option<libc::mode_t>) -> io::Result<ManagedChild> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    if let Some(mask) = mask {
        // SAFETY: after fork the closure performs only the async-signal-safe
        // `umask` call before exec and does not access shared state.
        unsafe {
            command.pre_exec(move || {
                libc::umask(mask);
                Ok(())
            });
        }
    }
    for attempt in 0..100 {
        match command.spawn() {
            Ok(child) => return Ok(ManagedChild(Some(child))),
            Err(error) if error.kind() == io::ErrorKind::ExecutableFileBusy && attempt != 99 => {
                thread::yield_now();
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!("the last launch attempt returns")
}

fn default_tag_path(file: &Path) -> PathBuf {
    let mut path = file.as_os_str().to_os_string();
    path.push(TAG_SUFFIX);
    PathBuf::from(path)
}

fn assert_success(output: &Output) {
    assert_eq!(
        output.status.code(),
        Some(0),
        "unexpected failure\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

fn assert_runtime_failure(output: &Output) {
    assert_eq!(
        output.status.code(),
        Some(1),
        "expected operational failure\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
}

fn identity(path: &Path) -> io::Result<(u64, u64)> {
    let metadata = fs::metadata(path)?;
    Ok((metadata.dev(), metadata.ino()))
}

fn entries(path: &Path) -> io::Result<BTreeSet<OsString>> {
    fs::read_dir(path)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect()
}

fn visible_temps(path: &Path) -> io::Result<Vec<PathBuf>> {
    let mut result = Vec::new();
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(".otp2-auth-") && name.ends_with(".tmp") {
            result.push(entry.path());
        }
    }
    result.sort();
    Ok(result)
}

fn wait_for_temp(child: &mut ManagedChild, directory: &Path) -> io::Result<PathBuf> {
    wait_for_temp_count(child, directory, 1).map(|mut paths| paths.remove(0))
}

fn wait_for_temp_count(
    child: &mut ManagedChild,
    directory: &Path,
    count: usize,
) -> io::Result<Vec<PathBuf>> {
    let started = Instant::now();
    loop {
        let paths = visible_temps(directory)?;
        if paths.len() >= count {
            return Ok(paths);
        }
        if let Some(status) = child.child_mut().try_wait()? {
            return Err(io::Error::other(format!(
                "otp2-auth exited with {status} before exposing {count} temporary files"
            )));
        }
        if started.elapsed() >= Duration::from_secs(10) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "temporary sidecar did not appear",
            ));
        }
        thread::yield_now();
    }
}

fn wait_until_child_has_open_path(child: &mut ManagedChild, path: &Path) -> io::Result<()> {
    let expected = identity(path)?;
    let descriptors = PathBuf::from(format!("/proc/{}/fd", child.child().id()));
    let started = Instant::now();
    loop {
        if let Ok(entries) = fs::read_dir(&descriptors) {
            for entry in entries.flatten() {
                if let Ok(metadata) = fs::metadata(entry.path())
                    && (metadata.dev(), metadata.ino()) == expected
                {
                    return Ok(());
                }
            }
        }
        if let Some(status) = child.child_mut().try_wait()? {
            return Err(io::Error::other(format!(
                "otp2-auth exited with {status} before the descriptor barrier"
            )));
        }
        if started.elapsed() >= Duration::from_secs(10) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "child did not open the expected path",
            ));
        }
        thread::yield_now();
    }
}

fn signal(child: &Child, value: libc::c_int) -> io::Result<()> {
    // SAFETY: the PID belongs to the live managed child and no Rust memory is
    // accessed by `kill`.
    if unsafe { libc::kill(child.id() as libc::pid_t, value) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn stop(child: &mut ManagedChild) -> io::Result<()> {
    signal(child.child(), libc::SIGSTOP)?;
    let mut status = 0;
    // SAFETY: `status` is writable and the PID belongs to the live child.
    let result = unsafe {
        libc::waitpid(
            child.child().id() as libc::pid_t,
            &mut status,
            libc::WUNTRACED,
        )
    };
    if result == child.child().id() as libc::pid_t && libc::WIFSTOPPED(status) {
        Ok(())
    } else if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Err(io::Error::other("child exited before SIGSTOP took effect"))
    }
}

fn resume(child: &ManagedChild) -> io::Result<()> {
    signal(child.child(), libc::SIGCONT)
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

fn assert_repeated(path: &Path, byte: u8, length: usize) -> io::Result<()> {
    let mut file = File::open(path)?;
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0;
    loop {
        let amount = file.read(&mut buffer)?;
        if amount == 0 {
            break;
        }
        assert!(buffer[..amount].iter().all(|actual| *actual == byte));
        total += amount;
    }
    assert_eq!(total, length);
    Ok(())
}

#[test]
fn attacker_cannot_win_initial_no_clobber_publish() -> io::Result<()> {
    const SIZE: usize = 32 * 1024 * 1024;
    let _serial = RACE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let fixture = Fixture::new("initial-no-clobber", b"")?;
    write_repeated(&fixture.file, 0x61, SIZE)?;
    let file_identity = identity(&fixture.file)?;
    let mut child = fixture.spawn(&[Path::new("tag"), &fixture.file])?;
    let _temp = wait_for_temp(&mut child, &fixture.data)?;
    stop(&mut child)?;

    let sentinel = b"attacker-created destination must survive";
    fs::write(fixture.tag_path(), sentinel)?;
    let sentinel_identity = identity(&fixture.tag_path())?;
    resume(&child)?;
    let output = child.wait(Duration::from_secs(20))?;

    assert_runtime_failure(&output);
    assert_eq!(identity(&fixture.file)?, file_identity);
    assert_repeated(&fixture.file, 0x61, SIZE)?;
    assert_eq!(identity(&fixture.tag_path())?, sentinel_identity);
    assert_eq!(fs::read(fixture.tag_path())?, sentinel);
    assert!(visible_temps(&fixture.data)?.is_empty());
    Ok(())
}

#[test]
fn replacement_is_identity_checked_and_never_overwrites_a_substitute() -> io::Result<()> {
    const SIZE: usize = 32 * 1024 * 1024;
    let _serial = RACE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let fixture = Fixture::new("replace-substitute", b"first payload")?;
    assert_success(&fixture.tag()?);
    let old_sidecar = fixture.root.join("old-sidecar");
    write_repeated(&fixture.file, 0x72, SIZE)?;
    let mut child = fixture.spawn(&[Path::new("tag"), Path::new("--replace"), &fixture.file])?;
    let _temp = wait_for_temp(&mut child, &fixture.data)?;
    stop(&mut child)?;

    fs::rename(fixture.tag_path(), &old_sidecar)?;
    let sentinel = b"concurrent sidecar replacement";
    fs::write(fixture.tag_path(), sentinel)?;
    let sentinel_identity = identity(&fixture.tag_path())?;
    resume(&child)?;
    let output = child.wait(Duration::from_secs(20))?;

    assert_runtime_failure(&output);
    assert_eq!(identity(&fixture.tag_path())?, sentinel_identity);
    assert_eq!(fs::read(fixture.tag_path())?, sentinel);
    assert_eq!(fs::metadata(old_sidecar)?.len(), 64);
    assert!(visible_temps(&fixture.data)?.is_empty());
    Ok(())
}

#[test]
fn replacing_the_payload_path_aborts_without_publishing_a_sidecar() -> io::Result<()> {
    const SIZE: usize = 32 * 1024 * 1024;
    let _serial = RACE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let fixture = Fixture::new("payload-replacement", b"")?;
    write_repeated(&fixture.file, 0x84, SIZE)?;
    let original = fixture.root.join("original-payload");
    let replacement = b"new payload saved by another process";
    let mut child = fixture.spawn(&[Path::new("tag"), &fixture.file])?;
    let _temp = wait_for_temp(&mut child, &fixture.data)?;
    stop(&mut child)?;

    fs::rename(&fixture.file, &original)?;
    fs::write(&fixture.file, replacement)?;
    let replacement_identity = identity(&fixture.file)?;
    resume(&child)?;
    let output = child.wait(Duration::from_secs(20))?;

    assert_runtime_failure(&output);
    assert_eq!(identity(&fixture.file)?, replacement_identity);
    assert_eq!(fs::read(&fixture.file)?, replacement);
    assert_repeated(&original, 0x84, SIZE)?;
    assert!(!fixture.tag_path().exists());
    assert!(visible_temps(&fixture.data)?.is_empty());
    Ok(())
}

#[test]
fn in_place_payload_mutation_aborts_without_publishing_a_sidecar() -> io::Result<()> {
    const SIZE: usize = 32 * 1024 * 1024;
    let _serial = RACE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let fixture = Fixture::new("payload-mutation", b"")?;
    write_repeated(&fixture.file, 0x95, SIZE)?;
    let file_identity = identity(&fixture.file)?;
    let mut child = fixture.spawn(&[Path::new("tag"), &fixture.file])?;
    let _temp = wait_for_temp(&mut child, &fixture.data)?;
    stop(&mut child)?;

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&fixture.file)?;
    file.seek(SeekFrom::Start(1_048_593))?;
    file.write_all(b"external mutation")?;
    file.seek(SeekFrom::End(0))?;
    file.write_all(b"external suffix")?;
    file.sync_all()?;
    resume(&child)?;
    let output = child.wait(Duration::from_secs(20))?;

    assert_runtime_failure(&output);
    assert_eq!(identity(&fixture.file)?, file_identity);
    assert_eq!(fs::metadata(&fixture.file)?.len(), (SIZE + 15) as u64);
    assert!(!fixture.tag_path().exists());
    assert!(visible_temps(&fixture.data)?.is_empty());
    Ok(())
}

#[test]
fn rotating_the_open_key_aborts_without_publishing_a_sidecar() -> io::Result<()> {
    const SIZE: usize = 32 * 1024 * 1024;
    let _serial = RACE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let fixture = Fixture::new("key-rotation", b"")?;
    write_repeated(&fixture.file, 0x47, SIZE)?;
    let old_key = fixture.root.join("old-auth.key");
    let replacement_key = fixture.root.join("replacement-auth.key");
    fs::write(&replacement_key, OTHER_KEY)?;
    fs::set_permissions(&replacement_key, fs::Permissions::from_mode(0o600))?;
    let mut child = fixture.spawn(&[Path::new("tag"), &fixture.file])?;
    let _temp = wait_for_temp(&mut child, &fixture.data)?;
    stop(&mut child)?;

    fs::rename(&fixture.key, &old_key)?;
    fs::rename(&replacement_key, &fixture.key)?;
    resume(&child)?;
    let output = child.wait(Duration::from_secs(20))?;

    assert_runtime_failure(&output);
    assert_eq!(fs::read(&fixture.key)?, OTHER_KEY);
    assert_eq!(fs::read(old_key)?, KEY);
    assert!(!fixture.tag_path().exists());
    assert!(visible_temps(&fixture.data)?.is_empty());
    Ok(())
}

#[test]
fn substituting_the_visible_temp_cannot_publish_or_delete_the_substitute() -> io::Result<()> {
    const SIZE: usize = 32 * 1024 * 1024;
    let _serial = RACE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let fixture = Fixture::new("temp-substitute", b"")?;
    write_repeated(&fixture.file, 0x28, SIZE)?;
    let mut child = fixture.spawn(&[Path::new("tag"), &fixture.file])?;
    let temp = wait_for_temp(&mut child, &fixture.data)?;
    stop(&mut child)?;

    let displaced = fixture.root.join("displaced-real-temp");
    fs::rename(&temp, &displaced)?;
    let sentinel = b"attacker temp substitute";
    fs::write(&temp, sentinel)?;
    let sentinel_identity = identity(&temp)?;
    resume(&child)?;
    let output = child.wait(Duration::from_secs(20))?;

    assert_runtime_failure(&output);
    assert_eq!(identity(&temp)?, sentinel_identity);
    assert_eq!(fs::read(&temp)?, sentinel);
    assert!(displaced.exists());
    assert!(!fixture.tag_path().exists());
    Ok(())
}

#[test]
fn renamed_resolved_directory_stays_pinned_after_parent_symlink_retarget() -> io::Result<()> {
    const SIZE: usize = 32 * 1024 * 1024;
    let _serial = RACE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let mut fixture = Fixture::new("parent-retarget", b"")?;
    let original_directory = fixture.root.join("original object directory");
    let anchored_directory = fixture.root.join("renamed anchored directory");
    let alternate_directory = fixture.root.join("alternate object directory");
    let alias = fixture.root.join("current object directory");
    fs::create_dir(&original_directory)?;
    fs::create_dir(&alternate_directory)?;
    write_repeated(&original_directory.join("object.bin"), 0x5d, SIZE)?;
    fs::write(alternate_directory.join("object.bin"), b"alternate")?;
    unix_fs::symlink(&original_directory, &alias)?;
    fixture.file = alias.join("object.bin");

    let mut child = fixture.spawn(&[Path::new("tag"), &fixture.file])?;
    let _temp = wait_for_temp(&mut child, &original_directory)?;
    stop(&mut child)?;
    fs::rename(&original_directory, &anchored_directory)?;
    fs::remove_file(&alias)?;
    unix_fs::symlink(&alternate_directory, &alias)?;
    resume(&child)?;
    let output = child.wait(Duration::from_secs(20))?;

    assert_success(&output);
    let anchored_file = anchored_directory.join("object.bin");
    let anchored_tag = default_tag_path(&anchored_file);
    assert_repeated(&anchored_file, 0x5d, SIZE)?;
    assert_eq!(fs::metadata(&anchored_tag)?.len(), 64);
    assert_eq!(fs::read(alias.join("object.bin"))?, b"alternate");
    assert!(!default_tag_path(&alias.join("object.bin")).exists());
    assert_success(&fixture.verify_path(&anchored_file, &anchored_tag)?);
    assert!(visible_temps(&anchored_directory)?.is_empty());
    Ok(())
}

#[test]
fn forced_termination_leaves_payload_intact_and_temp_private_under_umask_zero() -> io::Result<()> {
    const SIZE: usize = 32 * 1024 * 1024;
    let _serial = RACE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let fixture = Fixture::new("forced-termination", b"")?;
    write_repeated(&fixture.file, 0x36, SIZE)?;
    let file_identity = identity(&fixture.file)?;
    let mut child = fixture.spawn_with_umask(&[Path::new("tag"), &fixture.file], 0)?;
    let temp = wait_for_temp(&mut child, &fixture.data)?;
    stop(&mut child)?;
    assert_eq!(fs::metadata(&temp)?.mode() & 0o777, 0o600);

    child.child_mut().kill()?;
    let output = child.wait(Duration::from_secs(10))?;
    assert!(!output.status.success());
    assert_eq!(identity(&fixture.file)?, file_identity);
    assert_repeated(&fixture.file, 0x36, SIZE)?;
    assert!(!fixture.tag_path().exists());
    assert!(temp.exists(), "SIGKILL should bypass Rust cleanup");
    Ok(())
}

#[test]
fn hardlinked_inputs_are_allowed_and_never_replaced() -> io::Result<()> {
    let fixture = Fixture::new("hardlinked-input", b"same inode is legitimate input data")?;
    let alias = fixture.data.join("payload-hardlink.bin");
    fs::hard_link(&fixture.file, &alias)?;
    let original_identity = identity(&fixture.file)?;
    let original_entries = entries(&fixture.data)?;

    assert_success(&fixture.tag()?);
    let alias_tag = default_tag_path(&alias);
    assert_success(&fixture.run(&[Path::new("tag"), Path::new("--output"), &alias_tag, &alias])?);
    assert_success(&fixture.verify_path(&alias, &fixture.tag_path())?);

    assert_eq!(identity(&fixture.file)?, original_identity);
    assert_eq!(identity(&alias)?, original_identity);
    assert_eq!(fs::metadata(&fixture.file)?.nlink(), 2);
    let mut expected = original_entries;
    expected.insert(fixture.tag_path().file_name().unwrap().to_os_string());
    expected.insert(alias_tag.file_name().unwrap().to_os_string());
    assert_eq!(entries(&fixture.data)?, expected);
    Ok(())
}

#[test]
fn two_concurrent_initial_taggers_publish_exactly_one_complete_sidecar() -> io::Result<()> {
    const SIZE: usize = 32 * 1024 * 1024;
    let _serial = RACE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let fixture = Fixture::new("concurrent-initial-taggers", b"")?;
    write_repeated(&fixture.file, 0xa4, SIZE)?;
    let file_identity = identity(&fixture.file)?;

    let mut first = fixture.spawn(&[Path::new("tag"), &fixture.file])?;
    let _first_temp = wait_for_temp(&mut first, &fixture.data)?;
    stop(&mut first)?;
    let mut second = fixture.spawn(&[Path::new("tag"), &fixture.file])?;
    let _both_temps = wait_for_temp_count(&mut second, &fixture.data, 2)?;
    stop(&mut second)?;

    resume(&first)?;
    resume(&second)?;
    let first_output = first.wait(Duration::from_secs(20))?;
    let second_output = second.wait(Duration::from_secs(20))?;
    let mut codes = [first_output.status.code(), second_output.status.code()];
    codes.sort();
    assert_eq!(codes, [Some(0), Some(1)]);
    assert_eq!(identity(&fixture.file)?, file_identity);
    assert_repeated(&fixture.file, 0xa4, SIZE)?;
    assert_eq!(fs::metadata(fixture.tag_path())?.len(), 64);
    assert_success(&fixture.verify_path(&fixture.file, &fixture.tag_path())?);
    assert!(visible_temps(&fixture.data)?.is_empty());
    Ok(())
}

#[test]
fn atomic_replace_keeps_already_open_sidecar_descriptor_on_complete_old_inode() -> io::Result<()> {
    let fixture = Fixture::new("held-sidecar-descriptor", b"old payload")?;
    assert_success(&fixture.tag()?);
    let tag = fixture.tag_path();
    let old_bytes = fs::read(&tag)?;
    let mut held = File::open(&tag)?;
    let old_identity = identity(&tag)?;

    fs::write(
        &fixture.file,
        b"new payload with different authenticated bytes",
    )?;
    assert_success(&fixture.run(&[Path::new("tag"), Path::new("--replace"), &fixture.file])?);
    let new_bytes = fs::read(&tag)?;
    assert_ne!(new_bytes, old_bytes);
    assert_ne!(identity(&tag)?, old_identity);
    assert_eq!(fs::metadata(&tag)?.mode() & 0o777, 0o600);

    held.seek(SeekFrom::Start(0))?;
    let mut held_bytes = Vec::new();
    held.read_to_end(&mut held_bytes)?;
    assert_eq!(held_bytes, old_bytes);
    assert_eq!(held.metadata()?.ino(), old_identity.1);
    assert_eq!(held.metadata()?.nlink(), 0);
    assert_success(&fixture.verify_path(&fixture.file, &tag)?);
    Ok(())
}

#[test]
fn verification_racing_an_in_place_payload_mutation_never_false_accepts() -> io::Result<()> {
    const SIZE: usize = 64 * 1024 * 1024;
    let _serial = RACE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let fixture = Fixture::new("verify-payload-mutation", b"")?;
    write_repeated(&fixture.file, 0xc3, SIZE)?;
    assert_success(&fixture.tag()?);
    let tag_bytes = fs::read(fixture.tag_path())?;
    let file_identity = identity(&fixture.file)?;

    let mut child = fixture.spawn(&[Path::new("verify"), &fixture.file])?;
    wait_until_child_has_open_path(&mut child, &fixture.file)?;
    stop(&mut child)?;
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&fixture.file)?;
    file.seek(SeekFrom::Start(7 * 1024 * 1024 + 31))?;
    file.write_all(b"racing verifier mutation")?;
    file.sync_all()?;
    resume(&child)?;
    let output = child.wait(Duration::from_secs(20))?;

    assert_runtime_failure(&output);
    assert_eq!(identity(&fixture.file)?, file_identity);
    assert_eq!(fs::read(fixture.tag_path())?, tag_bytes);
    Ok(())
}

#[test]
fn verification_racing_a_sidecar_path_replacement_never_uses_the_substitute() -> io::Result<()> {
    const SIZE: usize = 64 * 1024 * 1024;
    let _serial = RACE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let fixture = Fixture::new("verify-sidecar-replacement", b"")?;
    write_repeated(&fixture.file, 0xd4, SIZE)?;
    assert_success(&fixture.tag()?);
    let tag = fixture.tag_path();
    let original_tag = fixture.root.join("original-valid-sidecar");

    let mut child = fixture.spawn(&[Path::new("verify"), &fixture.file])?;
    wait_until_child_has_open_path(&mut child, &tag)?;
    stop(&mut child)?;
    fs::rename(&tag, &original_tag)?;
    let substitute = [0x5a; 64];
    fs::write(&tag, substitute)?;
    fs::set_permissions(&tag, fs::Permissions::from_mode(0o600))?;
    let substitute_identity = identity(&tag)?;
    resume(&child)?;
    let output = child.wait(Duration::from_secs(20))?;

    assert_runtime_failure(&output);
    assert_eq!(identity(&tag)?, substitute_identity);
    assert_eq!(fs::read(&tag)?, substitute);
    assert_eq!(fs::metadata(&original_tag)?.len(), 64);
    Ok(())
}
