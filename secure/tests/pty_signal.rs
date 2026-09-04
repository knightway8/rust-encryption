#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]

use std::{
    ffi::OsStr,
    fs::File,
    io::{self, Read, Write},
    os::unix::fs::PermissionsExt,
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

use rustix::{
    fs::{self, OFlags},
    io::dup,
    process::{self as rustix_process, Pid, Signal},
    pty::{self, OpenptFlags},
    termios::{self, LocalModes, OptionalActions},
};

const POLL_INTERVAL: Duration = Duration::from_millis(5);
const PROMPT_TIMEOUT: Duration = Duration::from_secs(5);
const EXIT_TIMEOUT: Duration = Duration::from_secs(2);
const ROUND_TRIP_TIMEOUT: Duration = Duration::from_mins(1);
const PASSWORD_PROMPT: &[u8] = b"New password: ";
const CONFIRMATION_PROMPT: &[u8] = b"Confirm password: ";
const DECRYPTION_PROMPT: &[u8] = b"Password: ";

struct KillOnDrop(Child);

impl KillOnDrop {
    fn child(&mut self) -> &mut Child {
        &mut self.0
    }

    fn child_ref(&self) -> &Child {
        &self.0
    }
}

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        if matches!(self.0.try_wait(), Ok(None)) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

struct PtySession {
    master: Option<File>,
    slave: rustix::fd::OwnedFd,
    baseline_flags: LocalModes,
    baseline_termios: String,
    child: KillOnDrop,
}

impl PtySession {
    fn spawn(arguments: &[&OsStr]) -> Self {
        let master = pty::openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC)
            .expect("PTY master should open");
        pty::grantpt(&master).expect("PTY slave permissions should be granted");
        pty::unlockpt(&master).expect("PTY slave should be unlocked");
        let slave = pty::ioctl_tiocgptpeer(
            &master,
            OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC,
        )
        .expect("PTY slave should open");

        let sensitive = LocalModes::ECHO | LocalModes::ICANON | LocalModes::ISIG;
        let mut baseline = termios::tcgetattr(&slave).expect("baseline terminal flags should load");
        baseline.local_modes.insert(sensitive);
        termios::tcsetattr(&slave, OptionalActions::Now, &baseline)
            .expect("baseline terminal flags should be installed");
        let baseline_flags = termios::tcgetattr(&slave)
            .expect("installed baseline terminal flags should load")
            .local_modes;
        let baseline_termios = format!("{:?}", termios::tcgetattr(&slave).unwrap());
        assert!(baseline_flags.contains(sensitive));

        let stdin = File::from(dup(&slave).expect("PTY stdin should duplicate"));
        let stdout = File::from(dup(&slave).expect("PTY stdout should duplicate"));
        let stderr = File::from(dup(&slave).expect("PTY stderr should duplicate"));

        // `setsid --ctty` is the standard Linux utility for making an
        // already-open terminal the controlling terminal without an unsafe
        // `pre_exec` hook. A fresh child is not a process-group leader, so
        // setsid execs secure in-place; `verify_secure_pid` checks this.
        let child = Command::new("setsid")
            .arg("--ctty")
            .arg(env!("CARGO_BIN_EXE_secure"))
            .args(arguments.iter().copied())
            .stdin(Stdio::from(stdin))
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()
            .expect("secure should spawn in a fresh controlling-terminal session");

        fs::fcntl_setfl(
            &master,
            fs::fcntl_getfl(&master).unwrap() | OFlags::NONBLOCK,
        )
        .expect("PTY master should become nonblocking");

        Self {
            master: Some(File::from(master)),
            slave,
            baseline_flags,
            baseline_termios,
            child: KillOnDrop(child),
        }
    }

    fn wait_for_prompt(&mut self, prompt: &[u8], transcript: &mut Vec<u8>) {
        wait_for_disabled_prompt(
            self.master.as_mut().expect("PTY master should be open"),
            &self.slave,
            self.child.child(),
            prompt,
            transcript,
        );
    }

    fn write_password(&mut self, password: &[u8]) {
        self.master
            .as_mut()
            .expect("PTY master should be open")
            .write_all(password)
            .expect("password should be delivered to the PTY");
        self.master
            .as_mut()
            .expect("PTY master should be open")
            .write_all(b"\n")
            .expect("password newline should be delivered to the PTY");
        self.master
            .as_mut()
            .expect("PTY master should be open")
            .flush()
            .expect("password input should flush");
    }

    fn write_ctrl_c(&mut self) {
        self.master
            .as_mut()
            .expect("PTY master should be open")
            .write_all(b"\x03")
            .expect("Ctrl-C should be delivered to the password reader");
        self.master
            .as_mut()
            .expect("PTY master should be open")
            .flush()
            .expect("Ctrl-C should be flushed to the PTY");
    }

    fn write_ctrl_d(&mut self) {
        self.master
            .as_mut()
            .expect("PTY master should be open")
            .write_all(b"\x04")
            .expect("Ctrl-D should be delivered to the password reader");
        self.master
            .as_mut()
            .expect("PTY master should be open")
            .flush()
            .expect("Ctrl-D should be flushed");
    }

    fn secure_pid(&self) -> Pid {
        verify_secure_pid(self.child.child_ref())
    }

    fn wait_for_exit(&mut self, timeout: Duration, trigger: &str) -> ExitStatus {
        wait_for_exit(self.child.child(), timeout, trigger)
    }

    fn drain_into(&mut self, transcript: &mut Vec<u8>) {
        drain_available(
            self.master.as_mut().expect("PTY master should be open"),
            transcript,
        );
    }

    fn assert_password_mode(&self) {
        let protected_flags = termios::tcgetattr(&self.slave)
            .expect("protected terminal flags should load")
            .local_modes;
        assert!(!protected_flags.contains(LocalModes::ECHO));
        assert!(!protected_flags.contains(LocalModes::ICANON));
        assert!(!protected_flags.contains(LocalModes::ISIG));
    }

    fn assert_terminal_restored(&self) {
        let restored_flags = termios::tcgetattr(&self.slave)
            .expect("restored terminal flags should load")
            .local_modes;
        assert_eq!(restored_flags, self.baseline_flags);
        assert!(restored_flags.contains(LocalModes::ECHO | LocalModes::ICANON | LocalModes::ISIG));
        assert_eq!(
            format!("{:?}", termios::tcgetattr(&self.slave).unwrap()),
            self.baseline_termios,
            "the complete terminal configuration was not restored"
        );
    }
}

fn drain_available(master: &mut File, transcript: &mut Vec<u8>) {
    let mut buffer = [0_u8; 1024];
    loop {
        match master.read(&mut buffer) {
            Ok(0) => return,
            Ok(read) => transcript.extend_from_slice(&buffer[..read]),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => panic!("failed to read the pseudo-terminal master: {error}"),
        }
    }
}

fn wait_for_disabled_prompt(
    master: &mut File,
    slave: &rustix::fd::OwnedFd,
    child: &mut Child,
    prompt: &[u8],
    transcript: &mut Vec<u8>,
) {
    let deadline = Instant::now() + PROMPT_TIMEOUT;
    let sensitive = LocalModes::ECHO | LocalModes::ICANON | LocalModes::ISIG;

    while Instant::now() < deadline {
        drain_available(master, transcript);
        let flags = termios::tcgetattr(slave)
            .expect("the pseudo-terminal slave should remain inspectable")
            .local_modes;

        if transcript
            .windows(prompt.len())
            .any(|window| window == prompt)
        {
            assert!(
                !flags.intersects(sensitive),
                "password prompt became visible before echo/canonical/signal modes were disabled"
            );
            return;
        }

        if let Some(status) = child
            .try_wait()
            .expect("checking the secure child should succeed")
        {
            panic!(
                "secure exited before entering its protected password prompt ({status}); PTY transcript: {:?}",
                String::from_utf8_lossy(transcript)
            );
        }
        thread::sleep(POLL_INTERVAL);
    }

    panic!(
        "secure did not display a protected password prompt within {PROMPT_TIMEOUT:?}; PTY transcript: {:?}",
        String::from_utf8_lossy(transcript)
    );
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn wait_for_exit(child: &mut Child, timeout: Duration, trigger: &str) -> ExitStatus {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(status) = child
            .try_wait()
            .expect("checking the secure child should succeed")
        {
            return status;
        }
        thread::sleep(POLL_INTERVAL);
    }
    panic!("secure did not exit within {timeout:?} after {trigger}");
}

fn verify_secure_pid(child: &Child) -> Pid {
    let pid = Pid::from_child(child);
    // `secure` deliberately makes itself non-dumpable before prompting, which
    // also prevents this same-UID test process from reading `/proc/PID/exe`.
    // The task name remains readable and changes from `setsid` to `secure` on
    // the in-place exec.
    let task_name = std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .expect("the spawned process task name should be inspectable");
    assert_eq!(
        task_name.trim_end(),
        "secure",
        "the signal target must be secure itself, not a setsid waiter"
    );
    pid
}

#[derive(Clone, Copy, Debug)]
enum Interruption {
    CtrlC,
    CtrlD,
    Sigterm,
}

impl Interruption {
    const fn trigger_name(self) -> &'static str {
        match self {
            Self::CtrlC => "Ctrl-C",
            Self::CtrlD => "Ctrl-D",
            Self::Sigterm => "SIGTERM",
        }
    }

    const fn expected_exit_code(self) -> i32 {
        match self {
            Self::CtrlC => 130,
            Self::CtrlD => 1,
            Self::Sigterm => 143,
        }
    }
}

fn assert_prompt_interruption(interruption: Interruption) {
    let directory = tempfile::tempdir().expect("temporary directory should be created");
    let input = directory.path().join("input.txt");
    let output = directory.path().join("output.age");
    std::fs::write(&input, b"plaintext that must never reach the output")
        .expect("input fixture should be written");
    let arguments = [OsStr::new("E"), input.as_os_str(), output.as_os_str()];
    let mut session = PtySession::spawn(&arguments);
    let mut transcript = Vec::new();

    session.wait_for_prompt(PASSWORD_PROMPT, &mut transcript);
    session.assert_password_mode();
    assert!(
        transcript
            .windows(PASSWORD_PROMPT.len())
            .any(|window| window == PASSWORD_PROMPT)
    );

    let secure_pid = session.secure_pid();
    let interrupted_at = Instant::now();
    match interruption {
        Interruption::CtrlC => session.write_ctrl_c(),
        Interruption::CtrlD => session.write_ctrl_d(),
        Interruption::Sigterm => rustix_process::kill_process(secure_pid, Signal::TERM)
            .expect("SIGTERM should be sent to the secure process"),
    }
    let status = session.wait_for_exit(EXIT_TIMEOUT, interruption.trigger_name());

    assert_eq!(status.code(), Some(interruption.expected_exit_code()));
    assert!(interrupted_at.elapsed() < EXIT_TIMEOUT);
    session.assert_terminal_restored();
    assert!(!output.exists(), "interrupted encryption created an output");
}

#[test]
fn ctrl_c_at_password_prompt_restores_terminal_and_exits_130_without_output() {
    assert_prompt_interruption(Interruption::CtrlC);
}

#[test]
fn ctrl_d_at_empty_password_prompt_restores_terminal_and_fails_closed() {
    assert_prompt_interruption(Interruption::CtrlD);
}

#[test]
fn sigterm_at_idle_password_prompt_restores_terminal_and_exits_143_without_output() {
    assert_prompt_interruption(Interruption::Sigterm);
}

#[test]
fn pty_encrypt_then_decrypt_hides_password_and_creates_private_exact_output() {
    let directory = tempfile::tempdir().expect("temporary directory should be created");
    let input = directory.path().join("plain.bin");
    let encrypted = directory.path().join("plain.bin.age");
    let decrypted = directory.path().join("round-trip.bin");
    let plaintext: Vec<u8> = (0_u16..=4095)
        .flat_map(u16::to_le_bytes)
        .chain(b"\0binary tail\n".iter().copied())
        .collect();
    let password = b"PTY password never echo 2026!";
    std::fs::write(&input, &plaintext).expect("plaintext fixture should be written");

    let encryption_arguments = [OsStr::new("E"), input.as_os_str(), encrypted.as_os_str()];
    let mut encryption = PtySession::spawn(&encryption_arguments);
    let mut encryption_transcript = Vec::new();

    encryption.wait_for_prompt(PASSWORD_PROMPT, &mut encryption_transcript);
    encryption.assert_password_mode();
    encryption.write_password(password);
    encryption.wait_for_prompt(CONFIRMATION_PROMPT, &mut encryption_transcript);
    encryption.assert_password_mode();
    encryption.write_password(password);
    let encryption_status = encryption.wait_for_exit(ROUND_TRIP_TIMEOUT, "password confirmation");
    encryption.drain_into(&mut encryption_transcript);

    assert_eq!(encryption_status.code(), Some(0));
    encryption.assert_terminal_restored();
    assert!(contains_bytes(&encryption_transcript, PASSWORD_PROMPT));
    assert!(contains_bytes(&encryption_transcript, CONFIRMATION_PROMPT));
    assert!(
        !contains_bytes(&encryption_transcript, password),
        "password appeared in encryption PTY transcript: {:?}",
        String::from_utf8_lossy(&encryption_transcript)
    );
    assert_eq!(
        std::fs::metadata(&encrypted)
            .expect("encrypted output should exist")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_ne!(
        std::fs::read(&encrypted).expect("encrypted output should be readable"),
        plaintext
    );
    drop(encryption);

    let decryption_arguments = [
        OsStr::new("D"),
        encrypted.as_os_str(),
        decrypted.as_os_str(),
    ];
    let mut decryption = PtySession::spawn(&decryption_arguments);
    let mut decryption_transcript = Vec::new();

    decryption.wait_for_prompt(DECRYPTION_PROMPT, &mut decryption_transcript);
    decryption.assert_password_mode();
    decryption.write_password(password);
    let decryption_status = decryption.wait_for_exit(ROUND_TRIP_TIMEOUT, "decryption password");
    decryption.drain_into(&mut decryption_transcript);

    assert_eq!(decryption_status.code(), Some(0));
    decryption.assert_terminal_restored();
    assert!(contains_bytes(&decryption_transcript, DECRYPTION_PROMPT));
    assert!(
        !contains_bytes(&decryption_transcript, password),
        "password appeared in decryption PTY transcript: {:?}",
        String::from_utf8_lossy(&decryption_transcript)
    );
    assert_eq!(
        std::fs::read(&decrypted).expect("decrypted output should be readable"),
        plaintext
    );
    assert_eq!(
        std::fs::metadata(&decrypted)
            .expect("decrypted output should exist")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}
