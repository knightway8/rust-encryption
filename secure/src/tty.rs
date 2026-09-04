use std::{
    fs::File,
    io::{self, Read, Write},
};

use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    fs::{Mode, OFlags, open},
    io::Errno,
    termios::{LocalModes, OptionalActions, SpecialCodeIndex, Termios, tcgetattr, tcsetattr},
};

use age::secrecy::SecretString;

use crate::{Cancellation, Error, Operation, read_password};

const TTY_PATH: &str = "/dev/tty";
const POLL_INTERVAL: Timespec = Timespec {
    tv_sec: 0,
    tv_nsec: 50_000_000,
};
const MAX_RAW_PASSWORD_INPUT: usize = 16 * 1024;

/// Reads and validates the required password from the controlling terminal.
///
/// Terminal echo is disabled before the first prompt and remains disabled
/// through encryption confirmation. The terminal is polled so a handled
/// termination signal can restore its original mode promptly even when no
/// input bytes arrive.
///
/// # Errors
///
/// Returns [`Error::PasswordInput`] if the controlling terminal cannot be
/// opened, configured, read, written, or restored, or [`Error::Interrupted`]
/// if cancellation was requested.
pub fn read_password_from_terminal(
    operation: Operation,
    cancellation: &Cancellation,
) -> Result<SecretString, Error> {
    if cancellation.is_cancelled() {
        return Err(Error::Interrupted);
    }

    let mut terminal = PasswordTerminal::open(cancellation).map_err(Error::PasswordInput)?;
    let password_result = read_password(operation, |prompt| terminal.prompt(prompt));
    let restore_result = terminal.restore();

    restore_result.map_err(Error::PasswordInput)?;
    if cancellation.is_cancelled() {
        Err(Error::Interrupted)
    } else {
        password_result
    }
}

struct PasswordTerminal {
    terminal: File,
    guard: TerminalModeGuard,
    cancellation: Cancellation,
}

impl PasswordTerminal {
    fn open(cancellation: &Cancellation) -> io::Result<Self> {
        check_cancellation(cancellation)?;
        let terminal_fd = open(
            TTY_PATH,
            OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(io::Error::from)?;
        let terminal = File::from(terminal_fd);
        let guard = TerminalModeGuard::hide(&terminal)?;
        Ok(Self {
            terminal,
            guard,
            cancellation: cancellation.clone(),
        })
    }

    fn prompt(&mut self, prompt: &str) -> io::Result<String> {
        write_cancellable(&mut self.terminal, prompt.as_bytes(), &self.cancellation)?;
        let reader = CancellableTtyReader {
            terminal: self.terminal.try_clone()?,
            cancellation: self.cancellation.clone(),
            bytes_read: 0,
        };
        let config = rpassword::ConfigBuilder::new()
            .input_reader(reader)
            .output_discard()
            .build();
        let result = rpassword::read_password_with_config(config);

        // Keep the next prompt or diagnostic on its own line. This is best
        // effort so a cancellation error is not hidden by terminal output.
        let _ = self.terminal.write_all(b"\n");
        let _ = self.terminal.flush();
        result
    }

    fn restore(&mut self) -> io::Result<()> {
        self.guard.restore()
    }
}

struct TerminalModeGuard {
    terminal: File,
    original: Termios,
    active: bool,
}

impl TerminalModeGuard {
    fn hide(terminal: &File) -> io::Result<Self> {
        let original = tcgetattr(terminal).map_err(io::Error::from)?;
        let mut hidden = original.clone();
        hidden
            .local_modes
            .remove(LocalModes::ECHO | LocalModes::ECHONL | LocalModes::ICANON | LocalModes::ISIG);
        hidden.special_codes[SpecialCodeIndex::VMIN] = 1;
        hidden.special_codes[SpecialCodeIndex::VTIME] = 0;

        let guard = Self {
            terminal: terminal.try_clone()?,
            original,
            active: true,
        };
        if let Err(error) = tcsetattr(&guard.terminal, OptionalActions::Now, &hidden) {
            let _ = tcsetattr(&guard.terminal, OptionalActions::Now, &guard.original);
            return Err(io::Error::from(error));
        }
        Ok(guard)
    }

    fn restore(&mut self) -> io::Result<()> {
        if self.active {
            tcsetattr(&self.terminal, OptionalActions::Now, &self.original)
                .map_err(io::Error::from)?;
            self.active = false;
        }
        Ok(())
    }
}

impl Drop for TerminalModeGuard {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

struct CancellableTtyReader {
    terminal: File,
    cancellation: Cancellation,
    bytes_read: usize,
}

impl Read for CancellableTtyReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.bytes_read >= MAX_RAW_PASSWORD_INPUT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "password input exceeded the safety limit",
            ));
        }

        loop {
            check_cancellation(&self.cancellation)?;
            let events = poll_one(&self.terminal, PollFlags::IN)?;
            if events.contains(PollFlags::IN) {
                let maximum = buffer.len().min(MAX_RAW_PASSWORD_INPUT - self.bytes_read);
                match self.terminal.read(&mut buffer[..maximum]) {
                    Ok(0) => {
                        return Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "controlling terminal closed during password input",
                        ));
                    }
                    Ok(read) => {
                        self.bytes_read += read;
                        return Ok(read);
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                        ) => {}
                    Err(error) => return Err(error),
                }
            } else if events.intersects(PollFlags::ERR | PollFlags::HUP | PollFlags::NVAL) {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "controlling terminal closed during password input",
                ));
            }
        }
    }
}

fn write_cancellable(
    output: &mut File,
    mut bytes: &[u8],
    cancellation: &Cancellation,
) -> io::Result<()> {
    while !bytes.is_empty() {
        check_cancellation(cancellation)?;
        let events = poll_one(output, PollFlags::OUT)?;
        if events.contains(PollFlags::OUT) {
            match output.write(bytes) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "could not write the password prompt",
                    ));
                }
                Ok(written) => bytes = &bytes[written..],
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                    ) => {}
                Err(error) => return Err(error),
            }
        } else if events.intersects(PollFlags::ERR | PollFlags::HUP | PollFlags::NVAL) {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "controlling terminal closed while writing the password prompt",
            ));
        }
    }
    output.flush()
}

fn poll_one(file: &File, events: PollFlags) -> io::Result<PollFlags> {
    let mut descriptors = [PollFd::new(file, events)];
    match poll(&mut descriptors, Some(&POLL_INTERVAL)) {
        Ok(_) => Ok(descriptors[0].revents()),
        Err(Errno::INTR) => Ok(PollFlags::empty()),
        Err(error) => Err(io::Error::from(error)),
    }
}

fn check_cancellation(cancellation: &Cancellation) -> io::Result<()> {
    if cancellation.is_cancelled() {
        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "operation interrupted",
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use rustix::pty::{self, OpenptFlags};

    use super::*;

    #[test]
    fn cancelled_password_session_fails_before_opening_a_terminal() {
        let cancellation = Cancellation::never();
        cancellation.cancel_for_test();

        assert!(matches!(
            read_password_from_terminal(Operation::Decrypt, &cancellation),
            Err(Error::Interrupted)
        ));
    }

    #[test]
    fn cancellation_check_has_a_stable_error_kind() {
        let cancellation = Cancellation::never();
        assert!(check_cancellation(&cancellation).is_ok());
        cancellation.cancel_for_test();
        assert_eq!(
            check_cancellation(&cancellation).unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
    }

    #[test]
    fn pseudo_terminal_hangup_is_never_accepted_as_a_partial_password() {
        let master =
            pty::openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC).unwrap();
        pty::grantpt(&master).unwrap();
        pty::unlockpt(&master).unwrap();
        let slave = pty::ioctl_tiocgptpeer(
            &master,
            OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC,
        )
        .unwrap();
        let mut reader = CancellableTtyReader {
            terminal: File::from(slave),
            cancellation: Cancellation::never(),
            bytes_read: 0,
        };
        drop(master);

        let error = reader.read(&mut [0_u8; 1]).unwrap_err();
        assert_ne!(error.kind(), io::ErrorKind::UnexpectedEof);
    }
}
