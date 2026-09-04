use std::{
    io::{self, Read},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use signal_hook::{
    consts::{SIGHUP, SIGINT, SIGQUIT, SIGTERM},
    flag,
};

use crate::Error;

#[derive(Clone, Debug)]
pub struct Cancellation {
    signal: Arc<AtomicUsize>,
}

impl Cancellation {
    pub(crate) fn never() -> Self {
        Self {
            signal: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Installs graceful first-signal handlers for common termination signals.
    ///
    /// A handled signal requests cleanup and prevents publication when it is
    /// observed before the atomic commit point. `SIGKILL` remains available
    /// for immediate, non-cleanup termination.
    ///
    /// # Errors
    ///
    /// Returns [`Error::SignalHandler`] if a handler cannot be registered.
    pub fn install() -> Result<Self, Error> {
        let cancellation = Self::never();
        for signal in [SIGINT, SIGTERM, SIGHUP, SIGQUIT] {
            let signal_value = usize::try_from(signal).map_err(|_| {
                Error::SignalHandler(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Linux termination signals must be positive",
                ))
            })?;
            flag::register_usize(signal, Arc::clone(&cancellation.signal), signal_value)
                .map_err(Error::SignalHandler)?;
        }
        Ok(cancellation)
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.signal.load(Ordering::SeqCst) != 0
    }

    #[must_use]
    /// Returns the conventional `128 + signal` exit code, or `None` before a
    /// signal has been observed.
    pub fn exit_code(&self) -> Option<u8> {
        let signal = self.signal.load(Ordering::SeqCst);
        if signal == 0 {
            None
        } else {
            u8::try_from(128_usize.saturating_add(signal)).ok()
        }
    }

    pub(crate) fn check(&self) -> Result<(), Error> {
        if self.is_cancelled() {
            Err(Error::Interrupted)
        } else {
            Ok(())
        }
    }

    #[cfg(test)]
    pub(crate) fn cancel_for_test(&self) {
        self.signal
            .store(usize::try_from(SIGINT).unwrap(), Ordering::SeqCst);
    }
}

pub(crate) struct CancelReader<'a, R> {
    inner: R,
    cancellation: &'a Cancellation,
}

impl<'a, R> CancelReader<'a, R> {
    pub(crate) const fn new(inner: R, cancellation: &'a Cancellation) -> Self {
        Self {
            inner,
            cancellation,
        }
    }

    pub(crate) const fn get_ref(&self) -> &R {
        &self.inner
    }
}

impl<R: Read> Read for CancelReader<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.cancellation.is_cancelled() {
            return Err(io::Error::other("operation interrupted"));
        }
        self.inner.read(buffer)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn fresh_cancellation_is_inactive() {
        let cancellation = Cancellation::never();
        assert!(!cancellation.is_cancelled());
        assert!(cancellation.check().is_ok());
        assert_eq!(cancellation.exit_code(), None);
    }

    #[test]
    fn cancelled_reader_stops_before_consuming_bytes() {
        let cancellation = Cancellation::never();
        cancellation.cancel_for_test();
        let mut reader = CancelReader::new(Cursor::new(b"secret"), &cancellation);
        let mut output = Vec::new();

        let error = reader.read_to_end(&mut output).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(output.is_empty());
        assert_eq!(cancellation.exit_code(), Some(130));
    }
}
