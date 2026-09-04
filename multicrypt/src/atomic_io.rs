use std::io::{self, Write};
use std::path::Path;

#[cfg(any(unix, test))]
use std::fs;

#[derive(Debug)]
pub(crate) enum AtomicWriteError {
    AlreadyExists,
    Io(io::Error),
    #[cfg(unix)]
    PublishedButNotDurable(io::Error),
}

impl From<io::Error> for AtomicWriteError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

pub(crate) fn write_noclobber(
    destination: &Path,
    contents: &[u8],
    owner_only: bool,
) -> Result<(), AtomicWriteError> {
    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    let mut temporary = tempfile::Builder::new()
        .prefix(".multicrypt-")
        .tempfile_in(parent)?;

    #[cfg(unix)]
    if owner_only {
        use std::os::unix::fs::PermissionsExt;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    let _ = owner_only;

    temporary.write_all(contents)?;
    temporary.flush()?;
    temporary.as_file().sync_all()?;

    match temporary.persist_noclobber(destination) {
        Ok(_) => {}
        Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => {
            return Err(AtomicWriteError::AlreadyExists);
        }
        Err(error) => return Err(AtomicWriteError::Io(error.error)),
    }

    #[cfg(unix)]
    if let Err(error) = fs::File::open(parent).and_then(|directory| directory.sync_all()) {
        return Err(AtomicWriteError::PublishedButNotDurable(error));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publish_is_no_clobber() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("output.bin");

        write_noclobber(&output, b"first", false).unwrap();
        assert!(matches!(
            write_noclobber(&output, b"second", false),
            Err(AtomicWriteError::AlreadyExists)
        ));
        assert_eq!(fs::read(output).unwrap(), b"first");
    }

    #[test]
    fn failed_publish_leaves_no_temporary_file() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("output.bin");
        fs::write(&output, b"existing").unwrap();
        assert!(write_noclobber(&output, b"new", false).is_err());

        let names: Vec<_> = fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, [std::ffi::OsString::from("output.bin")]);
    }

    #[test]
    fn concurrent_publishers_never_clobber() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("race.bin");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let mut handles = Vec::new();
        for value in 0_u8..8 {
            let output = output.clone();
            let barrier = barrier.clone();
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                (value, write_noclobber(&output, &[value], false))
            }));
        }

        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert_eq!(
            results.iter().filter(|(_, result)| result.is_ok()).count(),
            1
        );
        assert!(results.iter().all(|(_, result)| {
            result.is_ok() || matches!(result, Err(AtomicWriteError::AlreadyExists))
        }));

        let stored = fs::read(output).unwrap();
        assert_eq!(stored.len(), 1);
        assert!(
            results
                .iter()
                .any(|(value, result)| result.is_ok() && stored[0] == *value)
        );
    }
}
