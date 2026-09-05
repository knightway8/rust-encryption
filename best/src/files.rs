use crate::{
    error::{Error, IoContext, Result},
    platform,
};
use std::{
    fs::{self, File, Metadata},
    path::{Component, Path, PathBuf},
};
use tempfile::NamedTempFile;

pub(crate) fn validate_path(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() || path == Path::new("-") {
        return Err(Error::Invalid(
            "use a regular file path; stdin/stdout streams are not supported",
        ));
    }
    for part in path.components() {
        if let Component::Normal(name) = part {
            let text = name.to_string_lossy();
            if text.contains('\0') {
                return Err(Error::Invalid("NUL in file path"));
            }
            #[cfg(windows)]
            {
                let stem = text
                    .split('.')
                    .next()
                    .unwrap_or("")
                    .trim_end()
                    .to_ascii_uppercase();
                let reserved = ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"]
                    .contains(&stem.as_str())
                    || (stem.starts_with("COM") || stem.starts_with("LPT"))
                        && matches!(
                            &stem[3..],
                            "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                        );
                if reserved
                    || text.contains(':')
                    || text.ends_with(['.', ' '])
                    || text.chars().any(|c| c < ' ' || "<>\"|?*".contains(c))
                {
                    return Err(Error::Invalid(
                        "unsupported Windows path: device names, alternate streams, and ambiguous names are refused",
                    ));
                }
            }
        }
        #[cfg(windows)]
        if let Component::Prefix(prefix) = part {
            use std::path::Prefix;
            if !matches!(
                prefix.kind(),
                Prefix::Disk(_)
                    | Prefix::UNC(_, _)
                    | Prefix::VerbatimDisk(_)
                    | Prefix::VerbatimUNC(_, _)
            ) {
                return Err(Error::Invalid("Windows device namespace paths are refused"));
            }
        }
    }
    Ok(())
}

pub(crate) struct Input {
    pub file: File,
    initial: Metadata,
}

impl Input {
    pub fn open(path: &Path) -> Result<Self> {
        validate_path(path)?;
        if fs::symlink_metadata(path)
            .context("cannot inspect input")?
            .file_type()
            .is_symlink()
        {
            return Err(Error::Invalid(
                "symbolic-link inputs are refused; use the actual file path",
            ));
        }
        let file = platform::open_input(path).context("cannot open regular input file")?;
        let initial = file.metadata().context("cannot inspect open input")?;
        Ok(Self { file, initial })
    }

    pub fn unchanged(&self) -> Result<()> {
        let now = self.file.metadata().context("cannot recheck input")?;
        if now.len() != self.initial.len() || now.modified().ok() != self.initial.modified().ok() {
            return Err(Error::Invalid(
                "input changed during operation; destination was not published",
            ));
        }
        Ok(())
    }
}

/// A same-directory transaction. Never replaces a destination, even in a race.
pub(crate) struct Output {
    temp: NamedTempFile,
    destination: PathBuf,
    parent: PathBuf,
}

impl Output {
    pub fn create(destination: &Path) -> Result<Self> {
        validate_path(destination)?;
        let name = destination
            .file_name()
            .ok_or(Error::Invalid("output needs a file name"))?;
        let parent = destination
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let parent = fs::canonicalize(parent).context("output directory must already exist")?;
        let destination = parent.join(name);
        match fs::symlink_metadata(&destination) {
            Ok(_) => {
                return Err(Error::Invalid(
                    "output already exists; choose a new path (overwriting is never allowed)",
                ));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(Error::Io {
                    action: "cannot inspect output",
                    source,
                });
            }
        }
        let temp = tempfile::Builder::new()
            .prefix(".best-tmp-")
            .rand_bytes(16)
            .make_in(&parent, platform::create_private)
            .context("cannot create private temporary output")?;
        Ok(Self {
            temp,
            destination,
            parent,
        })
    }

    pub fn file(&mut self) -> &mut File {
        self.temp.as_file_mut()
    }

    pub fn commit(self) -> Result<()> {
        self.temp
            .as_file()
            .sync_all()
            .context("cannot synchronize output before publishing")?;
        self.temp
            .persist_noclobber(&self.destination)
            .map_err(|e| Error::Io {
                action: "cannot publish output without overwriting",
                source: e.error,
            })?;
        // A directory sync is required for rename durability on Unix. If it fails,
        // report explicitly that the already-complete destination may exist.
        #[cfg(unix)]
        File::open(&self.parent)
            .and_then(|f| f.sync_all())
            .context("output published, but directory synchronization failed")?;
        #[cfg(windows)]
        let _ = self.parent;
        Ok(())
    }
}

pub fn encrypted_path(input: &Path) -> PathBuf {
    let mut name = input.as_os_str().to_owned();
    name.push(".age");
    PathBuf::from(name)
}

pub fn decrypted_path(input: &Path) -> Result<PathBuf> {
    if input.extension().is_some_and(|ext| ext == "age") {
        Ok(input.with_extension(""))
    } else {
        Err(Error::Invalid(
            "input does not end in .age; specify --output explicitly",
        ))
    }
}
