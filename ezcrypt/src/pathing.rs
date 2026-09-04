use crate::error::EzError;
use std::ffi::OsString;
use std::io;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, Path, PathBuf, Prefix};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    Encrypt,
    Decrypt,
}

impl Operation {
    pub fn past_tense(self) -> &'static str {
        match self {
            Self::Encrypt => "Encrypted",
            Self::Decrypt => "Decrypted",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransformPlan {
    input: PathBuf,
    output: PathBuf,
    operation: Operation,
}

impl TransformPlan {
    pub fn input(&self) -> &Path {
        &self.input
    }

    pub fn output(&self) -> &Path {
        &self.output
    }

    pub fn operation(&self) -> Operation {
        self.operation
    }
}

pub fn plan_for_path(path: impl AsRef<Path>) -> Result<TransformPlan, EzError> {
    let path = path.as_ref();
    if path.as_os_str().is_empty() {
        return Err(EzError::InvalidPath("path is empty"));
    }
    validate_lexical_components(path)?;
    let input = std::path::absolute(path)
        .map_err(|source| EzError::io("resolve the absolute path for", path, source))?;
    match input.components().next() {
        Some(Component::Prefix(prefix))
            if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)) => {}
        _ => {
            return Err(EzError::InvalidPath(
                "only local drive-letter paths are supported",
            ));
        }
    }
    let file_name = input
        .file_name()
        .ok_or(EzError::InvalidPath("path has no file name"))?;
    let units: Vec<u16> = file_name.encode_wide().collect();
    if units.is_empty() {
        return Err(EzError::InvalidPath("file name is empty"));
    }
    if units.len() > 255 {
        return Err(EzError::InvalidPath("file name exceeds 255 UTF-16 units"));
    }
    if units.contains(&(b':' as u16)) {
        return Err(EzError::AlternateDataStream(input));
    }

    let encrypted_suffix = ends_with_ez(&units);
    let (operation, output_name) = if encrypted_suffix {
        if units.len() == 3 {
            return Err(EzError::InvalidPath(
                "decrypting a file named only .ez would produce an empty name",
            ));
        }
        (
            Operation::Decrypt,
            OsString::from_wide(&units[..units.len() - 3]),
        )
    } else {
        let mut output = units;
        output.extend([b'.' as u16, b'e' as u16, b'z' as u16]);
        if output.len() > 255 {
            return Err(EzError::InvalidPath(
                "encrypted file name would exceed 255 UTF-16 units",
            ));
        }
        (Operation::Encrypt, OsString::from_wide(&output))
    };

    let output_units: Vec<u16> = output_name.encode_wide().collect();
    validate_output_name(&output_units)?;

    let output = input.with_file_name(output_name);
    Ok(TransformPlan {
        input,
        output,
        operation,
    })
}

fn validate_lexical_components(path: &Path) -> Result<(), EzError> {
    for component in path.components() {
        match component {
            Component::ParentDir => {
                return Err(EzError::InvalidPath(
                    "parent-directory components are not allowed",
                ));
            }
            Component::Normal(value) => {
                let units: Vec<u16> = value.encode_wide().collect();
                if units.is_empty() || units.contains(&0) {
                    return Err(EzError::InvalidPath(
                        "path component is empty or contains NUL",
                    ));
                }
                if units.len() > 255 {
                    return Err(EzError::InvalidPath(
                        "path component exceeds 255 UTF-16 units",
                    ));
                }
                if matches!(units.last(), Some(unit) if *unit == b'.' as u16 || *unit == b' ' as u16)
                {
                    return Err(EzError::InvalidPath(
                        "path components ending in a dot or space are ambiguous on Windows",
                    ));
                }
                if units.iter().any(|unit| {
                    *unit < 32
                        || matches!(
                            *unit,
                            x if x == b'<' as u16
                                || x == b'>' as u16
                                || x == b':' as u16
                                || x == b'\"' as u16
                                || x == b'|' as u16
                                || x == b'?' as u16
                                || x == b'*' as u16
                        )
                }) {
                    return Err(EzError::InvalidPath(
                        "path contains a character reserved by Windows",
                    ));
                }
                if is_reserved_dos_name(&units) {
                    return Err(EzError::InvalidPath(
                        "path contains a reserved Windows device name",
                    ));
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn validate_output_name(units: &[u16]) -> Result<(), EzError> {
    if units.is_empty() {
        return Err(EzError::InvalidPath(
            "decryption would produce an empty file name",
        ));
    }
    if units.len() > 255 {
        return Err(EzError::InvalidPath(
            "output file name exceeds 255 UTF-16 units",
        ));
    }
    if matches!(units.last(), Some(unit) if *unit == b'.' as u16 || *unit == b' ' as u16) {
        return Err(EzError::InvalidPath(
            "output file name would end in a dot or space",
        ));
    }
    if is_reserved_dos_name(units) {
        return Err(EzError::InvalidPath(
            "output would use a reserved Windows device name",
        ));
    }
    Ok(())
}

fn is_reserved_dos_name(units: &[u16]) -> bool {
    let stem_end = units
        .iter()
        .position(|unit| *unit == b'.' as u16)
        .unwrap_or(units.len());
    let stem: Vec<u16> = units[..stem_end].iter().copied().map(ascii_lower).collect();
    stem.as_slice() == [b'c' as u16, b'o' as u16, b'n' as u16]
        || stem.as_slice() == [b'p' as u16, b'r' as u16, b'n' as u16]
        || stem.as_slice() == [b'a' as u16, b'u' as u16, b'x' as u16]
        || stem.as_slice() == [b'n' as u16, b'u' as u16, b'l' as u16]
        || stem.as_slice()
            == [
                b'c' as u16,
                b'l' as u16,
                b'o' as u16,
                b'c' as u16,
                b'k' as u16,
                b'$' as u16,
            ]
        || (stem.len() == 4
            && (stem[..3] == [b'c' as u16, b'o' as u16, b'm' as u16]
                || stem[..3] == [b'l' as u16, b'p' as u16, b't' as u16])
            && is_reserved_device_number(stem[3]))
}

fn is_reserved_device_number(unit: u16) -> bool {
    (b'1' as u16..=b'9' as u16).contains(&unit)
        // Win32 also treats the ISO-8859-1 superscript digits 1, 2, and 3 as
        // device-number suffixes, so COM¹ and LPT² are reserved too.
        || matches!(unit, 0x00b9 | 0x00b2 | 0x00b3)
}

pub(crate) fn ensure_destination_absent(path: &Path) -> Result<(), EzError> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Err(EzError::DestinationExists(path.to_path_buf())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(EzError::io("inspect destination", path, source)),
    }
}

fn ends_with_ez(units: &[u16]) -> bool {
    if units.len() < 3 || units[units.len() - 3] != b'.' as u16 {
        return false;
    }
    ascii_lower(units[units.len() - 2]) == b'e' as u16
        && ascii_lower(units[units.len() - 1]) == b'z' as u16
}

fn ascii_lower(unit: u16) -> u16 {
    if (b'A' as u16..=b'Z' as u16).contains(&unit) {
        unit + u16::from(b'a' - b'A')
    } else {
        unit
    }
}
