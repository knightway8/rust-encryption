//! Password acquisition helpers that keep secret buffers zeroized on drop.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use zeroize::Zeroizing;

use crate::x4x::Error;

pub const MAX_PASSWORD_LEN: usize = 1024 * 1024;

/// Read a password file, removing exactly one trailing LF or CRLF.
///
/// Other bytes—including spaces and earlier newlines—are password data.
///
/// # Errors
///
/// Returns an error if the file cannot be read or the normalized password is
/// empty or larger than the configured safety limit.
pub fn read_password_file(path: &Path) -> Result<Zeroizing<Vec<u8>>, Error> {
    let file = File::open(path).map_err(|e| Error::io("cannot open password file", path, e))?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take((MAX_PASSWORD_LEN + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|e| Error::io("cannot read password file", path, e))?;

    if bytes.len() > MAX_PASSWORD_LEN {
        return Err(Error::PasswordTooLarge);
    }
    strip_one_line_ending(&mut bytes);
    validate(&bytes)?;
    Ok(bytes)
}

/// Prompt without terminal echo.
///
/// # Errors
///
/// Returns an error if the terminal cannot provide a password or the entered
/// password is empty or larger than the configured safety limit.
pub fn prompt(prompt: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
    let entered = Zeroizing::new(rpassword::prompt_password(prompt).map_err(|e| {
        Error::io(
            "cannot read password from terminal",
            Path::new("<terminal>"),
            e,
        )
    })?);
    let bytes = Zeroizing::new(entered.as_bytes().to_vec());
    validate(&bytes)?;
    Ok(bytes)
}

pub(crate) fn validate(password: &[u8]) -> Result<(), Error> {
    if password.is_empty() {
        return Err(Error::EmptyPassword);
    }
    if password.len() > MAX_PASSWORD_LEN {
        return Err(Error::PasswordTooLarge);
    }
    Ok(())
}

fn strip_one_line_ending(bytes: &mut Vec<u8>) {
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::NamedTempFile;

    use super::*;

    fn password_file(contents: &[u8]) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(contents).unwrap();
        file
    }

    #[test]
    fn removes_one_lf() {
        let file = password_file(b"correct horse\n");
        assert_eq!(&*read_password_file(file.path()).unwrap(), b"correct horse");
    }

    #[test]
    fn removes_one_crlf() {
        let file = password_file(b"correct horse\r\n");
        assert_eq!(&*read_password_file(file.path()).unwrap(), b"correct horse");
    }

    #[test]
    fn does_not_trim_spaces_or_multiple_newlines() {
        let file = password_file(b" pass \n\n");
        assert_eq!(&*read_password_file(file.path()).unwrap(), b" pass \n");
    }

    #[test]
    fn accepts_non_utf8_password_files() {
        let file = password_file(&[0xff, 0x00, 0x80]);
        assert_eq!(
            &*read_password_file(file.path()).unwrap(),
            &[0xff, 0x00, 0x80]
        );
    }

    #[test]
    fn rejects_empty_password() {
        let file = password_file(b"\n");
        assert!(matches!(
            read_password_file(file.path()),
            Err(Error::EmptyPassword)
        ));
    }

    #[test]
    fn rejects_oversized_password_without_unbounded_read() {
        let file = password_file(&vec![b'x'; MAX_PASSWORD_LEN + 1]);
        assert!(matches!(
            read_password_file(file.path()),
            Err(Error::PasswordTooLarge)
        ));
    }

    #[test]
    fn missing_password_file_has_context() {
        let error = read_password_file(Path::new("definitely-missing-password-file"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("cannot open password file"));
    }

    #[test]
    fn direct_validation_rejects_too_large_password() {
        assert!(matches!(
            validate(&vec![0; MAX_PASSWORD_LEN + 1]),
            Err(Error::PasswordTooLarge)
        ));
    }

    #[test]
    fn empty_file_is_rejected() {
        let file = password_file(b"");
        assert!(matches!(
            read_password_file(file.path()),
            Err(Error::EmptyPassword)
        ));
    }

    #[test]
    fn lone_carriage_return_is_password_data() {
        let file = password_file(b"secret\r");
        assert_eq!(&*read_password_file(file.path()).unwrap(), b"secret\r");
    }

    #[test]
    fn whitespace_only_nonempty_password_is_preserved() {
        let file = password_file(b"   \n");
        assert_eq!(&*read_password_file(file.path()).unwrap(), b"   ");
    }

    #[test]
    fn exact_maximum_password_length_is_accepted() {
        let expected = vec![b'x'; MAX_PASSWORD_LEN];
        let file = password_file(&expected);
        assert_eq!(&*read_password_file(file.path()).unwrap(), &expected);
    }

    #[test]
    fn crlf_only_is_rejected_after_normalization() {
        let file = password_file(b"\r\n");
        assert!(matches!(
            read_password_file(file.path()),
            Err(Error::EmptyPassword)
        ));
    }

    #[test]
    fn embedded_nuls_are_preserved_as_password_bytes() {
        let file = password_file(b"before\0after\n");
        assert_eq!(&*read_password_file(file.path()).unwrap(), b"before\0after");
    }

    #[test]
    fn only_one_of_two_crlf_endings_is_removed() {
        let file = password_file(b"secret\r\n\r\n");
        assert_eq!(&*read_password_file(file.path()).unwrap(), b"secret\r\n");
    }
}
