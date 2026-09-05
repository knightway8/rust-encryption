use crate::{
    error::{Error, IoContext, Result},
    files::Input,
};
use age::secrecy::{ExposeSecret, SecretString};
use std::{io::Read, path::Path};
use zeroize::Zeroizing;

pub const MAX_SECRET_BYTES: usize = 4096;
const MAX_IDENTITY_BYTES: usize = 64 * 1024;

fn read_limited(path: &Path, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    let input = Input::open(path)?;
    // Reserve the entire bounded read to avoid leaving secret copies behind in
    // allocations discarded by Vec growth.
    let mut bytes = Zeroizing::new(Vec::with_capacity(limit + 1));
    (&input.file)
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .context("cannot read secret file")?;
    if bytes.len() > limit {
        return Err(Error::Invalid("secret file exceeds its size limit"));
    }
    input.unchanged()?;
    Ok(bytes)
}

pub fn validate_password(password: &SecretString, encrypting: bool) -> Result<()> {
    let text = password.expose_secret();
    if text.is_empty() || text.len() > MAX_SECRET_BYTES || text.contains(['\r', '\n', '\0']) {
        return Err(Error::Invalid(
            "password must be nonempty, at most 4096 UTF-8 bytes, and contain no NUL or line breaks",
        ));
    }
    if encrypting && text.chars().count() < 12 {
        return Err(Error::Invalid(
            "encryption passwords must contain at least 12 characters; use a long randomly generated passphrase",
        ));
    }
    Ok(())
}

pub fn password_file(path: &Path, encrypting: bool) -> Result<SecretString> {
    let bytes = read_limited(path, MAX_SECRET_BYTES + 2)?;
    let text =
        std::str::from_utf8(&bytes).map_err(|_| Error::Invalid("password file must be UTF-8"))?;
    let text = text
        .strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(text);
    let secret = SecretString::from(text.to_owned());
    validate_password(&secret, encrypting)?;
    Ok(secret)
}

pub fn identities_file(path: &Path) -> Result<Vec<age::x25519::Identity>> {
    let bytes = read_limited(path, MAX_IDENTITY_BYTES)?;
    let text =
        std::str::from_utf8(&bytes).map_err(|_| Error::Invalid("identity file must be UTF-8"))?;
    let mut identities = Vec::new();
    for line in text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        if identities.len() == 32 {
            return Err(Error::Invalid("at most 32 identities are allowed per file"));
        }
        identities.push(line.parse().map_err(|_| {
            Error::Invalid("invalid X25519 identity file (private key is never echoed)")
        })?);
    }
    if identities.is_empty() {
        return Err(Error::Invalid(
            "identity file contains no X25519 private keys",
        ));
    }
    Ok(identities)
}
