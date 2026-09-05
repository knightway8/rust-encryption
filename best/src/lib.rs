//! Streaming age file encryption with transactional, no-overwrite output.
//! Use [`encrypt_file`], [`decrypt_file`], and [`verify_file`] for file operations.
//! The low-level stream APIs may write an authenticated prefix before a later
//! error; callers must discard all output on failure, as the file APIs do.
pub mod cli;
pub mod error;
pub mod files;
mod platform;
pub mod secret;

use age::secrecy::{ExposeSecret, SecretString};
use error::{Error, IoContext, Result};
use files::{Input, Output};
use std::{
    io::{self, BufRead, BufReader, BufWriter, Cursor, Read, Write},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use zeroize::Zeroizing;

pub const PASSWORD_WORK_FACTOR: u8 = 18;
pub const MAX_HEADER_BYTES: usize = 64 * 1024;
pub const MAX_RECIPIENTS: usize = 64;

#[derive(Clone, Default)]
pub struct Operation {
    pub cancelled: Arc<AtomicBool>,
    /// Maximum plaintext bytes allowed. None means no application size limit.
    pub max_bytes: Option<u64>,
}

impl Operation {
    pub fn check(&self) -> Result<()> {
        if self.cancelled.load(Ordering::Relaxed) {
            Err(Error::Cancelled)
        } else {
            Ok(())
        }
    }
}

pub enum Encryption {
    Password(SecretString),
    Recipients(Vec<age::x25519::Recipient>),
}

pub enum Decryption {
    Password {
        password: SecretString,
        max_work_factor: u8,
    },
    Identities(Vec<age::x25519::Identity>),
}

pub fn recipients(values: &[String]) -> Result<Vec<age::x25519::Recipient>> {
    if values.is_empty() || values.len() > MAX_RECIPIENTS {
        return Err(Error::Invalid("specify between 1 and 64 X25519 recipients"));
    }
    let mut seen = std::collections::HashSet::new();
    values
        .iter()
        .map(|s| {
            let recipient: age::x25519::Recipient = s
                .parse()
                .map_err(|_| Error::Invalid("invalid age X25519 recipient"))?;
            if !seen.insert(recipient.to_string()) {
                return Err(Error::Invalid("duplicate recipient"));
            }
            Ok(recipient)
        })
        .collect()
}

fn transfer(mut reader: impl Read, mut writer: impl Write, op: &Operation) -> Result<u64> {
    let mut buffer = Zeroizing::new(vec![0u8; 64 * 1024]);
    let mut total = 0u64;
    loop {
        op.check()?;
        let count = match reader.read(&mut buffer) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            result => result.context("cannot read or authenticate input")?,
        };
        if count == 0 {
            break;
        }
        total = total.checked_add(count as u64).ok_or(Error::Limit)?;
        if op.max_bytes.is_some_and(|limit| total > limit) {
            return Err(Error::Limit);
        }
        op.check()?;
        writer
            .write_all(&buffer[..count])
            .context("cannot write output")?;
    }
    op.check()?;
    writer.flush().context("cannot flush output")?;
    Ok(total)
}

pub fn encrypt_stream(
    input: impl Read,
    output: impl Write,
    method: Encryption,
    op: &Operation,
) -> Result<u64> {
    op.check()?;
    let encryptor = match method {
        Encryption::Password(password) => {
            secret::validate_password(&password, true)?;
            let mut recipient = age::scrypt::Recipient::new(password);
            recipient.set_work_factor(PASSWORD_WORK_FACTOR);
            age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))?
        }
        Encryption::Recipients(recipients) => {
            if recipients.is_empty() || recipients.len() > MAX_RECIPIENTS {
                return Err(Error::Invalid("specify between 1 and 64 X25519 recipients"));
            }
            let unique: std::collections::HashSet<_> =
                recipients.iter().map(ToString::to_string).collect();
            if unique.len() != recipients.len() {
                return Err(Error::Invalid("duplicate recipient"));
            }
            age::Encryptor::with_recipients(recipients.iter().map(|r| r as &dyn age::Recipient))?
        }
    };
    // age's header serializer expects complete writes. Buffering also avoids
    // tiny filesystem writes, while BufWriter handles short writes on flush.
    let mut writer = encryptor
        .wrap_output(BufWriter::with_capacity(64 * 1024, output))
        .context("cannot write encrypted header")?;
    let count = transfer(input, &mut writer, op)?;
    op.check()?;
    writer
        .finish()
        .context("cannot finalize authenticated ciphertext")?
        .flush()
        .context("cannot flush finalized ciphertext")?;
    Ok(count)
}

// Bound header allocation BEFORE handing attacker-controlled data to age. This
// only locates the footer; the age library validates the complete syntax and MAC.
fn bounded_input(input: impl Read, op: &Operation) -> Result<impl Read> {
    let mut input = BufReader::new(input);
    let mut header = Vec::new();
    let mut stanza_ended = true;
    loop {
        op.check()?;
        let start = header.len();
        let left = MAX_HEADER_BYTES - start;
        if left == 0 {
            return Err(Error::Invalid("age header exceeds the 64 KiB limit"));
        }
        let count = (&mut input)
            .take(left as u64)
            .read_until(b'\n', &mut header)
            .context("cannot read age header")?;
        if count == 0 || header.last() != Some(&b'\n') {
            return Err(Error::Invalid(
                "truncated, oversized, or non-binary age header",
            ));
        }
        if start == 0 && &header[..] != b"age-encryption.org/v1\n" {
            return Err(Error::Invalid(
                "expected a binary age v1 file (ASCII armor is not supported)",
            ));
        }
        let line = &header[start..];
        let footer = line.starts_with(b"--- ");
        if footer || line.starts_with(b"-> ") {
            // age also accepts two legacy encodings without a short final body
            // line. Require the canonical v1 grammar, as specified by CCTV.
            if !stanza_ended {
                return Err(Error::Invalid(
                    "age stanza is missing its final short body line",
                ));
            }
            stanza_ended = false;
        } else if start != 0 {
            stanza_ended = line.len() < 65;
        }
        if footer {
            break;
        }
    }
    Ok(Cursor::new(header).chain(input))
}

pub fn decrypt_stream(
    input: impl Read,
    output: impl Write,
    method: Decryption,
    op: &Operation,
) -> Result<u64> {
    op.check()?;
    let decryptor = age::Decryptor::new(bounded_input(input, op)?)?;
    match method {
        Decryption::Password {
            password,
            max_work_factor,
        } => {
            secret::validate_password(&password, false)?;
            if !(1..=20).contains(&max_work_factor) {
                return Err(Error::Invalid(
                    "maximum scrypt work factor must be between 1 and 20",
                ));
            }
            if !decryptor.is_scrypt() {
                return Err(Error::Invalid(
                    "this file requires an identity; use --identity",
                ));
            }
            let mut identity = age::scrypt::Identity::new(password);
            identity.set_max_work_factor(max_work_factor);
            let reader = decryptor.decrypt(std::iter::once(&identity as &dyn age::Identity))?;
            transfer(reader, output, op)
        }
        Decryption::Identities(identities) => {
            if identities.is_empty() || identities.len() > 128 {
                return Err(Error::Invalid("specify between 1 and 128 identities"));
            }
            if decryptor.is_scrypt() {
                return Err(Error::Invalid(
                    "this file requires a password; omit --identity",
                ));
            }
            let reader = decryptor.decrypt(identities.iter().map(|i| i as &dyn age::Identity))?;
            transfer(reader, output, op)
        }
    }
}

pub fn encrypt_file(
    input: &Path,
    output: &Path,
    method: Encryption,
    op: &Operation,
) -> Result<u64> {
    op.check()?;
    let input = Input::open(input)?;
    let mut output = Output::create(output)?;
    let count = encrypt_stream(&input.file, output.file(), method, op)?;
    input.unchanged()?;
    op.check()?;
    output.commit()?;
    Ok(count)
}

pub fn decrypt_file(
    input: &Path,
    output: &Path,
    method: Decryption,
    op: &Operation,
) -> Result<u64> {
    op.check()?;
    let input = Input::open(input)?;
    let mut output = Output::create(output)?;
    let count = decrypt_stream(&input.file, output.file(), method, op)?;
    input.unchanged()?;
    op.check()?;
    output.commit()?;
    Ok(count)
}

pub fn verify_file(input: &Path, method: Decryption, op: &Operation) -> Result<u64> {
    let input = Input::open(input)?;
    let count = decrypt_stream(&input.file, io::sink(), method, op)?;
    input.unchanged()?;
    Ok(count)
}

/// Generates a private identity file. Only the public recipient is returned.
pub fn keygen(output: &Path) -> Result<String> {
    let mut output = Output::create(output)?;
    let identity = age::x25519::Identity::generate();
    let public = identity.to_public().to_string();
    writeln!(
        output.file(),
        "# best X25519 identity\n# public key: {public}\n{}",
        identity.to_string().expose_secret()
    )
    .context("cannot write identity")?;
    output.commit()?;
    Ok(public)
}

#[cfg(test)]
mod tests;
