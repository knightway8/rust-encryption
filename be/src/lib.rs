#![forbid(unsafe_code)]

use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;

use age::secrecy::ExposeSecret;
use age::x25519::{Identity, Recipient};
use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

pub const SECRET_KEY_FILE: &str = "key.key";
pub const PUBLIC_KEY_FILE: &str = "key.pub";
const MAX_KEY_FILE_SIZE: u64 = 4096;
const IO_BUFFER_SIZE: usize = 1024 * 1024;

pub fn keygen_in(directory: &Path) -> Result<String> {
    ensure_directory(directory)?;
    let secret_path = directory.join(SECRET_KEY_FILE);
    let public_path = directory.join(PUBLIC_KEY_FILE);
    ensure_absent(&secret_path, "secret key")?;
    ensure_absent(&public_path, "public key")?;

    let identity = Identity::generate();
    let recipient = identity.to_public().to_string();
    let encoded_identity = identity.to_string();

    let mut secret_temp = private_tempfile(directory)?;
    writeln!(secret_temp, "{}", encoded_identity.expose_secret())
        .context("could not write the temporary secret key")?;
    secret_temp
        .as_file()
        .sync_all()
        .context("could not sync the temporary secret key")?;

    let mut public_temp = private_tempfile(directory)?;
    writeln!(public_temp, "{recipient}").context("could not write the temporary public key")?;
    public_temp
        .as_file()
        .sync_all()
        .context("could not sync the temporary public key")?;

    persist_noclobber(public_temp, &public_path, "public key")?;
    if let Err(error) = persist_noclobber(secret_temp, &secret_path, "secret key") {
        let _ = fs::remove_file(&public_path);
        let _ = sync_directory(directory);
        return Err(error);
    }
    sync_directory(directory)?;
    Ok(recipient)
}

pub fn encrypt_in(directory: &Path, input_name: &Path, output_name: &Path) -> Result<u64> {
    ensure_directory(directory)?;
    let (input_path, output_path) = data_paths(directory, input_name, output_name)?;
    ensure_absent(&output_path, "output")?;
    let recipient = load_recipient(directory)?;

    let input = open_regular_file(&input_path, "input")?;
    let mut input = BufReader::with_capacity(IO_BUFFER_SIZE, input);
    let temporary = private_tempfile(directory)?;
    let output = BufWriter::with_capacity(IO_BUFFER_SIZE, temporary);

    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
            .context("could not initialize age encryption")?;
    let mut encrypted = encryptor
        .wrap_output(output)
        .context("could not write the age header")?;
    let bytes = io::copy(&mut input, &mut encrypted).context("file encryption failed")?;
    let mut output = encrypted
        .finish()
        .context("could not finish the authenticated age stream")?;
    output.flush().context("could not flush encrypted output")?;
    output
        .get_ref()
        .as_file()
        .sync_all()
        .context("could not sync encrypted output")?;
    let temporary = output
        .into_inner()
        .map_err(|error| error.into_error())
        .context("could not finalize encrypted output")?;
    persist_noclobber(temporary, &output_path, "output")?;
    sync_directory(directory)?;
    Ok(bytes)
}

pub fn decrypt_in(directory: &Path, input_name: &Path, output_name: &Path) -> Result<u64> {
    ensure_directory(directory)?;
    let (input_path, output_path) = data_paths(directory, input_name, output_name)?;
    ensure_absent(&output_path, "output")?;
    let identity = load_identity(directory)?;

    // Authenticate before creating a plaintext file.
    let first = decrypt_and_hash(&input_path, &identity, io::sink())?;

    // Re-authenticate while writing privately. Matching hashes detect replacement
    // of the input between passes, even if the replacement is itself a valid file.
    let temporary = private_tempfile(directory)?;
    let output = BufWriter::with_capacity(IO_BUFFER_SIZE, temporary);
    let second = decrypt_and_hash(&input_path, &identity, output)?;
    if first.bytes != second.bytes || first.digest != second.digest {
        bail!("input changed between authentication and decryption; no output was created");
    }

    let mut output = second.inner;
    output.flush().context("could not flush decrypted output")?;
    output
        .get_ref()
        .as_file()
        .sync_all()
        .context("could not sync decrypted output")?;
    let temporary = output
        .into_inner()
        .map_err(|error| error.into_error())
        .context("could not finalize decrypted output")?;
    persist_noclobber(temporary, &output_path, "output")?;
    sync_directory(directory)?;
    Ok(first.bytes)
}

pub fn verify_in(directory: &Path, input_name: &Path) -> Result<u64> {
    ensure_directory(directory)?;
    let input_path = directory.join(bare_name(input_name, "input")?);
    reject_key_name(input_name)?;
    let identity = load_identity(directory)?;
    Ok(decrypt_and_hash(&input_path, &identity, io::sink())?.bytes)
}

pub fn public_key_in(directory: &Path) -> Result<String> {
    let identity = load_identity(directory)?;
    let derived = identity.to_public();
    let public_path = directory.join(PUBLIC_KEY_FILE);
    match fs::symlink_metadata(&public_path) {
        Ok(_) => {
            let stored = parse_recipient(&read_key_text(&public_path, false)?, &public_path)?;
            if stored != derived {
                bail!("key.pub does not match key.key");
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("could not inspect key.pub"),
    }
    Ok(derived.to_string())
}

fn load_recipient(directory: &Path) -> Result<Recipient> {
    let public_path = directory.join(PUBLIC_KEY_FILE);
    let recipient = parse_recipient(&read_key_text(&public_path, false)?, &public_path)?;

    let secret_path = directory.join(SECRET_KEY_FILE);
    match fs::symlink_metadata(&secret_path) {
        Ok(_) => {
            let identity = load_identity(directory)?;
            if identity.to_public() != recipient {
                bail!("key.pub does not match key.key; refusing to encrypt to the wrong key");
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("could not inspect key.key"),
    }
    Ok(recipient)
}

fn load_identity(directory: &Path) -> Result<Identity> {
    let path = directory.join(SECRET_KEY_FILE);
    let metadata = fs::symlink_metadata(&path)
        .with_context(|| format!("could not inspect secret key {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        bail!("secret key must not be a symbolic link: {}", path.display());
    }
    check_private_permissions(&path)?;
    let text = read_key_text(&path, true)?;
    Identity::from_str(single_token(&text, &path)?)
        .map_err(|error| anyhow::anyhow!("invalid age identity in {}: {error}", path.display()))
}

fn parse_recipient(text: &str, path: &Path) -> Result<Recipient> {
    Recipient::from_str(single_token(text, path)?)
        .map_err(|error| anyhow::anyhow!("invalid age recipient in {}: {error}", path.display()))
}

fn single_token<'a>(text: &'a str, path: &Path) -> Result<&'a str> {
    let mut tokens = text.split_whitespace();
    let token = tokens
        .next()
        .with_context(|| format!("{} is empty", path.display()))?;
    if tokens.next().is_some() {
        bail!("{} must contain exactly one key", path.display());
    }
    Ok(token)
}

fn read_key_text(path: &Path, private: bool) -> Result<String> {
    let file = open_regular_file(path, if private { "secret key" } else { "public key" })?;
    let length = file.metadata().context("could not inspect key file")?.len();
    if length > MAX_KEY_FILE_SIZE {
        bail!("key file is unexpectedly large: {}", path.display());
    }
    let mut text = String::with_capacity(length as usize);
    file.take(MAX_KEY_FILE_SIZE + 1)
        .read_to_string(&mut text)
        .with_context(|| format!("{} is not valid UTF-8", path.display()))?;
    if text.len() as u64 > MAX_KEY_FILE_SIZE {
        bail!("key file is unexpectedly large: {}", path.display());
    }
    Ok(text)
}

struct Decryption<W> {
    inner: W,
    digest: [u8; 32],
    bytes: u64,
}

fn decrypt_and_hash<W: Write>(
    path: &Path,
    identity: &Identity,
    output: W,
) -> Result<Decryption<W>> {
    let input = open_regular_file(path, "encrypted input")?;
    let input = BufReader::with_capacity(IO_BUFFER_SIZE, input);
    let decryptor = age::Decryptor::new_buffered(input)
        .with_context(|| format!("{} is not a valid age file", path.display()))?;
    if decryptor.is_scrypt() {
        bail!("passphrase-encrypted age files are not supported by this key-based app");
    }
    let mut plaintext = decryptor
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .context("age identity did not match or the header was corrupted")?;
    let mut hashing = HashingWriter::new(output);
    io::copy(&mut plaintext, &mut hashing)
        .context("authentication failed: ciphertext is corrupted or truncated")?;
    hashing.flush().context("could not flush plaintext")?;
    Ok(hashing.finish())
}

struct HashingWriter<W> {
    inner: W,
    hasher: Sha256,
    bytes: u64,
}

impl<W> HashingWriter<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
            bytes: 0,
        }
    }

    fn finish(self) -> Decryption<W> {
        Decryption {
            inner: self.inner,
            digest: self.hasher.finalize().into(),
            bytes: self.bytes,
        }
    }
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(buffer)?;
        self.hasher.update(&buffer[..written]);
        self.bytes = self.bytes.checked_add(written as u64).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "plaintext length exceeds u64")
        })?;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn data_paths(directory: &Path, input: &Path, output: &Path) -> Result<(PathBuf, PathBuf)> {
    let input_name = bare_name(input, "input")?;
    let output_name = bare_name(output, "output")?;
    if names_equal(input_name, output_name) {
        bail!("input and output must have different file names");
    }
    reject_key_name(input)?;
    reject_key_name(output)?;
    Ok((directory.join(input_name), directory.join(output_name)))
}

fn reject_key_name(path: &Path) -> Result<()> {
    let name = bare_name(path, "file")?;
    if names_equal(name, OsStr::new(SECRET_KEY_FILE))
        || names_equal(name, OsStr::new(PUBLIC_KEY_FILE))
    {
        bail!("key files cannot be used as input or output data files");
    }
    Ok(())
}

fn bare_name<'a>(path: &'a Path, role: &str) -> Result<&'a OsStr> {
    let mut components = path.components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(name)), None) => Ok(name),
        _ => bail!(
            "{role} must be a bare file name beside the executable, not a path: {}",
            path.display()
        ),
    }
}

fn names_equal(left: &OsStr, right: &OsStr) -> bool {
    left.to_string_lossy()
        .eq_ignore_ascii_case(&right.to_string_lossy())
}

fn ensure_directory(path: &Path) -> Result<()> {
    if !path
        .metadata()
        .with_context(|| format!("could not inspect directory {}", path.display()))?
        .is_dir()
    {
        bail!("not a directory: {}", path.display());
    }
    Ok(())
}

fn ensure_absent(path: &Path, role: &str) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => bail!(
            "{role} already exists; refusing to overwrite {}",
            path.display()
        ),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("could not inspect {}", path.display())),
    }
}

fn open_regular_file(path: &Path, role: &str) -> Result<File> {
    let file =
        File::open(path).with_context(|| format!("could not open {role} {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("could not inspect {role} {}", path.display()))?;
    if !metadata.is_file() {
        bail!("{role} is not a regular file: {}", path.display());
    }
    Ok(file)
}

fn private_tempfile(directory: &Path) -> Result<tempfile::NamedTempFile> {
    tempfile::Builder::new()
        .prefix(".be-")
        .tempfile_in(directory)
        .with_context(|| {
            format!(
                "could not create a temporary file in {}",
                directory.display()
            )
        })
}

fn persist_noclobber(
    temporary: tempfile::NamedTempFile,
    destination: &Path,
    role: &str,
) -> Result<()> {
    temporary.persist_noclobber(destination).map_err(|error| {
        anyhow::anyhow!(
            "could not create {role} {} without overwriting an existing file: {}",
            destination.display(),
            error.error
        )
    })?;
    Ok(())
}

#[cfg(unix)]
fn check_private_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("could not inspect secret key {}", path.display()))?;
    if metadata.permissions().mode() & 0o077 != 0 {
        bail!(
            "secret key permissions are too broad; run: chmod 600 '{}'",
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_private_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn sync_directory(directory: &Path) -> Result<()> {
    File::open(directory)
        .and_then(|file| file.sync_all())
        .with_context(|| format!("could not sync directory {}", directory.display()))
}

#[cfg(not(unix))]
fn sync_directory(_directory: &Path) -> Result<()> {
    Ok(())
}
