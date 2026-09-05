//! Authenticated, streaming file encryption built around Threefish-1024.
//!
//! Threefish is a low-level tweakable block cipher, not an authenticated file
//! format. This crate uses it in counter mode and applies encrypt-then-MAC with
//! HMAC-SHA-512. Per-file keys are derived from a 1024-bit master key using
//! HKDF-SHA-512.

use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha512;
use tempfile::{Builder, NamedTempFile};
use thiserror::Error;
use threefish::Threefish1024;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Default master-key filename, resolved relative to the process working directory.
pub const DEFAULT_KEY_FILE: &str = "key.key";
/// Required master-key size in bytes (1024 bits).
pub const KEY_LEN: usize = 128;
/// Size of the authenticated container header.
pub const HEADER_LEN: usize = 80;
const HEADER_LEN_U32: u32 = 80;
/// Size of the HMAC-SHA-512 authentication tag.
pub const TAG_LEN: usize = 64;

const MAGIC: &[u8; 8] = b"TF1024\0\0";
const FORMAT_VERSION: u16 = 1;
const ALGORITHM_ID: u16 = 1;
const SALT_LEN: usize = 32;
const TWEAK_LEN: usize = 16;
const BLOCK_LEN: usize = 128;
const IO_BUFFER_LEN: usize = 64 * 1024;
const ENCRYPTION_KEY_INFO: &[u8] = b"threefish1024/v1/threefish-1024-ctr";
const AUTHENTICATION_KEY_INFO: &[u8] = b"threefish1024/v1/hmac-sha512";
const AUTHENTICATION_DOMAIN: &[u8] = b"threefish1024/v1/auth\0";

type HmacSha512 = Hmac<Sha512>;

/// Errors returned by key generation and file operations.
#[derive(Debug, Error)]
pub enum Error {
    /// A filesystem or stream operation failed.
    #[error("could not {action} '{}': {source}", path.display())]
    Io {
        /// Description of the attempted operation.
        action: &'static str,
        /// Path involved in the operation.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// The operating system random source failed.
    #[error("the operating-system random source failed: {0}")]
    Random(#[from] getrandom::Error),

    /// The key file had an unexpected length.
    #[error(
        "key file '{}' must contain exactly {KEY_LEN} binary bytes (found {actual})",
        path.display()
    )]
    InvalidKeyLength {
        /// Path to the invalid key.
        path: PathBuf,
        /// Actual file length.
        actual: u64,
    },

    /// The key path was a symlink or non-regular file.
    #[error("key file '{}' must be a regular file, not a symlink or special file", path.display())]
    InvalidKeyFile {
        /// Path to the invalid key file.
        path: PathBuf,
    },

    /// Unix key permissions exposed the master key to another user.
    #[cfg(unix)]
    #[error(
        "key file '{}' has insecure permissions {:04o}; run 'chmod 600 {}'",
        path.display(),
        mode,
        path.display()
    )]
    InsecureKeyPermissions {
        /// Path to the key file.
        path: PathBuf,
        /// Unix permission bits.
        mode: u32,
    },

    /// The destination already exists and overwrite was not requested.
    #[error("output '{}' already exists (use --force to replace it)", path.display())]
    OutputExists {
        /// Existing destination path.
        path: PathBuf,
    },

    /// An input or output aliases the key or another protected path.
    #[error("{message}: '{}'", path.display())]
    UnsafePath {
        /// Explanation of the unsafe alias.
        message: &'static str,
        /// Path supplied by the caller.
        path: PathBuf,
    },

    /// The input is not a regular file.
    #[error("input '{}' must be a regular file", path.display())]
    InvalidInputFile {
        /// Invalid input path.
        path: PathBuf,
    },

    /// The encrypted container is malformed or unsupported.
    #[error("invalid encrypted file: {0}")]
    InvalidFormat(&'static str),

    /// The authentication tag did not validate.
    #[error("authentication failed (the key is wrong or the encrypted file was modified)")]
    AuthenticationFailed,

    /// The input changed while it was being encrypted.
    #[error("input '{}' changed while it was being read; no output was created", path.display())]
    InputChanged {
        /// Input path.
        path: PathBuf,
    },

    /// A theoretically unreachable cryptographic length limit was hit.
    #[error("cryptographic length limit exceeded")]
    CryptoLength,
}

/// Encrypt `input` into an authenticated container at `output`.
///
/// `key_path` must name an exact 128-byte binary master key. The output is
/// staged in the destination directory and is not replaced unless `overwrite`
/// is true.
///
/// # Errors
///
/// Returns an error when paths are unsafe, the key or input is invalid, secure
/// randomness is unavailable, authentication primitives cannot be initialized,
/// or any filesystem operation fails. Ordinary failures before publication do
/// not expose a partial destination.
pub fn encrypt_file(
    input: &Path,
    output: &Path,
    key_path: &Path,
    overwrite: bool,
) -> Result<(), Error> {
    validate_protected_paths(input, output, key_path, overwrite)?;
    let key = load_key(key_path)?;
    let input_file = open_regular_input(input)?;
    let plaintext_len = input_file
        .metadata()
        .map_err(|source| io_error("read metadata for", input, source))?
        .len();

    let mut salt = [0_u8; SALT_LEN];
    let mut tweak = [0_u8; TWEAK_LEN];
    getrandom::fill(&mut salt)?;
    getrandom::fill(&mut tweak)?;

    let header = Header {
        plaintext_len,
        salt,
        tweak,
    };
    let header_bytes = header.encode();
    let keys = derive_keys(&key, &salt)?;
    let mut temp = private_temp_file(output, ".threefish-output-")?;

    let operation = (|| {
        let mut reader = BufReader::with_capacity(IO_BUFFER_LEN, input_file);
        let mut writer = BufWriter::with_capacity(IO_BUFFER_LEN, temp.as_file_mut());
        let mut mac = new_mac(&keys.authentication)?;
        mac.update(AUTHENTICATION_DOMAIN);
        mac.update(&header_bytes);
        writer
            .write_all(&header_bytes)
            .map_err(|source| io_error("write", output, source))?;

        let mut ctr = ThreefishCtr::new(&keys.encryption, &tweak);
        let mut buffer = Zeroizing::new(vec![0_u8; IO_BUFFER_LEN]);
        let mut processed = 0_u64;

        loop {
            let count = reader
                .read(&mut buffer)
                .map_err(|source| io_error("read", input, source))?;
            if count == 0 {
                break;
            }
            processed = processed
                .checked_add(u64::try_from(count).map_err(|_| Error::CryptoLength)?)
                .ok_or(Error::CryptoLength)?;
            if processed > plaintext_len {
                return Err(Error::InputChanged {
                    path: input.to_path_buf(),
                });
            }

            ctr.apply_keystream(&mut buffer[..count])?;
            mac.update(&buffer[..count]);
            writer
                .write_all(&buffer[..count])
                .map_err(|source| io_error("write", output, source))?;
        }

        if processed != plaintext_len {
            return Err(Error::InputChanged {
                path: input.to_path_buf(),
            });
        }

        let tag = mac.finalize().into_bytes();
        writer
            .write_all(&tag)
            .map_err(|source| io_error("write", output, source))?;
        writer
            .flush()
            .map_err(|source| io_error("flush", output, source))?;
        Ok(())
    })();

    operation?;
    temp.as_file()
        .sync_all()
        .map_err(|source| io_error("sync", output, source))?;
    publish_temp(temp, output, overwrite)
}

/// Decrypt and authenticate `input`, writing the plaintext to `output`.
///
/// Plaintext is staged in a private temporary file. It is not published unless
/// the complete ciphertext and tag authenticate successfully.
///
/// # Errors
///
/// Returns an error when paths are unsafe, the key or container is invalid, the
/// authentication tag does not match, or any filesystem operation fails.
/// Plaintext is never published before successful authentication.
pub fn decrypt_file(
    input: &Path,
    output: &Path,
    key_path: &Path,
    overwrite: bool,
) -> Result<(), Error> {
    validate_protected_paths(input, output, key_path, overwrite)?;
    let key = load_key(key_path)?;
    let input_file = open_regular_input(input)?;
    let encrypted_len = input_file
        .metadata()
        .map_err(|source| io_error("read metadata for", input, source))?
        .len();
    let mut reader = BufReader::with_capacity(IO_BUFFER_LEN, input_file);

    let mut header_bytes = [0_u8; HEADER_LEN];
    read_exact_format(&mut reader, &mut header_bytes, input)?;
    let header = Header::decode(&header_bytes)?;
    let expected_len = u64::try_from(HEADER_LEN + TAG_LEN)
        .map_err(|_| Error::CryptoLength)?
        .checked_add(header.plaintext_len)
        .ok_or(Error::InvalidFormat("declared length overflows the format"))?;
    if encrypted_len != expected_len {
        return Err(Error::InvalidFormat(
            "file size does not match the authenticated header",
        ));
    }

    let keys = derive_keys(&key, &header.salt)?;

    // Authenticate once before creating any plaintext-bearing temporary file.
    // The second pass below authenticates again, protecting against concurrent
    // changes to the already-open input between verification and publication.
    verify_ciphertext(
        &mut reader,
        header.plaintext_len,
        &header_bytes,
        &keys.authentication,
        input,
    )?;
    reader
        .seek(SeekFrom::Start(HEADER_LEN as u64))
        .map_err(|source| io_error("seek", input, source))?;

    let mut temp = private_temp_file(output, ".threefish-output-")?;

    let operation = (|| {
        let mut mac = new_mac(&keys.authentication)?;
        mac.update(AUTHENTICATION_DOMAIN);
        mac.update(&header_bytes);
        let mut ctr = ThreefishCtr::new(&keys.encryption, &header.tweak);
        let mut writer = BufWriter::with_capacity(IO_BUFFER_LEN, temp.as_file_mut());
        let mut buffer = Zeroizing::new(vec![0_u8; IO_BUFFER_LEN]);
        let mut remaining = header.plaintext_len;

        while remaining != 0 {
            let wanted = usize::try_from(remaining.min(IO_BUFFER_LEN as u64))
                .map_err(|_| Error::CryptoLength)?;
            let count = reader
                .read(&mut buffer[..wanted])
                .map_err(|source| io_error("read", input, source))?;
            if count == 0 {
                return Err(Error::InvalidFormat("ciphertext is truncated"));
            }
            mac.update(&buffer[..count]);
            ctr.apply_keystream(&mut buffer[..count])?;
            writer
                .write_all(&buffer[..count])
                .map_err(|source| io_error("write", output, source))?;
            remaining -= u64::try_from(count).map_err(|_| Error::CryptoLength)?;
        }

        let mut supplied_tag = Zeroizing::new([0_u8; TAG_LEN]);
        read_exact_format(&mut reader, &mut *supplied_tag, input)?;
        let mut trailing = [0_u8; 1];
        if reader
            .read(&mut trailing)
            .map_err(|source| io_error("read", input, source))?
            != 0
        {
            return Err(Error::InvalidFormat("encrypted file has trailing data"));
        }

        mac.verify_slice(&*supplied_tag)
            .map_err(|_| Error::AuthenticationFailed)?;
        writer
            .flush()
            .map_err(|source| io_error("flush", output, source))?;
        Ok(())
    })();

    operation?;
    temp.as_file()
        .sync_all()
        .map_err(|source| io_error("sync", output, source))?;
    publish_temp(temp, output, overwrite)
}

/// Generate a new 1024-bit key at `key_path` using staged, no-clobber publication.
///
/// Existing paths are never overwritten. On Unix, the resulting file mode is
/// `0600`.
///
/// # Errors
///
/// Returns an error when secure randomness is unavailable, the destination
/// already exists, its parent cannot be used, or the key cannot be written and
/// published.
pub fn generate_key(key_path: &Path) -> Result<(), Error> {
    if fs::symlink_metadata(key_path).is_ok() {
        return Err(Error::OutputExists {
            path: key_path.to_path_buf(),
        });
    }

    let parent = usable_parent(key_path);
    let mut key = Zeroizing::new([0_u8; KEY_LEN]);
    getrandom::fill(&mut *key)?;
    let mut temp = Builder::new()
        .prefix(".threefish-key-")
        .tempfile_in(parent)
        .map_err(|source| io_error("create temporary key in", parent, source))?;
    set_private_permissions(temp.as_file(), key_path)?;
    temp.write_all(&*key)
        .map_err(|source| io_error("write", key_path, source))?;
    temp.flush()
        .map_err(|source| io_error("flush", key_path, source))?;
    temp.as_file()
        .sync_all()
        .map_err(|source| io_error("sync", key_path, source))?;

    temp.persist_noclobber(key_path)
        .map(|_| ())
        .map_err(|error| {
            if error.error.kind() == io::ErrorKind::AlreadyExists {
                Error::OutputExists {
                    path: key_path.to_path_buf(),
                }
            } else {
                io_error("publish", key_path, error.error)
            }
        })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Header {
    plaintext_len: u64,
    salt: [u8; SALT_LEN],
    tweak: [u8; TWEAK_LEN],
}

impl Header {
    fn encode(self) -> [u8; HEADER_LEN] {
        let mut bytes = [0_u8; HEADER_LEN];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        bytes[10..12].copy_from_slice(&ALGORITHM_ID.to_le_bytes());
        bytes[12..16].copy_from_slice(&HEADER_LEN_U32.to_le_bytes());
        // bytes 16..24 are flags and reserved space and remain zero.
        bytes[24..32].copy_from_slice(&self.plaintext_len.to_le_bytes());
        bytes[32..64].copy_from_slice(&self.salt);
        bytes[64..80].copy_from_slice(&self.tweak);
        bytes
    }

    fn decode(bytes: &[u8; HEADER_LEN]) -> Result<Self, Error> {
        if &bytes[..8] != MAGIC {
            return Err(Error::InvalidFormat("bad magic"));
        }
        if read_u16(&bytes[8..10]) != FORMAT_VERSION {
            return Err(Error::InvalidFormat("unsupported format version"));
        }
        if read_u16(&bytes[10..12]) != ALGORITHM_ID {
            return Err(Error::InvalidFormat("unsupported algorithm"));
        }
        if read_u32(&bytes[12..16]) != HEADER_LEN_U32 {
            return Err(Error::InvalidFormat("unsupported header length"));
        }
        if bytes[16..24] != [0_u8; 8] {
            return Err(Error::InvalidFormat("unsupported flags or reserved fields"));
        }

        let mut salt = [0_u8; SALT_LEN];
        salt.copy_from_slice(&bytes[32..64]);
        let mut tweak = [0_u8; TWEAK_LEN];
        tweak.copy_from_slice(&bytes[64..80]);
        Ok(Self {
            plaintext_len: read_u64(&bytes[24..32]),
            salt,
            tweak,
        })
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct DerivedKeys {
    encryption: [u8; KEY_LEN],
    authentication: [u8; TAG_LEN],
}

fn derive_keys(master: &[u8; KEY_LEN], salt: &[u8; SALT_LEN]) -> Result<DerivedKeys, Error> {
    let hkdf = Hkdf::<Sha512>::new(Some(salt), master);
    let mut keys = DerivedKeys {
        encryption: [0_u8; KEY_LEN],
        authentication: [0_u8; TAG_LEN],
    };
    hkdf.expand(ENCRYPTION_KEY_INFO, &mut keys.encryption)
        .map_err(|_| Error::CryptoLength)?;
    hkdf.expand(AUTHENTICATION_KEY_INFO, &mut keys.authentication)
        .map_err(|_| Error::CryptoLength)?;
    Ok(keys)
}

fn new_mac(key: &[u8; TAG_LEN]) -> Result<HmacSha512, Error> {
    <HmacSha512 as KeyInit>::new_from_slice(key).map_err(|_| Error::CryptoLength)
}

struct ThreefishCtr {
    cipher: Threefish1024,
    counter: u64,
    keystream: [u8; BLOCK_LEN],
    offset: usize,
}

impl ThreefishCtr {
    fn new(key: &[u8; KEY_LEN], tweak: &[u8; TWEAK_LEN]) -> Self {
        let mut key_words = Zeroizing::new([0_u64; 16]);
        for (word, bytes) in key_words.iter_mut().zip(key.as_chunks::<8>().0) {
            let mut little_endian = [0_u8; 8];
            little_endian.copy_from_slice(bytes);
            *word = u64::from_le_bytes(little_endian);
            little_endian.zeroize();
        }
        let mut tweak_words = [0_u64; 2];
        for (word, bytes) in tweak_words.iter_mut().zip(tweak.as_chunks::<8>().0) {
            let mut little_endian = [0_u8; 8];
            little_endian.copy_from_slice(bytes);
            *word = u64::from_le_bytes(little_endian);
        }
        let cipher = Threefish1024::new_with_tweak_u64(&key_words, &tweak_words);
        tweak_words.zeroize();
        Self {
            cipher,
            counter: 0,
            keystream: [0_u8; BLOCK_LEN],
            offset: BLOCK_LEN,
        }
    }

    fn apply_keystream(&mut self, mut data: &mut [u8]) -> Result<(), Error> {
        while !data.is_empty() {
            if self.offset == BLOCK_LEN {
                self.refill()?;
            }
            let available = BLOCK_LEN - self.offset;
            let count = available.min(data.len());
            for (byte, key_byte) in data[..count]
                .iter_mut()
                .zip(&self.keystream[self.offset..self.offset + count])
            {
                *byte ^= key_byte;
            }
            self.offset += count;
            data = &mut data[count..];
        }
        Ok(())
    }

    fn refill(&mut self) -> Result<(), Error> {
        let mut words = [0_u64; 16];
        words[0] = self.counter;
        self.cipher.encrypt_block_u64(&mut words);
        for (chunk, word) in self.keystream.as_chunks_mut::<8>().0.iter_mut().zip(words) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        words.zeroize();
        self.counter = self.counter.checked_add(1).ok_or(Error::CryptoLength)?;
        self.offset = 0;
        Ok(())
    }
}

impl Drop for ThreefishCtr {
    fn drop(&mut self) {
        self.keystream.zeroize();
        self.counter.zeroize();
        self.offset.zeroize();
    }
}

fn load_key(path: &Path) -> Result<Zeroizing<[u8; KEY_LEN]>, Error> {
    let path_metadata =
        fs::symlink_metadata(path).map_err(|source| io_error("open key file", path, source))?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return Err(Error::InvalidKeyFile {
            path: path.to_path_buf(),
        });
    }

    let mut file = open_key_without_following_symlinks(path)?;
    let metadata = file
        .metadata()
        .map_err(|source| io_error("read metadata for key file", path, source))?;
    if !metadata.is_file() {
        return Err(Error::InvalidKeyFile {
            path: path.to_path_buf(),
        });
    }
    if metadata.len() != KEY_LEN as u64 {
        return Err(Error::InvalidKeyLength {
            path: path.to_path_buf(),
            actual: metadata.len(),
        });
    }
    validate_key_permissions(path, &metadata)?;

    let mut key = Zeroizing::new([0_u8; KEY_LEN]);
    file.read_exact(&mut *key)
        .map_err(|source| io_error("read key file", path, source))?;
    let mut extra = [0_u8; 1];
    if file
        .read(&mut extra)
        .map_err(|source| io_error("read key file", path, source))?
        != 0
    {
        return Err(Error::InvalidKeyLength {
            path: path.to_path_buf(),
            actual: KEY_LEN as u64 + 1,
        });
    }
    Ok(key)
}

#[cfg(unix)]
fn open_key_without_following_symlinks(path: &Path) -> Result<File, Error> {
    use std::os::unix::fs::OpenOptionsExt;

    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| io_error("open key file", path, source))
}

#[cfg(not(unix))]
fn open_key_without_following_symlinks(path: &Path) -> Result<File, Error> {
    OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|source| io_error("open key file", path, source))
}

fn open_regular_input(path: &Path) -> Result<File, Error> {
    let file = File::open(path).map_err(|source| io_error("open input", path, source))?;
    let metadata = file
        .metadata()
        .map_err(|source| io_error("read metadata for", path, source))?;
    if !metadata.is_file() {
        return Err(Error::InvalidInputFile {
            path: path.to_path_buf(),
        });
    }
    Ok(file)
}

fn validate_protected_paths(
    input: &Path,
    output: &Path,
    key_path: &Path,
    overwrite: bool,
) -> Result<(), Error> {
    if paths_alias(input, key_path)? {
        return Err(Error::UnsafePath {
            message: "refusing to use the master key as input",
            path: input.to_path_buf(),
        });
    }
    if paths_alias(output, key_path)? {
        return Err(Error::UnsafePath {
            message: "refusing to replace the master key with output",
            path: output.to_path_buf(),
        });
    }
    if paths_alias(input, output)? {
        return Err(Error::UnsafePath {
            message: "input and output refer to the same file",
            path: output.to_path_buf(),
        });
    }
    if fs::symlink_metadata(output).is_ok() && !overwrite {
        return Err(Error::OutputExists {
            path: output.to_path_buf(),
        });
    }
    Ok(())
}

fn paths_alias(left: &Path, right: &Path) -> Result<bool, Error> {
    if left == right {
        return Ok(true);
    }

    if fs::symlink_metadata(left).is_ok() && fs::symlink_metadata(right).is_ok() {
        return same_file::is_same_file(left, right)
            .map_err(|source| io_error("compare", left, source));
    }

    let left_absolute = normalized_missing_path(left)?;
    let right_absolute = normalized_missing_path(right)?;
    Ok(left_absolute == right_absolute)
}

fn normalized_missing_path(path: &Path) -> Result<PathBuf, Error> {
    let name = path.file_name().ok_or_else(|| Error::UnsafePath {
        message: "path does not name a file",
        path: path.to_path_buf(),
    })?;
    let parent = usable_parent(path);
    let canonical_parent = parent
        .canonicalize()
        .map_err(|source| io_error("resolve parent directory for", path, source))?;
    Ok(canonical_parent.join(name))
}

fn private_temp_file(output: &Path, prefix: &str) -> Result<NamedTempFile, Error> {
    let parent = usable_parent(output);
    let temp = Builder::new()
        .prefix(prefix)
        .tempfile_in(parent)
        .map_err(|source| io_error("create temporary output in", parent, source))?;
    set_private_permissions(temp.as_file(), output)?;
    Ok(temp)
}

fn publish_temp(temp: NamedTempFile, output: &Path, overwrite: bool) -> Result<(), Error> {
    let result = if overwrite {
        temp.persist(output)
    } else {
        temp.persist_noclobber(output)
    };
    result.map(|_| ()).map_err(|error| {
        if error.error.kind() == io::ErrorKind::AlreadyExists {
            Error::OutputExists {
                path: output.to_path_buf(),
            }
        } else {
            io_error("publish", output, error.error)
        }
    })
}

fn usable_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

#[cfg(unix)]
fn set_private_permissions(file: &File, display_path: &Path) -> Result<(), Error> {
    use std::os::unix::fs::PermissionsExt;

    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|source| io_error("set private permissions on", display_path, source))
}

#[cfg(not(unix))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "Keeps the fallible Unix implementation's signature"
)]
fn set_private_permissions(_file: &File, _display_path: &Path) -> Result<(), Error> {
    Ok(())
}

#[cfg(unix)]
fn validate_key_permissions(path: &Path, metadata: &Metadata) -> Result<(), Error> {
    use std::os::unix::fs::PermissionsExt;

    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(Error::InsecureKeyPermissions {
            path: path.to_path_buf(),
            mode,
        });
    }
    Ok(())
}

#[cfg(not(unix))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "Keeps the fallible Unix implementation's signature"
)]
fn validate_key_permissions(_path: &Path, _metadata: &Metadata) -> Result<(), Error> {
    Ok(())
}

fn read_exact_format<R: Read>(reader: &mut R, buffer: &mut [u8], path: &Path) -> Result<(), Error> {
    match reader.read_exact(buffer) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
            Err(Error::InvalidFormat("encrypted file is truncated"))
        }
        Err(source) => Err(io_error("read", path, source)),
    }
}

fn verify_ciphertext<R: Read>(
    reader: &mut R,
    ciphertext_len: u64,
    header: &[u8; HEADER_LEN],
    authentication_key: &[u8; TAG_LEN],
    input: &Path,
) -> Result<(), Error> {
    let mut mac = new_mac(authentication_key)?;
    mac.update(AUTHENTICATION_DOMAIN);
    mac.update(header);
    let mut buffer = Zeroizing::new(vec![0_u8; IO_BUFFER_LEN]);
    let mut remaining = ciphertext_len;

    while remaining != 0 {
        let wanted = usize::try_from(remaining.min(IO_BUFFER_LEN as u64))
            .map_err(|_| Error::CryptoLength)?;
        let count = reader
            .read(&mut buffer[..wanted])
            .map_err(|source| io_error("read", input, source))?;
        if count == 0 {
            return Err(Error::InvalidFormat("ciphertext is truncated"));
        }
        mac.update(&buffer[..count]);
        remaining -= u64::try_from(count).map_err(|_| Error::CryptoLength)?;
    }

    let mut supplied_tag = Zeroizing::new([0_u8; TAG_LEN]);
    read_exact_format(reader, &mut *supplied_tag, input)?;
    let mut trailing = [0_u8; 1];
    if reader
        .read(&mut trailing)
        .map_err(|source| io_error("read", input, source))?
        != 0
    {
        return Err(Error::InvalidFormat("encrypted file has trailing data"));
    }
    mac.verify_slice(&*supplied_tag)
        .map_err(|_| Error::AuthenticationFailed)
}

fn read_u16(bytes: &[u8]) -> u16 {
    u16::from_le_bytes([bytes[0], bytes[1]])
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn read_u64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

fn io_error(action: &'static str, path: &Path, source: io::Error) -> Error {
    Error::Io {
        action,
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use proptest::prelude::*;
    use sha2::Digest;

    #[test]
    fn header_round_trip_has_stable_layout() {
        let header = Header {
            plaintext_len: 0x0807_0605_0403_0201,
            salt: [0x5a; SALT_LEN],
            tweak: [0xa5; TWEAK_LEN],
        };
        let encoded = header.encode();
        assert_eq!(&encoded[..8], MAGIC);
        assert_eq!(&encoded[8..10], &1_u16.to_le_bytes());
        assert_eq!(&encoded[10..12], &1_u16.to_le_bytes());
        assert_eq!(&encoded[12..16], &80_u32.to_le_bytes());
        assert_eq!(&encoded[16..24], &[0_u8; 8]);
        assert_eq!(Header::decode(&encoded).unwrap(), header);
    }

    #[test]
    fn header_rejects_each_structural_field() {
        let valid = Header {
            plaintext_len: 0,
            salt: [0; SALT_LEN],
            tweak: [0; TWEAK_LEN],
        }
        .encode();
        for offset in 0..24 {
            if (16..24).contains(&offset) || offset < 16 {
                let mut damaged = valid;
                damaged[offset] ^= 0x80;
                assert!(Header::decode(&damaged).is_err(), "offset {offset}");
            }
        }
    }

    #[test]
    fn threefish_1024_matches_official_zero_vector() {
        let expected = hex!(
            "F05C3D0A3D05B304 F785DDC7D1E03601"
            "5C8AA76E2F217B06 C6E1544C0BC1A90D"
            "F0ACCB9473C24E0F D54FEA68057F4332"
            "9CB454761D6DF5CF 7B2E9B3614FBD5A2"
            "0B2E4760B4060354 0D82EABC5482C171"
            "C832AFBE68406BC3 9500367A592943FA"
            "9A5B4A43286CA3C4 CF46104B443143D5"
            "60A4B230488311DF 4FEEF7E1DFE8391E"
        );
        let cipher = Threefish1024::new_with_tweak(&[0_u8; KEY_LEN], &[0_u8; TWEAK_LEN]);
        let mut words = [0_u64; 16];
        cipher.encrypt_block_u64(&mut words);
        let mut actual = [0_u8; BLOCK_LEN];
        for (chunk, word) in actual.as_chunks_mut::<8>().0.iter_mut().zip(words) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        assert_eq!(actual, expected);
    }

    #[test]
    fn ctr_is_symmetric_and_independent_of_chunking() {
        let key = [0x31; KEY_LEN];
        let tweak = [0x72; TWEAK_LEN];
        let original: Vec<u8> = (0_u16..1025).map(|n| (n % 251) as u8).collect();

        let mut whole = original.clone();
        ThreefishCtr::new(&key, &tweak)
            .apply_keystream(&mut whole)
            .unwrap();

        let mut chunked = original.clone();
        let mut ctr = ThreefishCtr::new(&key, &tweak);
        for chunk in chunked.chunks_mut(37) {
            ctr.apply_keystream(chunk).unwrap();
        }
        assert_eq!(whole, chunked);

        ThreefishCtr::new(&key, &tweak)
            .apply_keystream(&mut whole)
            .unwrap();
        assert_eq!(whole, original);
    }

    #[test]
    fn derived_keys_are_separate_and_salt_dependent() {
        let master = [7_u8; KEY_LEN];
        let first = derive_keys(&master, &[1_u8; SALT_LEN]).unwrap();
        let second = derive_keys(&master, &[2_u8; SALT_LEN]).unwrap();
        assert_ne!(&first.encryption[..TAG_LEN], &first.authentication);
        assert_ne!(first.encryption, second.encryption);
        assert_ne!(first.authentication, second.authentication);
    }

    #[test]
    fn deterministic_container_fingerprint_is_stable() {
        let mut master = [0_u8; KEY_LEN];
        for (index, byte) in master.iter_mut().enumerate() {
            *byte = u8::try_from(index).unwrap();
        }
        let mut salt = [0_u8; SALT_LEN];
        for (index, byte) in salt.iter_mut().enumerate() {
            *byte = 0xa0_u8.wrapping_add(u8::try_from(index).unwrap());
        }
        let mut tweak = [0_u8; TWEAK_LEN];
        for (index, byte) in tweak.iter_mut().enumerate() {
            *byte = 0xf0_u8.wrapping_sub(u8::try_from(index).unwrap());
        }
        let plaintext = b"Threefish-1024 authenticated format v1\n";
        let header = Header {
            plaintext_len: u64::try_from(plaintext.len()).unwrap(),
            salt,
            tweak,
        }
        .encode();
        let keys = derive_keys(&master, &salt).unwrap();
        let mut ciphertext = plaintext.to_vec();
        ThreefishCtr::new(&keys.encryption, &tweak)
            .apply_keystream(&mut ciphertext)
            .unwrap();
        let mut mac = new_mac(&keys.authentication).unwrap();
        mac.update(AUTHENTICATION_DOMAIN);
        mac.update(&header);
        mac.update(&ciphertext);
        let tag = mac.finalize().into_bytes();
        let mut container = Vec::with_capacity(HEADER_LEN + plaintext.len() + TAG_LEN);
        container.extend_from_slice(&header);
        container.extend_from_slice(&ciphertext);
        container.extend_from_slice(&tag);
        let fingerprint = Sha512::digest(&container);
        let expected = hex!(
            "4433454789084227e7c33330169bb7ea"
            "29661bf4505396f28127954a3f6e1fe7"
            "f8efbed7125475aa75f7936799fe2d61"
            "0c38fa572cbc668e6448541226568b71"
        );
        assert_eq!(&fingerprint[..], &expected);
        assert_eq!(container.len(), HEADER_LEN + plaintext.len() + TAG_LEN);
    }

    proptest! {
        #[test]
        fn ctr_round_trips_arbitrary_bytes(
            key in any::<[u8; KEY_LEN]>(),
            tweak in any::<[u8; TWEAK_LEN]>(),
            data in proptest::collection::vec(any::<u8>(), 0..16_384),
            chunk_size in 1_usize..513,
        ) {
            let mut encrypted = data.clone();
            let mut encryptor = ThreefishCtr::new(&key, &tweak);
            for chunk in encrypted.chunks_mut(chunk_size) {
                encryptor.apply_keystream(chunk).unwrap();
            }
            let mut decryptor = ThreefishCtr::new(&key, &tweak);
            for chunk in encrypted.chunks_mut(chunk_size.saturating_add(17)) {
                decryptor.apply_keystream(chunk).unwrap();
            }
            prop_assert_eq!(encrypted, data);
        }
    }
}
