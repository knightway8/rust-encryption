use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use subtle::ConstantTimeEq;
use threefish::Threefish1024;
use zeroize::Zeroizing;

const KEY_FILE: &str = "key.key";
const KEY_LEN: usize = 128;
const BLOCK_LEN: usize = 128;
const SALT_LEN: usize = 32;
const TWEAK_LEN: usize = 16;
const TAG_LEN: usize = 32;
const HEADER_LEN: usize = 64;
const BUFFER_LEN: usize = 1024 * 1024;
const MAGIC: [u8; 8] = *b"TF1024\x01\0";
const MAC_KDF_CONTEXT: &str = "tf1024 v1 BLAKE3 ciphertext-authentication key";

#[derive(Parser)]
#[command(
    name = "tf1024",
    version,
    about = "Authenticated streaming file encryption using Threefish-1024",
    after_help = "The key and both files must be in the same directory as the executable.\n\
                  Only bare file names are accepted. Existing output files are never overwritten."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new 1024-bit key.key beside the executable.
    #[command(name = "keygen")]
    Keygen,

    /// Encrypt INPUT to OUTPUT.
    #[command(name = "E", visible_aliases = ["e", "encrypt"])]
    Encrypt {
        /// Plaintext file name.
        input: PathBuf,
        /// Encrypted file name.
        output: PathBuf,
    },

    /// Decrypt INPUT to OUTPUT after authenticating it.
    #[command(name = "D", visible_aliases = ["d", "decrypt"])]
    Decrypt {
        /// Encrypted file name.
        input: PathBuf,
        /// Decrypted file name.
        output: PathBuf,
    },
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let executable = std::env::current_exe().context("could not locate the executable")?;
    let directory = executable
        .parent()
        .context("the executable has no parent directory")?;

    match cli.command {
        Command::Keygen => keygen(directory),
        Command::Encrypt { input, output } => encrypt(directory, &input, &output),
        Command::Decrypt { input, output } => decrypt(directory, &input, &output),
    }
}

fn keygen(directory: &Path) -> Result<()> {
    let path = directory.join(KEY_FILE);
    let mut key = Zeroizing::new([0_u8; KEY_LEN]);
    getrandom::fill(&mut *key).map_err(|error| {
        anyhow::anyhow!("the operating system random generator failed: {error}")
    })?;

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options
        .open(&path)
        .with_context(|| format!("could not create {}; it may already exist", path.display()))?;
    file.write_all(&*key)
        .context("could not write the key file")?;
    file.sync_all().context("could not sync the key file")?;

    println!("created {}", path.display());
    println!("Back it up securely. Encrypted files cannot be recovered without this exact key.");
    Ok(())
}

fn encrypt(directory: &Path, input_name: &Path, output_name: &Path) -> Result<()> {
    let input_path = file_path(directory, input_name, "input")?;
    let output_path = file_path(directory, output_name, "output")?;
    validate_file_pair(input_name, output_name)?;
    ensure_output_absent(&output_path)?;

    let input = File::open(&input_path)
        .with_context(|| format!("could not open input file {}", input_path.display()))?;
    let metadata = input
        .metadata()
        .with_context(|| format!("could not inspect {}", input_path.display()))?;
    if !metadata.is_file() {
        bail!("input is not a regular file: {}", input_path.display());
    }
    let plaintext_len = metadata.len();

    let master_key = load_key(directory)?;
    let mut salt = [0_u8; SALT_LEN];
    let mut tweak = [0_u8; TWEAK_LEN];
    getrandom::fill(&mut salt)
        .map_err(|error| anyhow::anyhow!("could not generate the per-file salt: {error}"))?;
    getrandom::fill(&mut tweak)
        .map_err(|error| anyhow::anyhow!("could not generate the Threefish tweak: {error}"))?;
    let mac_key = derive_mac_key(&master_key, &salt);
    let header = make_header(plaintext_len, &salt, &tweak);

    let cipher = Threefish1024::new_with_tweak(&master_key, &tweak);
    let mut stream = CtrStream::new(cipher);
    let mut mac = blake3::Hasher::new_keyed(&mac_key);
    mac.update(&header);

    let temporary = tempfile::Builder::new()
        .prefix(".tf1024-")
        .tempfile_in(directory)
        .with_context(|| {
            format!(
                "could not create a temporary file in {}",
                directory.display()
            )
        })?;
    let mut writer = BufWriter::new(temporary);
    writer
        .write_all(&header)
        .context("could not write the encrypted-file header")?;

    let mut reader = BufReader::with_capacity(BUFFER_LEN, input);
    let mut buffer = vec![0_u8; BUFFER_LEN];
    let mut remaining = plaintext_len;
    while remaining != 0 {
        let requested = usize::try_from(remaining.min(BUFFER_LEN as u64)).unwrap();
        let count = reader
            .read(&mut buffer[..requested])
            .context("could not read the input file")?;
        if count == 0 {
            bail!("the input file became shorter while it was being encrypted");
        }
        stream.apply(&mut buffer[..count]);
        mac.update(&buffer[..count]);
        writer
            .write_all(&buffer[..count])
            .context("could not write encrypted data")?;
        remaining -= count as u64;
    }

    let mut extra = [0_u8; 1];
    if reader
        .read(&mut extra)
        .context("could not finish reading input")?
        != 0
    {
        bail!("the input file grew while it was being encrypted");
    }

    writer
        .write_all(mac.finalize().as_bytes())
        .context("could not write the authentication tag")?;
    writer.flush().context("could not flush encrypted output")?;
    writer
        .get_ref()
        .as_file()
        .sync_all()
        .context("could not sync encrypted output")?;
    let temporary = writer
        .into_inner()
        .map_err(|error| error.into_error())
        .context("could not finalize encrypted output")?;
    persist_without_overwrite(temporary, &output_path)?;

    println!(
        "encrypted {} -> {} ({} bytes)",
        input_path.display(),
        output_path.display(),
        plaintext_len
    );
    Ok(())
}

fn decrypt(directory: &Path, input_name: &Path, output_name: &Path) -> Result<()> {
    let input_path = file_path(directory, input_name, "input")?;
    let output_path = file_path(directory, output_name, "output")?;
    validate_file_pair(input_name, output_name)?;
    ensure_output_absent(&output_path)?;

    let input = File::open(&input_path)
        .with_context(|| format!("could not open input file {}", input_path.display()))?;
    let metadata = input
        .metadata()
        .with_context(|| format!("could not inspect {}", input_path.display()))?;
    if !metadata.is_file() {
        bail!("input is not a regular file: {}", input_path.display());
    }

    let mut reader = BufReader::with_capacity(BUFFER_LEN, input);
    let mut header = [0_u8; HEADER_LEN];
    reader
        .read_exact(&mut header)
        .context("input is too short to be a tf1024 encrypted file")?;
    let parsed = parse_header(&header)?;
    let expected_len = (HEADER_LEN as u64)
        .checked_add(parsed.plaintext_len)
        .and_then(|length| length.checked_add(TAG_LEN as u64))
        .context("encrypted-file length overflow")?;
    if metadata.len() != expected_len {
        bail!(
            "encrypted-file length is invalid: header expects {expected_len} bytes, file has {}",
            metadata.len()
        );
    }

    let master_key = load_key(directory)?;
    let mac_key = derive_mac_key(&master_key, &parsed.salt);

    // Authenticate before creating a plaintext temporary file. The second check below
    // detects any change to the input between this pass and the decryption pass.
    authenticate_ciphertext(&mut reader, parsed.plaintext_len, &header, &mac_key)?;
    reader
        .seek(SeekFrom::Start(HEADER_LEN as u64))
        .context("could not rewind the authenticated ciphertext")?;

    let cipher = Threefish1024::new_with_tweak(&master_key, &parsed.tweak);
    let mut stream = CtrStream::new(cipher);
    let mut mac = blake3::Hasher::new_keyed(&mac_key);
    mac.update(&header);

    let temporary = tempfile::Builder::new()
        .prefix(".tf1024-")
        .tempfile_in(directory)
        .with_context(|| {
            format!(
                "could not create a temporary file in {}",
                directory.display()
            )
        })?;
    let mut writer = BufWriter::new(temporary);
    let mut buffer = vec![0_u8; BUFFER_LEN];
    let mut remaining = parsed.plaintext_len;
    while remaining != 0 {
        let requested = usize::try_from(remaining.min(BUFFER_LEN as u64)).unwrap();
        reader
            .read_exact(&mut buffer[..requested])
            .context("encrypted data ended unexpectedly")?;
        mac.update(&buffer[..requested]);
        stream.apply(&mut buffer[..requested]);
        writer
            .write_all(&buffer[..requested])
            .context("could not write decrypted data")?;
        remaining -= requested as u64;
    }

    let mut stored_tag = [0_u8; TAG_LEN];
    reader
        .read_exact(&mut stored_tag)
        .context("authentication tag is missing")?;
    verify_tag(&mac.finalize(), &stored_tag)?;

    writer.flush().context("could not flush decrypted output")?;
    writer
        .get_ref()
        .as_file()
        .sync_all()
        .context("could not sync decrypted output")?;
    let temporary = writer
        .into_inner()
        .map_err(|error| error.into_error())
        .context("could not finalize decrypted output")?;
    persist_without_overwrite(temporary, &output_path)?;

    println!(
        "decrypted {} -> {} ({} bytes)",
        input_path.display(),
        output_path.display(),
        parsed.plaintext_len
    );
    Ok(())
}

fn validate_file_pair(input: &Path, output: &Path) -> Result<()> {
    let input = bare_name(input, "input")?;
    let output = bare_name(output, "output")?;
    if names_equal(input, output) {
        bail!("input and output must have different file names");
    }
    if names_equal(input, OsStr::new(KEY_FILE)) || names_equal(output, OsStr::new(KEY_FILE)) {
        bail!("key.key cannot be used as an input or output data file");
    }
    Ok(())
}

fn file_path(directory: &Path, name: &Path, role: &str) -> Result<PathBuf> {
    Ok(directory.join(bare_name(name, role)?))
}

fn bare_name<'a>(path: &'a Path, role: &str) -> Result<&'a OsStr> {
    let mut components = path.components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(name)), None) => Ok(name),
        _ => bail!(
            "{role} must be a bare file name in the executable directory, not a path: {}",
            path.display()
        ),
    }
}

fn names_equal(left: &OsStr, right: &OsStr) -> bool {
    left.to_string_lossy()
        .eq_ignore_ascii_case(&right.to_string_lossy())
}

fn ensure_output_absent(path: &Path) -> Result<()> {
    if fs::symlink_metadata(path).is_ok() {
        bail!(
            "output already exists; refusing to overwrite {}",
            path.display()
        );
    }
    Ok(())
}

fn load_key(directory: &Path) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let path = directory.join(KEY_FILE);
    let mut file = File::open(&path)
        .with_context(|| format!("could not open the key file {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("could not inspect the key file {}", path.display()))?;
    if !metadata.is_file() || metadata.len() != KEY_LEN as u64 {
        bail!(
            "{} must be a regular, exactly 128-byte key file",
            path.display()
        );
    }

    let mut key = Zeroizing::new([0_u8; KEY_LEN]);
    file.read_exact(&mut *key)
        .with_context(|| format!("could not read the key file {}", path.display()))?;
    Ok(key)
}

fn derive_mac_key(master_key: &[u8; KEY_LEN], salt: &[u8; SALT_LEN]) -> Zeroizing<[u8; 32]> {
    let mut mac_key = Zeroizing::new([0_u8; 32]);
    let mut mac_kdf = blake3::Hasher::new_derive_key(MAC_KDF_CONTEXT);
    mac_kdf.update(master_key);
    mac_kdf.update(salt);
    mac_kdf.finalize_xof().fill(&mut *mac_key);
    mac_key
}

fn authenticate_ciphertext<R: Read>(
    reader: &mut R,
    ciphertext_len: u64,
    header: &[u8; HEADER_LEN],
    mac_key: &[u8; 32],
) -> Result<()> {
    let mut mac = blake3::Hasher::new_keyed(mac_key);
    mac.update(header);
    let mut remaining = ciphertext_len;
    let mut buffer = vec![0_u8; BUFFER_LEN];
    while remaining != 0 {
        let requested = usize::try_from(remaining.min(BUFFER_LEN as u64)).unwrap();
        reader
            .read_exact(&mut buffer[..requested])
            .context("encrypted data ended unexpectedly")?;
        mac.update(&buffer[..requested]);
        remaining -= requested as u64;
    }

    let mut stored_tag = [0_u8; TAG_LEN];
    reader
        .read_exact(&mut stored_tag)
        .context("authentication tag is missing")?;
    verify_tag(&mac.finalize(), &stored_tag)
}

fn verify_tag(calculated: &blake3::Hash, stored: &[u8; TAG_LEN]) -> Result<()> {
    if calculated.as_bytes().ct_eq(stored).unwrap_u8() != 1 {
        bail!("authentication failed: wrong key, corrupted file, or modified ciphertext");
    }
    Ok(())
}

fn make_header(
    plaintext_len: u64,
    salt: &[u8; SALT_LEN],
    tweak: &[u8; TWEAK_LEN],
) -> [u8; HEADER_LEN] {
    let mut header = [0_u8; HEADER_LEN];
    header[..8].copy_from_slice(&MAGIC);
    header[8..16].copy_from_slice(&plaintext_len.to_le_bytes());
    header[16..48].copy_from_slice(salt);
    header[48..64].copy_from_slice(tweak);
    header
}

struct ParsedHeader {
    plaintext_len: u64,
    salt: [u8; SALT_LEN],
    tweak: [u8; TWEAK_LEN],
}

fn parse_header(header: &[u8; HEADER_LEN]) -> Result<ParsedHeader> {
    if header[..8] != MAGIC {
        bail!("input is not a supported tf1024 encrypted file");
    }
    let plaintext_len = u64::from_le_bytes(header[8..16].try_into().unwrap());
    let salt = header[16..48].try_into().unwrap();
    let tweak = header[48..64].try_into().unwrap();
    Ok(ParsedHeader {
        plaintext_len,
        salt,
        tweak,
    })
}

fn persist_without_overwrite(temporary: tempfile::NamedTempFile, output: &Path) -> Result<()> {
    temporary.persist_noclobber(output).map_err(|error| {
        anyhow::anyhow!(
            "could not create output {} without overwriting an existing file: {}",
            output.display(),
            error.error
        )
    })?;
    Ok(())
}

struct CtrStream {
    cipher: Threefish1024,
    counter: u128,
    keystream: [u8; BLOCK_LEN],
    offset: usize,
}

impl CtrStream {
    fn new(cipher: Threefish1024) -> Self {
        Self {
            cipher,
            counter: 0,
            keystream: [0_u8; BLOCK_LEN],
            offset: BLOCK_LEN,
        }
    }

    fn apply(&mut self, data: &mut [u8]) {
        for byte in data {
            if self.offset == BLOCK_LEN {
                self.refill();
            }
            *byte ^= self.keystream[self.offset];
            self.offset += 1;
        }
    }

    fn refill(&mut self) {
        let mut words = [0_u64; 16];
        let counter_bytes = self.counter.to_le_bytes();
        words[0] = u64::from_le_bytes(counter_bytes[..8].try_into().unwrap());
        words[1] = u64::from_le_bytes(counter_bytes[8..].try_into().unwrap());
        self.cipher.encrypt_block_u64(&mut words);
        for (chunk, word) in self.keystream.as_chunks_mut::<8>().0.iter_mut().zip(words) {
            *chunk = word.to_le_bytes();
        }
        // A u64-sized file cannot come remotely close to exhausting this u128 counter.
        self.counter = self.counter.checked_add(1).unwrap();
        self.offset = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Seek, SeekFrom, Write};

    fn install_test_key(directory: &Path, fill: u8) {
        fs::write(directory.join(KEY_FILE), [fill; KEY_LEN]).unwrap();
    }

    #[test]
    fn round_trips_boundary_sizes() {
        for (index, size) in [0, 1, 127, 128, 129, BUFFER_LEN + 17]
            .into_iter()
            .enumerate()
        {
            let directory = tempfile::tempdir().unwrap();
            install_test_key(directory.path(), 0x5a);
            let input = format!("input-{index}.bin");
            let encrypted = format!("encrypted-{index}.tf1024");
            let output = format!("output-{index}.bin");
            let data: Vec<u8> = (0..size).map(|value| (value % 251) as u8).collect();
            fs::write(directory.path().join(&input), &data).unwrap();

            encrypt(directory.path(), Path::new(&input), Path::new(&encrypted)).unwrap();
            decrypt(directory.path(), Path::new(&encrypted), Path::new(&output)).unwrap();

            assert_eq!(fs::read(directory.path().join(output)).unwrap(), data);
        }
    }

    #[test]
    fn tampering_is_rejected_without_output() {
        let directory = tempfile::tempdir().unwrap();
        install_test_key(directory.path(), 0x33);
        fs::write(directory.path().join("plain.bin"), b"authenticated payload").unwrap();
        encrypt(
            directory.path(),
            Path::new("plain.bin"),
            Path::new("cipher.bin"),
        )
        .unwrap();

        let encrypted = directory.path().join("cipher.bin");
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(encrypted)
            .unwrap();
        file.seek(SeekFrom::Start(HEADER_LEN as u64 + 3)).unwrap();
        let mut byte = [0_u8; 1];
        file.read_exact(&mut byte).unwrap();
        byte[0] ^= 0x80;
        file.seek(SeekFrom::Current(-1)).unwrap();
        file.write_all(&byte).unwrap();
        drop(file);

        let error = decrypt(
            directory.path(),
            Path::new("cipher.bin"),
            Path::new("recovered.bin"),
        )
        .unwrap_err();
        assert!(error.to_string().contains("authentication failed"));
        assert!(!directory.path().join("recovered.bin").exists());
    }

    #[test]
    fn wrong_key_is_rejected() {
        let directory = tempfile::tempdir().unwrap();
        install_test_key(directory.path(), 0x11);
        fs::write(directory.path().join("plain.bin"), b"secret").unwrap();
        encrypt(
            directory.path(),
            Path::new("plain.bin"),
            Path::new("cipher.bin"),
        )
        .unwrap();
        install_test_key(directory.path(), 0x22);

        assert!(
            decrypt(
                directory.path(),
                Path::new("cipher.bin"),
                Path::new("recovered.bin")
            )
            .is_err()
        );
        assert!(!directory.path().join("recovered.bin").exists());
    }

    #[test]
    fn rejects_paths_key_and_overwrite() {
        assert!(bare_name(Path::new("../outside"), "input").is_err());
        assert!(bare_name(Path::new("sub/file"), "input").is_err());
        assert!(validate_file_pair(Path::new("same"), Path::new("SAME")).is_err());
        assert!(validate_file_pair(Path::new("key.key"), Path::new("out")).is_err());

        let directory = tempfile::tempdir().unwrap();
        install_test_key(directory.path(), 0x44);
        fs::write(directory.path().join("plain.bin"), b"data").unwrap();
        fs::write(directory.path().join("exists.bin"), b"keep me").unwrap();
        assert!(
            encrypt(
                directory.path(),
                Path::new("plain.bin"),
                Path::new("exists.bin")
            )
            .is_err()
        );
        assert_eq!(
            fs::read(directory.path().join("exists.bin")).unwrap(),
            b"keep me"
        );
    }

    #[test]
    fn ctr_is_chunk_boundary_independent() {
        let key = [0x42; KEY_LEN];
        let tweak = [0x24; TWEAK_LEN];
        let mut all_at_once = vec![0xa5; BLOCK_LEN * 3 + 7];
        let mut fragmented = all_at_once.clone();

        CtrStream::new(Threefish1024::new_with_tweak(&key, &tweak)).apply(&mut all_at_once);
        let mut stream = CtrStream::new(Threefish1024::new_with_tweak(&key, &tweak));
        for chunk in fragmented.chunks_mut(37) {
            stream.apply(chunk);
        }
        assert_eq!(all_at_once, fragmented);
    }

    #[test]
    fn threefish_1024_matches_known_answer_vector() {
        // Zero-key/zero-tweak/zero-plaintext vector used by the upstream RustCrypto
        // implementation and the Crypto++ Threefish test-vector set.
        let expected = decode_hex(concat!(
            "F05C3D0A3D05B304F785DDC7D1E03601",
            "5C8AA76E2F217B06C6E1544C0BC1A90D",
            "F0ACCB9473C24E0FD54FEA68057F4332",
            "9CB454761D6DF5CF7B2E9B3614FBD5A2",
            "0B2E4760B40603540D82EABC5482C171",
            "C832AFBE68406BC39500367A592943FA",
            "9A5B4A43286CA3C4CF46104B443143D5",
            "60A4B230488311DF4FEEF7E1DFE8391E"
        ));
        let mut words = [0_u64; 16];
        Threefish1024::new_with_tweak(&[0_u8; KEY_LEN], &[0_u8; TWEAK_LEN])
            .encrypt_block_u64(&mut words);
        let actual: Vec<u8> = words.into_iter().flat_map(u64::to_le_bytes).collect();
        assert_eq!(actual, expected);
    }

    fn decode_hex(input: &str) -> Vec<u8> {
        let (pairs, remainder) = input.as_bytes().as_chunks::<2>();
        assert!(remainder.is_empty());
        pairs
            .iter()
            .map(|pair| {
                let high = (pair[0] as char).to_digit(16).unwrap();
                let low = (pair[1] as char).to_digit(16).unwrap();
                ((high << 4) | low) as u8
            })
            .collect()
    }
}
