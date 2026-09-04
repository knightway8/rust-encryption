use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::{
    env,
    error::Error,
    ffi::{OsStr, OsString},
    fmt,
    fs::File,
    io::{self, BufRead, BufReader, BufWriter, IsTerminal, Read, Write},
    path::{Path, PathBuf},
    process::ExitCode,
};
use zeroize::Zeroize;

const APP_NAME: &str = env!("CARGO_PKG_NAME");
const APP_ID: u8 = 38;
const PAYLOAD_ALGORITHM: &str = "Twofish-256";
const SUITE_NAME: &str = "PBKDF2-SHA256 / Twofish-256 / HMAC-SHA256-EtM";
const MAGIC: [u8; 8] = [69, 84, 79, 79, 76, 0, 0, APP_ID];
const VERSION: u8 = 2;
const INTEGRITY_ERROR: &str = "decryption failed or input is invalid";
const SALT_SIZE: usize = 16;
const PREFIX_SIZE: usize = 16;
const HEADER_SIZE: usize = 8 + 1 + 1 + SALT_SIZE + PREFIX_SIZE;
const MAC_TAG_SIZE: usize = 32;
const CIPHER_OVERHEAD: usize = 0;
const CHUNK_SIZE: usize = 32768;
const ENC_KEY_SIZE: usize = 32;
const KDF_ROUNDS: u32 = 173000;
const MAX_PASSWORD_BYTES: usize = 4096;

type AppResult<T> = Result<T, AppError>;
type RecordMac = Hmac<Sha256>;

#[derive(Debug, Clone, Eq, PartialEq)]
struct AppError(String);

impl AppError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

fn integrity_error() -> AppError {
    AppError::new(INTEGRITY_ERROR)
}

impl fmt::Display for AppError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for AppError {}

struct Keys {
    encryption: Vec<u8>,
    authentication: [u8; MAC_TAG_SIZE],
}

impl Drop for Keys {
    fn drop(&mut self) {
        self.encryption.zeroize();
        self.authentication.zeroize();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Encrypt,
    Decrypt,
}

#[derive(Debug, Eq, PartialEq)]
struct Command {
    mode: Mode,
    input: PathBuf,
    output: PathBuf,
}

fn main() -> ExitCode {
    if let Err(error) = run_cli() {
        eprintln!("{APP_NAME}");
        eprintln!("{error}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

fn run_cli() -> AppResult<()> {
    let command = parse_args(env::args_os().skip(1).collect())?;
    let mut password = read_password(command.mode)?;
    let result = match command.mode {
        Mode::Encrypt => encrypt_file(&command.input, &command.output, &password),
        Mode::Decrypt => decrypt_file(&command.input, &command.output, &password),
    };
    password.zeroize();
    result
}

fn usage() -> String {
    format!(
        "Usage: {APP_NAME} E|D <input> <output>\nPayload algorithm: {PAYLOAD_ALGORITHM}\nSuite: {SUITE_NAME}"
    )
}

fn parse_args(args: Vec<OsString>) -> AppResult<Command> {
    if args.len() != 3 {
        return Err(AppError::new(usage()));
    }
    let mode = if args[0] == OsStr::new("E") {
        Mode::Encrypt
    } else if args[0] == OsStr::new("D") {
        Mode::Decrypt
    } else {
        return Err(AppError::new(usage()));
    };
    Ok(Command {
        mode,
        input: PathBuf::from(&args[1]),
        output: PathBuf::from(&args[2]),
    })
}

fn read_password(mode: Mode) -> AppResult<String> {
    let stdin = io::stdin();
    if stdin.is_terminal() {
        let password = rpassword::prompt_password("Password: ")
            .map_err(|error| AppError::new(error.to_string()))?;
        validate_password(&password)?;
        if mode == Mode::Encrypt {
            let confirmation = rpassword::prompt_password("Confirm password: ")
                .map_err(|error| AppError::new(error.to_string()))?;
            if confirmation != password {
                return Err(integrity_error());
            }
        }
        Ok(password)
    } else {
        read_password_line(&mut stdin.lock())
    }
}

fn read_password_line(reader: &mut impl BufRead) -> AppResult<String> {
    let mut password = String::new();
    reader
        .take((MAX_PASSWORD_BYTES + 3) as u64)
        .read_line(&mut password)
        .map_err(|error| AppError::new(error.to_string()))?;
    if password.ends_with('\n') {
        password.pop();
        if password.ends_with('\r') {
            password.pop();
        }
    }
    validate_password(&password)?;
    Ok(password)
}

fn validate_password(password: &str) -> AppResult<()> {
    if password.is_empty() || password.len() > MAX_PASSWORD_BYTES {
        return Err(AppError::new(usage()));
    }
    Ok(())
}

fn derive_keys(password: &str, salt: &[u8; SALT_SIZE]) -> Keys {
    let mut material = [0_u8; 64];
    let rounds = if cfg!(test) { 1 } else { KDF_ROUNDS };
    pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, rounds, &mut material);
    let encryption = material[..ENC_KEY_SIZE].to_vec();
    let mut authentication = [0_u8; MAC_TAG_SIZE];
    authentication.copy_from_slice(&material[32..]);
    material.zeroize();
    Keys {
        encryption,
        authentication,
    }
}

fn make_header(salt: &[u8; SALT_SIZE], prefix: &[u8; PREFIX_SIZE]) -> Vec<u8> {
    let mut header = Vec::with_capacity(HEADER_SIZE);
    header.extend_from_slice(&MAGIC);
    header.push(VERSION);
    header.push(APP_ID);
    header.extend_from_slice(salt);
    header.extend_from_slice(prefix);
    header
}

fn parse_header(
    reader: &mut impl Read,
) -> AppResult<(Vec<u8>, [u8; SALT_SIZE], [u8; PREFIX_SIZE])> {
    let mut header = vec![0_u8; HEADER_SIZE];
    reader
        .read_exact(&mut header)
        .map_err(|_| integrity_error())?;
    if header[..8] != MAGIC || header[8] != VERSION || header[9] != APP_ID {
        return Err(integrity_error());
    }
    let mut salt = [0_u8; SALT_SIZE];
    salt.copy_from_slice(&header[10..10 + SALT_SIZE]);
    let mut prefix = [0_u8; PREFIX_SIZE];
    prefix.copy_from_slice(&header[10 + SALT_SIZE..]);
    Ok((header, salt, prefix))
}

fn make_aad(header: &[u8], counter: u64, final_record: bool, length: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(header.len() + 13);
    aad.extend_from_slice(header);
    aad.extend_from_slice(&counter.to_be_bytes());
    aad.push(u8::from(final_record));
    aad.extend_from_slice(&length.to_be_bytes());
    aad
}

fn record_mac(key: &[u8; MAC_TAG_SIZE], aad: &[u8], ciphertext: &[u8]) -> RecordMac {
    let mut mac = <RecordMac as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(aad);
    mac.update(ciphertext);
    mac
}

fn make_tag(key: &[u8; MAC_TAG_SIZE], aad: &[u8], ciphertext: &[u8]) -> [u8; MAC_TAG_SIZE] {
    record_mac(key, aad, ciphertext)
        .finalize()
        .into_bytes()
        .into()
}

fn verify_tag(
    key: &[u8; MAC_TAG_SIZE],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> AppResult<()> {
    record_mac(key, aad, ciphertext)
        .verify_slice(tag)
        .map_err(|_| integrity_error())
}

fn counter_block(prefix: &[u8; PREFIX_SIZE], record: u64, block_index: u64) -> [u8; 16] {
    let mut block = *prefix;
    for (slot, value) in block[..8].iter_mut().zip(record.to_be_bytes()) {
        *slot ^= value;
    }
    for (slot, value) in block[8..].iter_mut().zip(block_index.to_be_bytes()) {
        *slot ^= value;
    }
    block
}

fn transform_payload(
    key: &[u8],
    prefix: &[u8; PREFIX_SIZE],
    record: u64,
    input: &[u8],
) -> AppResult<Vec<u8>> {
    use twofish::cipher::{Array, BlockCipherEncrypt, KeyInit};
    let cipher = twofish::Twofish::new_from_slice(key).map_err(|_| integrity_error())?;
    let mut output = input.to_vec();
    for (block_index, chunk) in output.chunks_mut(16).enumerate() {
        let block_index = u64::try_from(block_index).map_err(|_| integrity_error())?;
        let mut stream = Array::from(counter_block(prefix, record, block_index));
        cipher.encrypt_block(&mut stream);
        for (byte, mask) in chunk.iter_mut().zip(stream.iter()) {
            *byte ^= mask;
        }
    }
    Ok(output)
}

fn encrypt_payload(
    key: &[u8],
    prefix: &[u8; PREFIX_SIZE],
    record: u64,
    _aad: &[u8],
    plaintext: &[u8],
) -> AppResult<Vec<u8>> {
    transform_payload(key, prefix, record, plaintext)
}

fn decrypt_payload(
    key: &[u8],
    prefix: &[u8; PREFIX_SIZE],
    record: u64,
    _aad: &[u8],
    ciphertext: &[u8],
) -> AppResult<Vec<u8>> {
    transform_payload(key, prefix, record, ciphertext)
}

fn encrypt_file(input: &Path, output: &Path, password: &str) -> AppResult<()> {
    validate_paths(input, output)?;
    let input_file = open_regular_file(input)?;
    let mut reader = BufReader::with_capacity(CHUNK_SIZE, input_file);
    let mut temporary = create_temporary_output(output)?;
    let mut salt = [0_u8; SALT_SIZE];
    let mut prefix = [0_u8; PREFIX_SIZE];
    getrandom::fill(&mut salt).map_err(|error| AppError::new(error.to_string()))?;
    getrandom::fill(&mut prefix).map_err(|error| AppError::new(error.to_string()))?;
    let keys = derive_keys(password, &salt);
    let header = make_header(&salt, &prefix);

    {
        let mut writer = BufWriter::with_capacity(CHUNK_SIZE, temporary.as_file_mut());
        writer
            .write_all(&header)
            .map_err(|error| AppError::new(error.to_string()))?;
        encrypt_records(&mut reader, &mut writer, &keys, &header, &prefix)?;
        writer
            .flush()
            .map_err(|error| AppError::new(error.to_string()))?;
    }
    commit_output(temporary, output)
}

fn encrypt_records(
    reader: &mut impl Read,
    writer: &mut impl Write,
    keys: &Keys,
    header: &[u8],
    prefix: &[u8; PREFIX_SIZE],
) -> AppResult<()> {
    let mut counter = 0_u64;
    let mut current = vec![0_u8; CHUNK_SIZE];
    let mut next = vec![0_u8; CHUNK_SIZE];
    let mut current_len = read_chunk(reader, &mut current)?;
    loop {
        let next_len = if current_len == CHUNK_SIZE {
            read_chunk(reader, &mut next)?
        } else {
            0
        };
        let final_record = current_len < CHUNK_SIZE || next_len == 0;
        let length = u32::try_from(current_len).map_err(|_| integrity_error())?;
        let aad = make_aad(header, counter, final_record, length);
        let ciphertext = encrypt_payload(
            &keys.encryption,
            prefix,
            counter,
            &aad,
            &current[..current_len],
        )?;
        if ciphertext.len() != current_len + CIPHER_OVERHEAD {
            return Err(integrity_error());
        }
        let tag = make_tag(&keys.authentication, &aad, &ciphertext);
        write_record(writer, length, final_record, &ciphertext, &tag)?;
        if final_record {
            return Ok(());
        }
        counter = counter.checked_add(1).ok_or_else(integrity_error)?;
        std::mem::swap(&mut current, &mut next);
        current_len = next_len;
    }
}

fn write_record(
    writer: &mut impl Write,
    length: u32,
    final_record: bool,
    ciphertext: &[u8],
    tag: &[u8; MAC_TAG_SIZE],
) -> AppResult<()> {
    writer
        .write_all(&length.to_be_bytes())
        .and_then(|_| writer.write_all(&[u8::from(final_record)]))
        .and_then(|_| writer.write_all(ciphertext))
        .and_then(|_| writer.write_all(tag))
        .map_err(|error| AppError::new(error.to_string()))
}

fn read_chunk(reader: &mut impl Read, buffer: &mut [u8]) -> AppResult<usize> {
    let mut total = 0;
    while total < buffer.len() {
        match reader.read(&mut buffer[total..]) {
            Ok(0) => break,
            Ok(read) => total += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(AppError::new(error.to_string())),
        }
    }
    Ok(total)
}

fn decrypt_file(input: &Path, output: &Path, password: &str) -> AppResult<()> {
    validate_paths(input, output)?;
    let input_file = open_regular_file(input)?;
    let mut reader =
        BufReader::with_capacity(CHUNK_SIZE + CIPHER_OVERHEAD + MAC_TAG_SIZE, input_file);
    let (header, salt, prefix) = parse_header(&mut reader)?;
    let keys = derive_keys(password, &salt);
    let mut temporary = create_temporary_output(output)?;

    {
        let mut writer = BufWriter::with_capacity(CHUNK_SIZE, temporary.as_file_mut());
        decrypt_records(&mut reader, &mut writer, &keys, &header, &prefix)?;
        writer
            .flush()
            .map_err(|error| AppError::new(error.to_string()))?;
    }
    commit_output(temporary, output)
}

fn decrypt_records(
    reader: &mut impl Read,
    writer: &mut impl Write,
    keys: &Keys,
    header: &[u8],
    prefix: &[u8; PREFIX_SIZE],
) -> AppResult<()> {
    let mut counter = 0_u64;
    loop {
        let mut record_header = [0_u8; 5];
        reader
            .read_exact(&mut record_header)
            .map_err(|_| integrity_error())?;
        let length = u32::from_be_bytes(
            record_header[..4]
                .try_into()
                .map_err(|_| integrity_error())?,
        );
        let final_record = match record_header[4] {
            0 => false,
            1 => true,
            _ => return Err(integrity_error()),
        };
        if length as usize > CHUNK_SIZE || (!final_record && length as usize != CHUNK_SIZE) {
            return Err(integrity_error());
        }
        let payload_len = (length as usize)
            .checked_add(CIPHER_OVERHEAD)
            .ok_or_else(integrity_error)?;
        let stored_len = payload_len
            .checked_add(MAC_TAG_SIZE)
            .ok_or_else(integrity_error)?;
        let mut stored = vec![0_u8; stored_len];
        reader
            .read_exact(&mut stored)
            .map_err(|_| integrity_error())?;
        let (ciphertext, tag) = stored.split_at(payload_len);
        let aad = make_aad(header, counter, final_record, length);

        // Encrypt-then-MAC: authenticate before invoking any decryption primitive.
        verify_tag(&keys.authentication, &aad, ciphertext, tag)?;
        let plaintext = decrypt_payload(&keys.encryption, prefix, counter, &aad, ciphertext)?;
        if plaintext.len() != length as usize {
            return Err(integrity_error());
        }
        writer
            .write_all(&plaintext)
            .map_err(|_| integrity_error())?;
        if final_record {
            let mut trailing = [0_u8; 1];
            if reader.read(&mut trailing).map_err(|_| integrity_error())? != 0 {
                return Err(integrity_error());
            }
            return Ok(());
        }
        counter = counter.checked_add(1).ok_or_else(integrity_error)?;
    }
}

fn validate_paths(input: &Path, output: &Path) -> AppResult<()> {
    if input == output {
        return Err(integrity_error());
    }
    if output
        .try_exists()
        .map_err(|error| AppError::new(error.to_string()))?
    {
        return Err(integrity_error());
    }
    Ok(())
}

fn open_regular_file(path: &Path) -> AppResult<File> {
    let file = File::open(path).map_err(|error| AppError::new(error.to_string()))?;
    if !file
        .metadata()
        .map_err(|error| AppError::new(error.to_string()))?
        .is_file()
    {
        return Err(integrity_error());
    }
    Ok(file)
}

fn output_parent(output: &Path) -> &Path {
    output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn create_temporary_output(output: &Path) -> AppResult<tempfile::NamedTempFile> {
    tempfile::Builder::new()
        .prefix(&format!(".{APP_NAME}-"))
        .suffix(".tmp")
        .tempfile_in(output_parent(output))
        .map_err(|error| AppError::new(error.to_string()))
}

fn commit_output(temporary: tempfile::NamedTempFile, output: &Path) -> AppResult<()> {
    temporary
        .as_file()
        .sync_all()
        .map_err(|error| AppError::new(error.to_string()))?;
    let committed = temporary
        .persist_noclobber(output)
        .map_err(|error| AppError::new(error.error.to_string()))?;
    committed
        .sync_all()
        .map_err(|error| AppError::new(error.to_string()))?;
    sync_output_directory(output_parent(output))
}

#[cfg(unix)]
fn sync_output_directory(directory: &Path) -> AppResult<()> {
    File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(|error| AppError::new(error.to_string()))
}

#[cfg(not(unix))]
fn sync_output_directory(_directory: &Path) -> AppResult<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    const PASSWORD: &str = "password";

    fn bytes(length: usize) -> Vec<u8> {
        (0..length)
            .map(|index| ((index * (APP_ID as usize + 17)) & 255) as u8)
            .collect()
    }

    #[test]
    fn payload_primitive_is_reversible_and_not_identity() {
        let key = vec![0x5a; ENC_KEY_SIZE];
        let prefix = [0xa5; PREFIX_SIZE];
        let aad = b"direct primitive test";
        let plaintext = bytes(257);
        let ciphertext = encrypt_payload(&key, &prefix, 7, aad, &plaintext).unwrap();
        assert_ne!(&ciphertext[..plaintext.len()], plaintext);
        let recovered = decrypt_payload(&key, &prefix, 7, aad, &ciphertext).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn round_trips_boundaries() {
        for length in [0, 1, CHUNK_SIZE - 1, CHUNK_SIZE, CHUNK_SIZE + 1] {
            let directory = TempDir::new().unwrap();
            let input = directory.path().join("input");
            let encrypted = directory.path().join("encrypted");
            let output = directory.path().join("output");
            let data = bytes(length);
            fs::write(&input, &data).unwrap();
            encrypt_file(&input, &encrypted, PASSWORD).unwrap();
            decrypt_file(&encrypted, &output, PASSWORD).unwrap();
            assert_eq!(fs::read(output).unwrap(), data);
        }
    }

    #[test]
    fn randomized_tamper_evident_and_verify_before_decrypt() {
        let directory = TempDir::new().unwrap();
        let input = directory.path().join("input");
        let first = directory.path().join("first");
        let second = directory.path().join("second");
        fs::write(&input, bytes(1234)).unwrap();
        encrypt_file(&input, &first, PASSWORD).unwrap();
        encrypt_file(&input, &second, PASSWORD).unwrap();
        assert_ne!(fs::read(&first).unwrap(), fs::read(&second).unwrap());
        let mut damaged = fs::read(&first).unwrap();
        let middle = damaged.len() / 2;
        damaged[middle] ^= 1;
        fs::write(&first, damaged).unwrap();
        let output = directory.path().join("output");
        assert!(decrypt_file(&first, &output, PASSWORD).is_err());
        assert!(!output.exists());
    }

    #[test]
    fn rejects_sibling_format_and_wrong_password() {
        let directory = TempDir::new().unwrap();
        let input = directory.path().join("input");
        let encrypted = directory.path().join("encrypted");
        let output = directory.path().join("output");
        fs::write(&input, bytes(73)).unwrap();
        encrypt_file(&input, &encrypted, PASSWORD).unwrap();
        assert!(decrypt_file(&encrypted, &output, "wrong password").is_err());
        assert!(!output.exists());

        let salt = [0_u8; SALT_SIZE];
        let prefix = [0_u8; PREFIX_SIZE];
        let mut header = make_header(&salt, &prefix);
        let sibling_id = if APP_ID == 50 { 49 } else { APP_ID + 1 };
        header[7] = sibling_id;
        header[9] = sibling_id;
        assert!(parse_header(&mut header.as_slice()).is_err());
    }

    #[test]
    fn identity_names_the_real_payload_algorithm() {
        assert_eq!(MAGIC[7], APP_ID);
        assert!(SUITE_NAME.contains(PAYLOAD_ALGORITHM));
        assert!(!PAYLOAD_ALGORITHM.is_empty());
    }
}
