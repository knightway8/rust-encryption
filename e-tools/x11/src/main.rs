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

const APP_NAME: &str = env!("CARGO_PKG_NAME");
const APP_ID: u8 = 11;
const SUITE_NAME: &str = "PBKDF2-SHA384-Forro14-Poly1305-131072-records";
const MAGIC: [u8; 8] = [69, 84, 79, 79, 76, 0, 0, APP_ID];
const VERSION: u8 = 1;
const INTEGRITY_ERROR: &str = "decryption failed or input is invalid";
const SALT_SIZE: usize = 16;
const PREFIX_SIZE: usize = 4;
const HEADER_SIZE: usize = 8 + 1 + 1 + SALT_SIZE + PREFIX_SIZE;
const TAG_SIZE: usize = 16;
const NONCE_SIZE: usize = 12;
const KEY_MATERIAL_SIZE: usize = 32;
const CHUNK_SIZE: usize = 131072;
const MAX_PASSWORD_BYTES: usize = 4096;

type AppResult<T> = Result<T, AppError>;

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
    let result = run_cli();
    if let Err(error) = result {
        eprintln!("{}", APP_NAME);
        eprintln!("{}", error);
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

fn run_cli() -> AppResult<()> {
    let command = parse_args(env::args_os().skip(1).collect())?;
    let password = read_password(command.mode)?;
    match command.mode {
        Mode::Encrypt => encrypt_file(&command.input, &command.output, &password),
        Mode::Decrypt => decrypt_file(&command.input, &command.output, &password),
    }
}

fn usage() -> String {
    format!("Usage: {APP_NAME} E|D <input> <output>\nSuite: {SUITE_NAME}")
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
    if password.is_empty() {
        return Err(AppError::new(usage()));
    }
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(AppError::new(usage()));
    }
    Ok(())
}

fn derive_key(password: &str, salt: &[u8; SALT_SIZE]) -> AppResult<Vec<u8>> {
    let mut key = vec![0_u8; KEY_MATERIAL_SIZE];
    let rounds = if cfg!(test) { 1 } else { 180_000 };
    pbkdf2::pbkdf2_hmac::<sha2::Sha384>(password.as_bytes(), salt, rounds, &mut key);
    Ok(key)
}

fn seal_record(
    key: &[u8],
    nonce: &[u8; NONCE_SIZE],
    message: &[u8],
    aad: &[u8],
) -> AppResult<Vec<u8>> {
    let key: &[u8; 32] = key.try_into().map_err(|_| integrity_error())?;
    let cipher = forro::Forro14Poly1305::new(key);
    let mut ciphertext = vec![0_u8; message.len() + TAG_SIZE];
    cipher
        .seal(&mut ciphertext, nonce, message, aad)
        .map_err(|_| integrity_error())?;
    Ok(ciphertext)
}

fn open_record(
    key: &[u8],
    nonce: &[u8; NONCE_SIZE],
    ciphertext: &[u8],
    aad: &[u8],
) -> AppResult<Vec<u8>> {
    let key: &[u8; 32] = key.try_into().map_err(|_| integrity_error())?;
    let plaintext_len = ciphertext
        .len()
        .checked_sub(TAG_SIZE)
        .ok_or_else(integrity_error)?;
    let mut plaintext = vec![0_u8; plaintext_len];
    forro::Forro14Poly1305::new(key)
        .open(&mut plaintext, nonce, ciphertext, aad)
        .map_err(|_| integrity_error())?;
    Ok(plaintext)
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

fn make_nonce(prefix: &[u8; PREFIX_SIZE], counter: u64) -> [u8; NONCE_SIZE] {
    let mut nonce = [0_u8; NONCE_SIZE];
    nonce[..PREFIX_SIZE].copy_from_slice(prefix);
    nonce[PREFIX_SIZE..].copy_from_slice(&counter.to_be_bytes());
    nonce
}
fn make_aad(header: &[u8], counter: u64, final_record: bool, length: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(header.len() + 13);
    aad.extend_from_slice(header);
    aad.extend_from_slice(&counter.to_be_bytes());
    aad.push(u8::from(final_record));
    aad.extend_from_slice(&length.to_be_bytes());
    aad
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
    let key = derive_key(password, &salt)?;
    let header = make_header(&salt, &prefix);

    {
        let mut writer = BufWriter::with_capacity(CHUNK_SIZE, temporary.as_file_mut());
        writer
            .write_all(&header)
            .map_err(|error| AppError::new(error.to_string()))?;
        encrypt_records(&mut reader, &mut writer, &key, &header, &prefix)?;
        writer
            .flush()
            .map_err(|error| AppError::new(error.to_string()))?;
    }
    commit_output(temporary, output)
}

fn encrypt_records(
    reader: &mut impl Read,
    writer: &mut impl Write,
    key: &[u8],
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
        let length = current_len as u32;
        let nonce = make_nonce(prefix, counter);
        let aad = make_aad(header, counter, final_record, length);
        let ciphertext = seal_record(key, &nonce, &current[..current_len], &aad)?;
        write_record(writer, length, final_record, &ciphertext)?;
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
    data: &[u8],
) -> AppResult<()> {
    writer
        .write_all(&length.to_be_bytes())
        .map_err(|error| AppError::new(error.to_string()))?;
    writer
        .write_all(&[u8::from(final_record)])
        .map_err(|error| AppError::new(error.to_string()))?;
    writer
        .write_all(data)
        .map_err(|error| AppError::new(error.to_string()))?;
    Ok(())
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
    let mut reader = BufReader::with_capacity(CHUNK_SIZE + TAG_SIZE, input_file);
    let (header, salt, prefix) = parse_header(&mut reader)?;
    let key = derive_key(password, &salt).map_err(|_| integrity_error())?;
    let mut temporary = create_temporary_output(output)?;

    {
        let mut writer = BufWriter::with_capacity(CHUNK_SIZE, temporary.as_file_mut());
        decrypt_records(&mut reader, &mut writer, &key, &header, &prefix)?;
        writer
            .flush()
            .map_err(|error| AppError::new(error.to_string()))?;
    }
    commit_output(temporary, output)
}

fn decrypt_records(
    reader: &mut impl Read,
    writer: &mut impl Write,
    key: &[u8],
    header: &[u8],
    prefix: &[u8; PREFIX_SIZE],
) -> AppResult<()> {
    let mut counter = 0_u64;
    loop {
        let mut record_header = [0_u8; 5];
        reader
            .read_exact(&mut record_header)
            .map_err(|_| integrity_error())?;
        let length = u32::from_be_bytes([
            record_header[0],
            record_header[1],
            record_header[2],
            record_header[3],
        ]);
        let final_record = match record_header[4] {
            0 => false,
            1 => true,
            _ => return Err(integrity_error()),
        };
        if length as usize > CHUNK_SIZE || (!final_record && length as usize != CHUNK_SIZE) {
            return Err(integrity_error());
        }
        let mut ciphertext = vec![0_u8; length as usize + TAG_SIZE];
        reader
            .read_exact(&mut ciphertext)
            .map_err(|_| integrity_error())?;
        let nonce = make_nonce(prefix, counter);
        let aad = make_aad(header, counter, final_record, length);
        let plaintext = open_record(key, &nonce, &ciphertext, &aad)?;
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
        .prefix(&format!(".{}-", APP_NAME))
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
    fn randomized_and_tamper_evident() {
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
    fn rejects_a_sibling_format_id() {
        let salt = [0_u8; SALT_SIZE];
        let prefix = [0_u8; PREFIX_SIZE];
        let mut header = make_header(&salt, &prefix);
        let sibling_id = if APP_ID == 50 { 49 } else { APP_ID + 1 };
        header[7] = sibling_id;
        header[9] = sibling_id;
        assert!(parse_header(&mut header.as_slice()).is_err());
    }

    #[test]
    fn payload_algorithm_smoke() {
        let key = vec![APP_ID; KEY_MATERIAL_SIZE];
        let nonce = [APP_ID; NONCE_SIZE];
        let message = b"algorithm-specific smoke";
        let aad = b"fixed format and record metadata";
        let ciphertext = seal_record(&key, &nonce, message, aad).unwrap();
        assert!(ciphertext.len() >= message.len() + 16);
        assert_eq!(
            open_record(&key, &nonce, &ciphertext, aad).unwrap(),
            message
        );

        let mut damaged = ciphertext;
        let middle = damaged.len() / 2;
        damaged[middle] ^= 1;
        assert!(open_record(&key, &nonce, &damaged, aad).is_err());
    }
    #[test]
    fn unique_magic_matches_app_id() {
        assert_eq!(MAGIC[7], APP_ID);
        assert!(!SUITE_NAME.is_empty());
    }
}
