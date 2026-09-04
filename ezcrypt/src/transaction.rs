use crate::crypto::{decrypt_stream, encrypt_stream, random_material};
use crate::error::EzError;
use crate::format::KdfParams;
use crate::pathing::{Operation, TransformPlan, ensure_destination_absent, plan_for_path};
use crate::platform::{ParentDirectory, PendingOutput, SourceDeleteError, SourceFile};
use blake3::{Hash, Hasher};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use zeroize::Zeroizing;

const IO_BUFFER_SIZE: usize = 256 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransformOutcome {
    operation: Operation,
    input: std::path::PathBuf,
    output: std::path::PathBuf,
    bytes: u64,
}

impl TransformOutcome {
    pub fn operation(&self) -> Operation {
        self.operation
    }

    pub fn input(&self) -> &Path {
        &self.input
    }

    pub fn output(&self) -> &Path {
        &self.output
    }

    pub fn plaintext_bytes(&self) -> u64 {
        self.bytes
    }
}

pub fn transform_file(
    path: impl AsRef<Path>,
    password: &[u8],
) -> Result<TransformOutcome, EzError> {
    let plan = plan_for_path(path)?;
    transform_plan(&plan, password, KdfParams::default())
}

pub(crate) fn transform_plan(
    plan: &TransformPlan,
    password: &[u8],
    kdf: KdfParams,
) -> Result<TransformOutcome, EzError> {
    crate::crypto::validate_password(password)?;
    ensure_destination_absent(plan.output())?;

    let parent_path = plan
        .input()
        .parent()
        .ok_or(EzError::InvalidPath("input has no containing directory"))?;
    let parent = ParentDirectory::open(parent_path)?;
    let mut source = SourceFile::open(plan.input())?;
    ensure_destination_absent(plan.output())?;
    let source_len = source.len();
    let mut pending = PendingOutput::create(parent_path)?;
    let temp_path = pending.path().to_path_buf();
    // Apply the source's restrictive DACL before any transformed bytes (especially
    // plaintext during decryption) enter the temporary file.
    pending.apply_source_security(&source.file)?;
    pending.sync()?;

    let (written_len, plaintext_len, expected_digest, source_digest) = {
        // The crypto layer already works in 1 MiB chunks. Avoid generic buffered I/O
        // here so decrypted plaintext is not left in non-zeroizing library buffers.
        let mut reader = HashingReader::new(&mut source.file);
        let mut writer = HashingWriter::new(pending.file_mut());
        let result = match plan.operation() {
            Operation::Encrypt => {
                let (salt, nonce_prefix) = random_material()?;
                encrypt_stream(
                    &mut reader,
                    &mut writer,
                    source_len,
                    password,
                    kdf,
                    salt,
                    nonce_prefix,
                    plan.input(),
                    &temp_path,
                )
                .map(|written| (written, source_len))
            }
            Operation::Decrypt => decrypt_stream(
                &mut reader,
                &mut writer,
                source_len,
                password,
                plan.input(),
                &temp_path,
            )
            .map(|plaintext| (plaintext, plaintext)),
        }?;
        writer
            .flush()
            .map_err(|source| EzError::io("flush buffered temporary output", &temp_path, source))?;
        let digest = writer.digest();
        (result.0, result.1, digest, reader.digest())
    };

    pending.sync()?;
    verify_readback(pending.file_mut(), written_len, expected_digest, &temp_path)?;
    if plan.operation() == Operation::Encrypt {
        verify_encrypted_output(
            pending.file_mut(),
            written_len,
            source_len,
            source_digest,
            password,
            &temp_path,
        )?;
    }
    pending.apply_source_metadata(&source.info)?;
    pending.sync()?;
    verify_source_readback(&mut source.file, source_len, source_digest, plan.input())?;
    source.verify_unchanged(plan.input())?;

    // Retain the committed output's no-sharing handle until source deletion has
    // completed. This prevents a concurrent remove/replace from creating a
    // neither-file state in the final transaction window.
    let committed = pending.publish(plan.output(), &parent)?;
    if let Err(source_error) = source.delete() {
        return Err(match source_error {
            SourceDeleteError::Retained(source) => EzError::CommittedButSourceRetained {
                input: plan.input().to_path_buf(),
                output: plan.output().to_path_buf(),
                source,
            },
            SourceDeleteError::RemovalUnconfirmed(source) => {
                EzError::CommittedSourceRemovalUnconfirmed {
                    input: plan.input().to_path_buf(),
                    output: plan.output().to_path_buf(),
                    source,
                }
            }
        });
    }
    drop(committed);

    Ok(TransformOutcome {
        operation: plan.operation(),
        input: plan.input().to_path_buf(),
        output: plan.output().to_path_buf(),
        bytes: plaintext_len,
    })
}

fn verify_encrypted_output(
    file: &mut File,
    encrypted_len: u64,
    expected_plaintext_len: u64,
    expected_plaintext_digest: Hash,
    password: &[u8],
    path: &Path,
) -> Result<(), EzError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|source| EzError::io("rewind encrypted verification output", path, source))?;
    let mut sink = HashingWriter::new(io::sink());
    let plaintext_len = decrypt_stream(file, &mut sink, encrypted_len, password, path, path)
        .map_err(|_| EzError::VerificationFailed(path.to_path_buf()))?;
    if plaintext_len != expected_plaintext_len || sink.digest() != expected_plaintext_digest {
        return Err(EzError::VerificationFailed(path.to_path_buf()));
    }
    Ok(())
}

fn verify_source_readback(
    file: &mut File,
    expected_len: u64,
    expected_digest: Hash,
    path: &Path,
) -> Result<(), EzError> {
    if file
        .metadata()
        .map_err(|source| EzError::io("re-inspect input", path, source))?
        .len()
        != expected_len
    {
        return Err(EzError::InputChanged(path.to_path_buf()));
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|source| EzError::io("rewind input for verification", path, source))?;
    let mut hasher = Hasher::new();
    let mut buffer = Zeroizing::new(vec![0u8; IO_BUFFER_SIZE]);
    let mut remaining = expected_len;
    while remaining != 0 {
        let wanted = remaining.min(buffer.len() as u64) as usize;
        let count = read_retry(file, &mut buffer[..wanted])
            .map_err(|source| EzError::io("verify input contents", path, source))?;
        if count == 0 {
            return Err(EzError::InputChanged(path.to_path_buf()));
        }
        hasher.update(&buffer[..count]);
        remaining -= count as u64;
    }
    let mut probe = [0u8; 1];
    if read_retry(file, &mut probe)
        .map_err(|source| EzError::io("finish verifying input", path, source))?
        != 0
        || hasher.finalize() != expected_digest
    {
        return Err(EzError::InputChanged(path.to_path_buf()));
    }
    Ok(())
}

fn verify_readback(
    file: &mut File,
    expected_len: u64,
    expected_digest: Hash,
    path: &Path,
) -> Result<(), EzError> {
    let actual_len = file
        .metadata()
        .map_err(|source| EzError::io("inspect temporary output", path, source))?
        .len();
    if actual_len != expected_len {
        return Err(EzError::VerificationFailed(path.to_path_buf()));
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|source| EzError::io("rewind temporary output", path, source))?;
    let mut hasher = Hasher::new();
    let mut buffer = Zeroizing::new(vec![0u8; IO_BUFFER_SIZE]);
    let mut remaining = expected_len;
    while remaining != 0 {
        let wanted = remaining.min(buffer.len() as u64) as usize;
        let count = read_retry(file, &mut buffer[..wanted])
            .map_err(|source| EzError::io("read back temporary output", path, source))?;
        if count == 0 {
            return Err(EzError::VerificationFailed(path.to_path_buf()));
        }
        hasher.update(&buffer[..count]);
        remaining -= count as u64;
    }
    let mut probe = [0u8; 1];
    if read_retry(file, &mut probe)
        .map_err(|source| EzError::io("finish verifying temporary output", path, source))?
        != 0
        || hasher.finalize() != expected_digest
    {
        return Err(EzError::VerificationFailed(path.to_path_buf()));
    }
    Ok(())
}

fn read_retry<R: Read>(reader: &mut R, bytes: &mut [u8]) -> io::Result<usize> {
    loop {
        match reader.read(bytes) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => return result,
        }
    }
}

struct HashingReader<R> {
    inner: R,
    hasher: Hasher,
}

impl<R> HashingReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            hasher: Hasher::new(),
        }
    }

    fn digest(&self) -> Hash {
        self.hasher.clone().finalize()
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let count = self.inner.read(bytes)?;
        self.hasher.update(&bytes[..count]);
        Ok(count)
    }
}

struct HashingWriter<W> {
    inner: W,
    hasher: Hasher,
}

impl<W> HashingWriter<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            hasher: Hasher::new(),
        }
    }

    fn digest(&self) -> Hash {
        self.hasher.clone().finalize()
    }
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let count = self.inner.write(bytes)?;
        self.hasher.update(&bytes[..count]);
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
