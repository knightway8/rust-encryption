#![forbid(unsafe_code)]

mod algorithms;
pub mod cli;
mod container;
pub mod error;
mod file_io;
mod key_store;
#[cfg(unix)]
mod unix_fs;

use zeroize::Zeroizing;

pub use algorithms::Algorithm;
use cli::{Command, Operation};
use error::AppError;
use key_store::KeyStore;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn execute(command: Command) -> Result<(), AppError> {
    match command {
        Command::Help | Command::Version => Ok(()),
        Command::Keygen => KeyStore::beside_current_executable()?.generate_all(),
        Command::Transform {
            algorithm,
            operation,
            input,
            output,
        } => {
            // Binding opens and validates the destination directory but does
            // not create an entry. In particular, a decrypt authenticates
            // successfully before `write_atomic_noclobber` creates plaintext.
            let output_target = file_io::OutputTarget::bind(&output)?;
            let key_store = KeyStore::beside_current_executable()?;
            let master_key = key_store.read(algorithm)?;
            let input_bytes = file_io::read_regular_file(&input)?;
            let output_bytes = match operation {
                Operation::Encrypt => {
                    let envelope_len = container::encrypted_len(algorithm, input_bytes.len())?;
                    if u64::try_from(envelope_len).map_err(|_| AppError::InputTooLarge)?
                        > file_io::MAX_FILE_BYTES
                    {
                        return Err(AppError::InputTooLarge);
                    }
                    Zeroizing::new(container::encrypt(algorithm, &master_key, &input_bytes)?)
                }
                Operation::Decrypt => container::decrypt(algorithm, &master_key, &input_bytes)?,
            };
            output_target.write_atomic_noclobber(&output_bytes)
        }
    }
}
