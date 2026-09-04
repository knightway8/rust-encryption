//! Authenticated, bounded-memory file encryption with strict no-overwrite output handling.

#![deny(unsafe_code)]

mod crypto;
mod error;
mod format;
mod key;
mod staging;
#[cfg(windows)]
mod windows_security;

pub use crypto::{decrypt_file, encrypt_file};
pub use error::{FileCryptError, Result};
pub use format::{Algorithm, CHUNK_SIZE, HEADER_SIZE, MAX_PLAINTEXT_SIZE, RECORD_HEADER_SIZE};
pub use key::{
    KEY_FILE_NAME, KEY_SIZE, MasterKey, executable_key_path, generate_executable_key,
    generate_key_file, load_executable_key, load_key_file,
};
