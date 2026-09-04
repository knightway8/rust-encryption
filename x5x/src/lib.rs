//! Shared implementation for the x3x command-line encryption tools.
//!
//! Every executable is intentionally tiny and delegates to this library so the
//! security-sensitive file format and I/O rules have one auditable implementation.

mod algorithm;
pub mod cli;
mod crypto;
mod io_util;
mod key_text;
mod key_tools;
mod otp_tool;
pub mod x4x;

pub use algorithm::{Algorithm, Mode};
pub use crypto::{CHUNK_SIZE, process_file_in, process_password_file_in};
pub use key_text::{binary_key_to_text_in, text_to_binary_key_in};
pub use key_tools::{MAX_KEY_SIZE, generate_random_key_in, make_deterministic_key_in};
pub use otp_tool::xor_file_in_place;
