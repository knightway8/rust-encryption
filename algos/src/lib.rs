#![forbid(unsafe_code)]
//! Shared, auditable core for the thirty algorithm-specific file CLIs.

pub mod cli;

mod crypto;
mod envelope;
mod error;
mod format;
mod kdf;
mod suites;

pub use error::{Error, Result};
pub use suites::{ALL_SUITES, Suite};
