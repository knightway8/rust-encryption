#![cfg_attr(not(windows), allow(dead_code))]

#[cfg(not(windows))]
compile_error!("ezcrypt is intentionally supported only on Windows 11");

pub mod cli;
mod crypto;
mod error;
mod format;
mod pathing;
mod platform;
mod transaction;

pub use error::{EzError, FormatError};
pub use pathing::{Operation, TransformPlan, plan_for_path};
pub use transaction::{TransformOutcome, transform_file};

#[cfg(test)]
mod tests;
