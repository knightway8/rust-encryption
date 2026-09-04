#[path = "common/password_cipher.rs"]
mod common;

common::define_password_cipher_tests!(env!("CARGO_BIN_EXE_aegis128lp"), "aegis128lp");
