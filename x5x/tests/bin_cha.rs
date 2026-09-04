#[path = "common/key_cipher.rs"]
mod common;

common::define_key_cipher_tests!(env!("CARGO_BIN_EXE_cha"), "cha", "cha.key", 32);
