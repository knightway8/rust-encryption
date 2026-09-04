#[path = "common/key_cipher.rs"]
mod common;

common::define_key_cipher_tests!(
    env!("CARGO_BIN_EXE_aegis128l"),
    "aegis128l",
    "aegis128l.key",
    16
);
