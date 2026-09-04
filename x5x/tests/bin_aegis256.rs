#[path = "common/key_cipher.rs"]
mod common;

common::define_key_cipher_tests!(
    env!("CARGO_BIN_EXE_aegis256"),
    "aegis256",
    "aegis256.key",
    32
);
