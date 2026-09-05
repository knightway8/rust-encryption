# tf1024

`tf1024` is a small, cross-platform file-encryption CLI built around the full
80-round Threefish-1024 block cipher.

## Commands

Place the executable in a writable directory, then run:

```text
tf1024 keygen
tf1024 E input.bin input.bin.tf1024
tf1024 D input.bin.tf1024 recovered.bin
```

`keygen` creates a raw 128-byte `key.key`. The key, input, and output are always
looked up beside the executable. Arguments must therefore be bare file names,
not paths. Existing output files and an existing key are never overwritten.
On Windows, device names, alternate data streams, and names ending in a dot or
space are rejected so aliases cannot bypass the protection for `key.key`.

Back up `key.key` securely. Losing it makes encrypted files unrecoverable. Anyone
who obtains it can decrypt the files.

## File format and construction

Version 1 files contain:

- a 64-byte authenticated header (magic/version, plaintext length, 32-byte salt,
  and 16-byte Threefish tweak);
- ciphertext of the same length as the plaintext; and
- a 32-byte keyed BLAKE3 authentication tag.

The complete 1024-bit master key is used directly as the Threefish-1024 key. A
fresh 128-bit tweak is generated for every encryption. A separate per-file MAC
key is derived from the master key and 256-bit salt using BLAKE3 derive-key mode.
Encryption uses Threefish-1024 as a counter-mode keystream generator with a
128-bit block counter. The header and ciphertext are authenticated using
encrypt-then-MAC. Decryption authenticates before creating a private plaintext
temporary file, checks again while decrypting to detect concurrent changes, and
only commits the output after a constant-time tag check succeeds. Processing is
streaming, so file size is not limited by RAM.

## Important security note

Threefish-1024 is a real standardized primitive, but the RustCrypto `threefish`
crate labels itself low-level “hazmat” and states that it has not received a
security audit. This application adds authentication and misuse protections,
but the complete construction has not been independently audited. For critical
or long-term data, prefer a widely reviewed format such as age unless
Threefish-1024 is a firm interoperability requirement.

## Build and test

Rust 1.98.1 is required and pinned in `rust-toolchain.toml`.

```text
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo build --release
```
