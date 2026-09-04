# `algos`: 30 authenticated file-encryption suites

This workspace builds 30 small Rust command-line programs. Each executable is
fixed to one cipher suite, while parsing, password handling, key derivation,
record framing, authenticated encryption, and safe file publication live in one
shared library. The result is intentionally repetitive at the CLI boundary and
centralized everywhere security-sensitive, which makes the mapping from binary
name to suite easy to inspect.

> **Security status:** this is an educational and evaluation-oriented project,
> not an independently audited encryption product. Keep backups and do not make
> it the only protection for valuable data. Suites 1–8 use native AEAD
> constructions. Suites 9–30 use this project's custom Encrypt-then-HMAC
> composition; several underlying ciphers are niche or legacy choices. See
> [Security](docs/SECURITY.md) before choosing a binary.

## What “30 algorithms” means here

The repository contains exactly **30 cipher suites**, not 30 unrelated primitive
families. Key-size variants have distinct stable suite IDs and distinct
executables. The catalog is:

- 8 native AEAD suites: AES-GCM, AES-GCM-SIV, AES-CMAC-SIV,
  ChaCha20-Poly1305, and XChaCha20-Poly1305 variants;
- 22 custom Encrypt-then-HMAC-SHA256 suites built from CTR-mode block ciphers
  or native stream ciphers.

The complete ID, binary, key, nonce, tag, and status table is in
[Algorithms](docs/ALGORITHMS.md).

## Build

Rust 1.85 or newer is required.

```text
cargo build --release --bins
```

The executables are written under `target/release/` (`.exe` is added on
Windows). For example, `aes256-gcm-file` handles only suite 2,
AES-256-GCM. A file encrypted by a different suite is rejected rather than
silently dispatched to another implementation.

## CLI contract

Every one of the 30 binaries has the same interface:

```text
<binary> encrypt -i <INPUT> -o <OUTPUT> [--password-file <PATH>]
<binary> decrypt -i <INPUT> -o <OUTPUT> [--password-file <PATH>]
```

Long forms `--input` and `--output` are equivalent to `-i` and `-o`.

For example:

```text
target/release/aes256-gcm-file encrypt --input report.pdf --output report.pdf.algo
target/release/aes256-gcm-file decrypt --input report.pdf.algo --output recovered-report.pdf
```

Without `--password-file`, the password is read through a hidden terminal
prompt. Encryption asks for confirmation; decryption does not. A password file
is read as exact bytes: a trailing CR or LF is part of the password. Empty
passwords and password files larger than 1 MiB are rejected. Protect password
files with appropriate filesystem permissions and avoid tools that add an
unintended newline.

The interface deliberately has no inline password argument, stdin/stdout data
mode, in-place mode, or force-overwrite option. Input and output must be
different files. An existing output is never overwritten. Work is written to a
temporary file in the destination directory and the final name is published
with a no-overwrite operation only after the complete encryption or
authenticated decryption succeeds. “Atomic” here describes publication of the
completed output; it is not a promise of power-loss durability.

The input must be a regular file. The output's parent directory must already
exist and be writable, and the output path must not exist as a file, directory,
or symlink. Successful encrypt/decrypt operations are silent and return status
zero; usage or operational failures are reported on stderr with a nonzero
status. There is no required filename extension.

## Format at a glance

Version 1 files contain:

```text
80-byte header
zero or more authenticated data records
one mandatory authenticated empty FINAL record
```

Plaintext is processed in 65,536-byte records. Passwords feed a fixed Argon2id
v1 profile (64 MiB, three passes, one lane), and HKDF-SHA256 derives
suite-separated, per-record encryption keys. Every record authenticates the
entire header and its own 16-byte record header. The FINAL record makes
truncation detectable even for empty files and exact chunk boundaries.

The byte-for-byte specification is in [Format](docs/FORMAT.md). It is the right
starting point for interoperability work; do not infer a wire format from a
primitive's crate API.

## Documentation

- [Algorithms](docs/ALGORITHMS.md) — the exact 30-suite registry and caveats
- [Format](docs/FORMAT.md) — canonical bytes, KDF, keys, nonces, AAD, and tags
- [Architecture](docs/ARCHITECTURE.md) — module ownership and audit workflow
- [Testing](docs/TESTING.md) — test layers, commands, and future change gates
- [Security](docs/SECURITY.md) — threat model, guarantees, and limitations

## Development checks

```text
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
```

Cryptographic round trips are necessary but not sufficient. Any suite change
must retain authoritative primitive known-answer tests, composition tests,
all-suite envelope tests, corruption/truncation tests, and CLI atomicity tests.
[Testing](docs/TESTING.md) explains the expected coverage and how to distinguish
standards-based vectors from local regression fixtures.

## Repository map

- [`src/suites.rs`](src/suites.rs) is the authoritative 30-entry registry.
- [`src/format.rs`](src/format.rs) owns canonical fixed-width serialization.
- [`src/kdf.rs`](src/kdf.rs) owns Argon2id, HKDF, and nonce derivation.
- [`src/crypto.rs`](src/crypto.rs) owns suite dispatch and record protection.
- [`src/envelope.rs`](src/envelope.rs) owns record sequencing and safe file I/O.
- [`src/cli.rs`](src/cli.rs) owns the common command-line and password contract.
- `src/bin/*.rs` contains 30 thin, suite-specific entry points.

The library forbids unsafe Rust. Dependency versions are pinned in
[`Cargo.toml`](Cargo.toml), and [`Cargo.lock`](Cargo.lock) records the resolved
dependency graph.
