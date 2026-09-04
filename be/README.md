# be — Best Encryption

`be` is a conservative file-encryption CLI that produces standard age v1 files.
Its ciphertext is interoperable with the reference `age` implementation and the
Rust `rage` implementation.

## Commands

Keep the executable in a writable directory. All key and data files must be in
that same directory, and command arguments must be bare file names.

```text
be keygen
be E document.pdf document.pdf.age
be verify document.pdf.age
be D document.pdf.age recovered.pdf
be pubkey
```

`keygen` creates:

- `key.key`: the age X25519 secret identity required for decryption; and
- `key.pub`: the corresponding public recipient used for encryption.

Back up `key.key` securely. Losing it makes the ciphertext unrecoverable. The
public key can be shared. Encryption can operate with only `key.pub`; when both
files are present, `be` verifies that they match before encrypting.

Existing keys and output files are never overwritten.

## Reliability and security properties

- Standard age v1 format rather than a custom cipher construction.
- X25519 recipient encryption, HKDF-SHA-256 key derivation, and
  ChaCha20-Poly1305 authenticated encryption.
- Authenticated 64 KiB streaming chunks, so large files do not consume large RAM.
- Encryption output is finalized, flushed, and synchronized before an atomic,
  no-overwrite commit.
- Decryption performs a full authentication pass before creating plaintext,
  then decrypts and authenticates again. SHA-256 digests from both passes must
  match, detecting concurrent replacement.
- Decrypted output is written privately and atomically committed only after the
  entire ciphertext is authenticated.
- Strict filename confinement, regular-file checks, key-pair matching, and
  private-key permission checks on Unix.
- Plugin, SSH, passphrase, and ASCII-armor features are disabled to minimize the
  attack surface.

## Build and assurance checks

```text
cargo test --locked
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo build --release --locked
```

The project contains more than 100 individually named tests, plus property tests
covering randomized content, corruption, truncation, boundaries, wrong keys,
key handling, and no-overwrite behavior.

## Security status

The age format is public and interoperable, but this wrapper has not received an
independent professional security audit. No amount of automated testing alone
can establish that software is “production grade.” Commission an independent
review before using it where failure could cause severe harm, and keep tested,
offline backups of both data and `key.key`.
