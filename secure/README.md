# secure

`secure` is a Linux-only command-line program for password-encrypting one file
into another. It uses the standardized binary
[age v1](https://age-encryption.org/v1) format rather than a custom encryption
format.

## Requirements

- Linux kernel 5.6 or newer (`openat2` is used to reject symlinks throughout
  input and output-directory paths)
- Rust 1.98.1 or newer to build
- About 256 MiB of available memory per encryption or decryption
- An output filesystem with Linux `O_TMPFILE` support for decryption (required
  so unauthenticated temporary plaintext never has a pathname)
- An accessible `/proc/self/fd` when the kernel denies unprivileged
  `linkat(AT_EMPTY_PATH)` publication; systems that permit the direct link do
  not need the procfs fallback

## Build

```console
cargo build --release --locked
```

Use the release binary for normal work. Password hardening is deliberately
expensive and is much slower in an unoptimized debug build.

## Usage

```console
./target/release/secure E document.pdf document.pdf.age
./target/release/secure D document.pdf.age recovered-document.pdf
```

`E` and `D` must be uppercase. Encryption prompts for the password twice;
decryption prompts once. Passwords are read from the controlling terminal with
echo disabled, never from command-line arguments or environment variables.

New encryption passwords must be at least 12 Unicode characters and no more
than 1,024 UTF-8 bytes. Spaces are significant. Passwords are not trimmed or
Unicode-normalized, so enter the exact same sequence when decrypting. For real
security, use a password-manager-generated value or at least five randomly
selected words; the 12-character check cannot measure entropy.

The destination must not already exist. This is intentional: `secure` never
overwrites files. Every output has mode `0600` and contains no original
filename, permissions, owner, timestamps, ACLs, or extended attributes.

## Security design

- Standard age v1 passphrase files. Current age/rage tools can decrypt files
  produced by `secure`; inbound passphrase files are accepted only when their
  scrypt `logN` is at most 18. The inbound cap intentionally rejects otherwise
  valid, more expensive age files to prevent CPU/memory denial of service.
- A fresh random file key, salt, and payload nonce for every encryption.
- Scrypt with fixed `logN = 18`, `r = 8`, and `p = 1` (approximately 256 MiB),
  with the same value enforced as the maximum accepted decryption work factor.
- Authenticated ChaCha20-Poly1305 streaming in 64 KiB records. The entire input
  is read through the authenticated final record before plaintext is published.
- A 64 KiB encrypted-header ceiling before age parsing, preventing unbounded
  header allocation from hostile files.
- Core dumps and dumpable-process inspection are disabled before password entry.
  Secret strings use zeroizing storage.
- Password input uses nonblocking terminal polling and an explicit restoration
  guard. A handled Ctrl-C or external termination request restores the full
  terminal configuration and returns the conventional signal exit code. If the
  request is observed before the final commit check, no destination is
  published; if atomic publication has already won the race, success is
  reported consistently.
- Input is opened once as a regular file with `openat2`, `O_NOFOLLOW`, and
  `RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`. FIFOs, sockets, devices,
  directories, and symlinks are refused.
- Decrypted output is written beside its destination only to Linux `O_TMPFILE`
  unnamed storage. If the filesystem cannot provide it, decryption fails closed
  instead of exposing temporary plaintext. Encryption may use a guarded,
  randomly named fallback because its temporary content is already ciphertext.
  Output is mode-forced to `0600`, fully flushed and `fsync`ed, then atomically
  published without replacement.
- The parent directory is `fsync`ed after publication. Failed encryption,
  authentication, writes, or publication leave no destination or partial
  plaintext.
- Encryption verifies the opened input's inode, size, modification time, and
  change time again before publishing, and discards the result if they changed.

## Important limitations

- Password encryption permits offline guessing. A weak or reused password is
  not rescued by a strong KDF.
- Ciphertext length reveals the approximate plaintext length. There is no
  padding.
- The source file is not deleted. Verify decryption before removing anything;
  reliable secure deletion is generally unavailable on modern journaling,
  copy-on-write, flash, and snapshotting storage.
- `SecretString` reduces accidental disclosure and zeroizes its owned storage,
  but cannot protect registers, swap, page cache, privileged debuggers, or a
  compromised kernel.
- Do not expose decryption as a remote yes/no oracle. This application is
  designed for local interactive use.
- `SIGKILL` and abrupt power loss cannot run in-process cleanup. Unnamed
  temporary files still disappear when the kernel closes the process's file
  descriptors, but terminal restoration requires a handled exit.
- The age on-disk format is standardized and cross-implemented, but the Rust
  `age` crate is still pre-1.0. This project pins it to 0.12.1 and commits
  `Cargo.lock`; upgrades require re-running the full adversarial test suite.
- This project has extensive automated tests but has not received an independent
  professional security audit. Do not describe it as formally verified.

## Verification

```console
cargo fmt --all -- --check
cargo test --all-targets --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo build --release --locked
```

The suite covers streaming boundaries, corruption and truncation, password and
CLI behavior, hostile headers and work factors, filesystem object types,
symlink rejection, atomic no-clobber races, permissions, cleanup, Unicode and
non-UTF-8 paths, terminal restoration after Ctrl-C/SIGTERM, and interoperability
with the age library. The PTY tests require the Linux `setsid` utility.
