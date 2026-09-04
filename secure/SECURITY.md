# Security policy and threat model

## Intended use

`secure` protects local file contents at rest when the encrypted file may be
read or modified by an attacker who does not know the password. It treats input
ciphertexts and filesystem path state as hostile. It is an interactive,
single-file Linux tool, not a network service, archive format, key-management
system, or secure-deletion utility.

## Invariants

1. Existing destination objects are never replaced, including under a race.
2. A destination becomes visible only after encryption is finalized or
   decryption reaches and authenticates the final record.
3. Decrypted plaintext remains in unnamed `O_TMPFILE` storage until publication;
   failure or process death closes and removes it automatically.
4. Published outputs are regular files with mode `0600`.
5. Passwords never intentionally enter argv, environment variables, logs, or
   terminal-echoed input.
6. Attacker-controlled header size and scrypt work are bounded before costly
   processing.
7. The application contains no handwritten cryptographic primitive or custom
   encrypted-file format.
8. A handled termination request restores password-terminal settings and is
   observed again immediately before the atomic publication commit point.

## Out of scope

- Attackers with root/kernel access or the ability to read this process's live
  memory
- A compromised Rust toolchain, dependency, CPU, random source, or operating
  system
- Password guessing when the password has insufficient entropy
- Hiding file size, access timing, the existence of encrypted data, or the
  user-selected input/output paths
- Preservation of source metadata
- Guaranteed erasure of plaintext from storage, backups, snapshots, RAM, swap,
  caches, or hardware remapping layers
- Availability when the attacker can exhaust disk, memory, file descriptors,
  or CPU within the configured bounds

## Dependency handling

Crypto and terminal dependencies are pinned by `Cargo.lock`. Before a release,
run the formatting, test, Clippy, and release-build commands in `README.md`, then
scan the lockfile with a current RustSec-compatible audit tool. Dependency
updates should be reviewed individually; do not blindly refresh crypto-related
packages.

## Reporting a vulnerability

Do not include real passwords, keys, plaintext, or sensitive files in a report.
Provide the smallest synthetic reproducer possible, including the exact commit,
Linux kernel, Rust version, filesystem type, and command used.
