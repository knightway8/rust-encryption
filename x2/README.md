# x2

`x2` is a conservative, password-based file-encryption command-line tool. It
supports AES-256-GCM-SIV and XChaCha20-Poly1305, streams large files in bounded
chunks, and does not overwrite an existing destination.

The project is pinned to Rust **1.98.0**, the latest stable release on
2026-08-20. Build it with:

```console
cargo build --release --locked
```

## Usage

```text
x2 E AES  INPUT OUTPUT
x2 E XCHA INPUT OUTPUT
x2 D AES  INPUT OUTPUT
x2 D XCHA INPUT OUTPUT
```

`E` prompts for `Password:` and `Confirm password:`. `D` prompts once. Passwords
are read from the controlling terminal with echo disabled; they are never
accepted in arguments or environment variables. Empty passwords are rejected.
Completed passwords longer than 1,024 UTF-8 bytes are rejected. Tokens are
deliberately exact and uppercase.

The algorithm supplied for decryption must match the authenticated algorithm in
the encrypted file. The input is opened and validated before the password
prompt, so swapping its pathname while the user types does not select a new
file. The destination directory is likewise resolved to an absolute target
before prompting. Outputs are published only after the cryptographic operation
succeeds. If the destination already exists—including a dangling symlink—`x2`
fails without changing it. There is intentionally no in-place or force mode.

Exit status `0` means success, `1` means an operational or output-stream error,
and `2` means invalid command syntax.

## Version 1 container

The format is architecture-independent and manually serialized. Its fixed
80-byte header contains:

- magic, format version, and header length;
- the AEAD and Argon2id identifiers;
- the exact Argon2 version and work profile;
- chunk size and plaintext length;
- a fresh 128-bit salt and algorithm-sized random base nonce.

Version 1 accepts exactly Argon2id v1.3 with 64 MiB of memory, three passes,
four lanes, and a 256-bit output. This fixed allowlist prevents a hostile file
from requesting attacker-chosen KDF resources. The Argon2 output is
domain-separated with HKDF-SHA-256 before use as an AEAD key.

Plaintext is processed as canonical 1 MiB records. Each record independently
authenticates the complete header, a monotonically increasing record number,
record type, and length. A checked counter is mixed into the random base nonce.
Every file—including an empty file—ends with a zero-length authenticated final
record. Decryption rejects missing, reordered, duplicated, cross-file spliced,
truncated, or trailing records, assuming the independently generated header
material is unique.

Files are written to an exclusively created, same-directory temporary file with
a 128-bit OS-CSPRNG name. The file is created with Unix mode `0600`, synchronized,
and installed with no-clobber persistence. On Unix, the parent directory is
then synchronized; if that final step fails, `x2` explicitly reports that the
output was installed but its crash durability is uncertain. The requested
plaintext path never becomes visible after a wrong password or authentication
error.

## Security boundaries and limitations

- This is a custom container and has not received an independent security
  review. Internal tests and an implementation audit are not a substitute for
  external cryptographic review.
- Password encryption permits offline guessing. Argon2id raises the cost but
  cannot rescue a weak password.
- File length, access time, and the selected algorithms are not secret.
- Whole-file rollback or substitution is not detectable without trusted
  external versioning. Symmetric authentication proves password knowledge, not
  a sender's identity.
- Secrets can still be exposed by a compromised host, keylogger, debugger,
  same-user process, core dump, or swap. Rust zeroization cannot clear every
  compiler copy, CPU register, or kernel buffer.
- The 1,024-byte password rule is a post-entry acceptance limit: the terminal
  library reads the hidden line before `x2` rejects it. A hostile PTY master
  requires the same-user or compromised-host access already outside this threat
  model.
- Output path components must be in a namespace trusted against modification by
  other users. Publication is path-based; do not use a shared attacker-writable
  directory. Same-user malicious processes are already outside the threat
  model.
- Unix mode bits do not override an ACL that grants additional access. Windows
  files inherit the destination directory's DACL. Use a private destination
  directory with an appropriate ACL; `x2` cannot make an untrusted directory
  confidential.
- Normal cleanup failures are reported, but a crash, power loss, or abrupt
  termination (including `SIGINT`, `SIGTERM`, or `SIGKILL`) can leave a
  temporary file. Secure deletion cannot be promised on journaling,
  copy-on-write, or flash storage.
- Directory-entry synchronization is explicit on Unix. Other platforms receive
  file synchronization and the operating system's normal rename guarantees,
  but `x2` does not promise power-loss namespace durability there.
- An input that is rewritten concurrently without changing length cannot be
  detected reliably; do not modify files while encrypting them.
- RustCrypto documents that `aes-gcm-siv` has not had a dedicated audit. Both
  AEAD crates warn that portable implementations may not be constant time on
  unusual processors with variable-time multiplication; affected 32-bit
  PowerPC and non-ARM microcontroller targets are unsupported. See the upstream
  [`aes-gcm-siv` notes](https://docs.rs/aes-gcm-siv/0.12.0/aes_gcm_siv/#security-notes)
  and [`chacha20poly1305` notes](https://docs.rs/chacha20poly1305/0.11.0/chacha20poly1305/#security-notes).

The algorithms and format choices follow [RFC 8452](https://www.rfc-editor.org/rfc/rfc8452),
the [XChaCha draft](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha),
[RFC 9106](https://www.rfc-editor.org/rfc/rfc9106), and
[RFC 5869](https://www.rfc-editor.org/rfc/rfc5869).

## Verification

```console
cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
cargo build --release --locked
cargo audit --deny warnings
```

The test suite covers official primitive vectors, frozen complete-container
vectors, both algorithms at every chunk boundary, structure-aware property
tests, all single-byte container mutations, every truncation point, wrong
passwords, record reordering/duplication/splicing, interrupted/short/failed and
contract-violating I/O, retained pre-prompt input handles, no-clobber races,
temporary-file cleanup, and Unix mode bits. CI builds and tests Linux, macOS,
and Windows; platform ACL and power-loss behavior still require deployment-level
validation.
