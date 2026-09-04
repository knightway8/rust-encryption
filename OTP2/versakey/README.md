# VersaKey

VersaKey is a Linux-only collection of five interactive Rust CLIs that
deterministically create `key.key` in the current directory. Each one asks for
a decimal byte count from `1` through `20000000000`, then asks for the password
twice with hidden input.

## Requirements

- Linux. Other targets are rejected at compile time.
- Rust 1.97.1 or newer and Cargo's Rust 2024 edition support.
- `rustfmt` and Clippy for the complete local quality checks.

The checked-in `rust-toolchain.toml` pins Rust 1.97.1 with the minimal profile,
`rustfmt`, and Clippy so ordinary `cargo` commands use the tested toolchain.
You can explicitly select a newer compatible toolchain if needed.

Use a release build, especially for large files. The original AES suite remains
the default, so these two commands are equivalent:

```text
cargo run --locked --release
cargo run --locked --release --bin versakey
```

Run the other suites explicitly:

```text
cargo run --locked --release --bin versakey-scrypt
cargo run --locked --release --bin versakey-pbkdf2
cargo run --locked --release --bin versakey-chacha20
cargo run --locked --release --bin versakey-blake3
```

To compile all five at once, run `cargo build --locked --release --bins`. The
Cargo binary names are `versakey`, `versakey-scrypt`, `versakey-pbkdf2`,
`versakey-chacha20`, and `versakey-blake3`.

## Choose a suite

| Binary | Construction | Intended choice |
| --- | --- | --- |
| `versakey` | Argon2id v1.3 (64 MiB, 3 iterations, 1 lane, 32-byte output) -> AES-256-CTR | Original, default suite; preserves the output compatibility of earlier VersaKey versions. |
| `versakey-scrypt` | scrypt (`N=2^16`, `r=8`, `p=1`, about 64 MiB, 32-byte output) -> AES-256-CTR | Memory-hard alternative to Argon2id. |
| `versakey-pbkdf2` | PBKDF2-HMAC-SHA-256 (600,000 iterations, 32-byte output) -> AES-256-CTR | Widely standardized, low-memory alternative. |
| `versakey-chacha20` | Argon2id v1.3 (64 MiB, 3 iterations, 1 lane, 32-byte output) -> ChaCha20 | Non-AES stream-cipher alternative. |
| `versakey-blake3` | Argon2id v1.3 (64 MiB, 3 iterations, 1 lane, 32-byte output) -> keyed BLAKE3 XOF | Direct extendable-output alternative. |

The suites are intentionally domain-separated and non-interchangeable. The
same password and size reproduce the same bytes only when the same binary and
compatibility-critical constants are used. The five binaries deliberately
produce different bytes from one another, and `key.key` contains no suite
header. Record which binary created a key if it must be reproduced later.

The original `versakey` binary retains its application salt, pepper, domain,
Argon2id parameters, and AES-256-CTR construction. Existing password-and-size
combinations therefore continue to reproduce the original bytes. Changing a
suite's salt, pepper, domain, KDF parameters, or stream construction breaks
that suite's compatibility.

## Output handling

Every binary writes or replaces the same file, `key.key`, in the current
directory. Running a second suite therefore replaces the first suite's output;
move or rename a key first if both files are needed.

Generation streams through a 1 MiB buffer. Its memory use is bounded by that
buffer plus the selected KDF's fixed working set and does not grow with the
requested file size, including at the 20,000,000,000-byte limit.

On conventional local Linux filesystems, a completed temporary file is flushed,
synchronized, and atomically moved to `key.key`. A derivation or write failure
before the final replacement preserves an earlier `key.key`. A rare Linux
directory-sync failure after replacement is reported explicitly as already
committed because the replacement cannot then be rolled back.

Some network and userspace filesystems, including some NFS and FUSE setups, can
report a rename error even when the server or filesystem applied the rename.
VersaKey therefore reports any replacement error as outcome-uncertain. Inspect
both `key.key` and the reported `.key.key.*` recovery path before retrying. The
recovery path is deliberately not deleted and contains the complete synchronized
temporary file when the failed rename left it in place. If the rename actually
succeeded, that old temporary path may no longer exist. The same suite,
password, size, and compatibility constants deterministically regenerate the
same bytes, but a retry can still overwrite an unrelated file or another
process's concurrent output.

Normal errors before replacement and Rust unwinding remove the temporary file;
an outcome-uncertain replacement deliberately retains its reported recovery
path. A forced process kill, abort, or power loss can also leave a partial
`.key.key.*` file behind. After confirming that no VersaKey process is running
and inspecting any reported recovery path, stale files can be removed. They are
not deleted automatically because another concurrent VersaKey process may still
own one.

On Linux, a newly generated file has owner-only mode `0600`. Atomic replacement
also replaces a more permissive older file or a `key.key` symbolic link rather
than inheriting or following it. The containing directory's ownership, ACL,
mount, and backup policies still matter, so use a suitably restricted directory
for sensitive output.

## Determinism and security

- The requested byte length and suite domain participate in derivation. A
  different size changes the whole output rather than sharing the shorter
  file's stream prefix.
- Output entropy is limited by the password-derived 256-bit key. A very large
  `key.key` is deterministic pseudorandom material, not a true-random one-time
  pad merely because it is large.
- Individual bytes and short substrings can and will repeat in a sufficiently
  large random-looking file. No generator can make every byte unique after 256
  bytes, and none of these suites cycles or copies a shorter digest.
- The AES-256-CTR suites use one persistent stream whose 128-bit counter is not
  reused within a generated file. Since AES is a permutation, their aligned
  16-byte blocks cannot repeat at the supported sizes. That specific
  no-repeated-block property does not apply to ChaCha20 or BLAKE3 output.
- The compiled-in pepper can be extracted from an executable. It diversifies
  builds but is not a substitute for a strong password or an external secret.
- VersaKey zeroizes the password values and key/buffer state it owns. The
  third-party scrypt and PBKDF2 implementations do not guarantee erasure of
  every internal intermediate allocation after derivation.
- Anyone who obtains `key.key` can test password guesses offline by regenerating
  it. Argon2id and scrypt use memory-hard work to raise guessing cost, but no
  KDF adds entropy to a weak password. Use a long, high-entropy passphrase.
- PBKDF2 is CPU-hard but not memory-hard. Its low memory requirement and broad
  standardization can be useful for constrained or compatibility-oriented
  deployments, but attackers can parallelize guesses more economically than
  against the configured Argon2id or scrypt suites. Prefer a memory-hard suite
  unless that PBKDF2 tradeoff is specifically needed.

Run the complete test suite with:

```text
cargo fmt --all -- --check
cargo test --locked --all-targets --no-fail-fast
cargo clippy --locked --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps
cargo build --locked --release --bins
```
