# multicrypt

`multicrypt` is a whole-file, authenticated encryption CLI. Every operation
requires an explicit algorithm, an uppercase `E` or `D`, an input path, and
an output path.

## Build

```text
cargo build --release
```

The binary will be `target/release/multicrypt` (or
`target\release\multicrypt.exe` on Windows).

## Create keys

```text
multicrypt keygen
```

`keygen` creates one independent, cryptographically random 256-bit master-key
file per algorithm in the directory containing the executable. These are the
default *filenames*, not public or deterministic default secrets. The command
never replaces an existing key file; rerunning it only fills missing key files.

Back up the key files securely. Losing a key makes files encrypted with that key
unrecoverable. Anyone who obtains a key file can decrypt data protected by it.

## Encrypt and decrypt

```text
multicrypt AES-256-GCM-SIV E document.pdf document.pdf.mcrypt
multicrypt AES-256-GCM-SIV D document.pdf.mcrypt restored.pdf
```

Supported algorithm names:

- `AES-256-GCM-SIV`
- `SERPENT-256-CTR-HMAC-SHA-512`
- `THREEFISH-1024-CTR-HMAC-SHA-512`
- `ASCON-AEAD128`
- `RABBIT-HMAC-SHA-512`
- `AEGIS-256`
- `AEGIS-128L`

Algorithm names are accepted case-insensitively. The operation is deliberately
strict: only uppercase `E` and `D` are valid. Output files are published
with a no-clobber operation and never overwritten.

## Security design

- Each suite has a typed key file, preventing accidental cross-algorithm key
  use.
- Every encryption obtains a 256-bit random salt and a suite-appropriate random
  nonce/IV from the operating system.
- HKDF-SHA-512 derives independent per-file encryption and MAC keys. This also
  gives Rabbit a fresh effective key for every file despite its 64-bit IV.
- Serpent, Threefish, and Rabbit use encrypt-then-MAC with a full
  HMAC-SHA-512 tag. HMAC is verified before decryption.
- AEAD suites authenticate the complete versioned header as associated data.
- Decryption is completed and authenticated in memory before an output file is
  created.
- Secret key material and in-memory plaintext buffers use best-effort
  zeroization.
- Key files and outputs use temporary files, `sync_all`, and atomic
  no-clobber publication on supported filesystems. Unix key files are required
  to be owner-only.

The v1 format pins Serpent to 256-bit keys with `Ctr128BE`. Threefish uses a
1024-bit key, a zero tweak, and `Ctr128BE`, where the final 16 bytes of its
128-byte IV block are the counter. AEGIS uses 32-byte tags. Format fields,
ciphertext, nonces, and tags are all authenticated.

The byte-exact v1 container, key-file, KDF, and suite definitions are documented
in [FORMAT.md](FORMAT.md).

## Important limitations

This program is production-minded, but the complete seven-suite set cannot
honestly be described as independently production-audited. Serpent, Threefish,
Rabbit, Ascon, and the selected AEGIS implementation carry varying upstream
audit or maturity warnings. Threefish-CTR is an application-defined
construction, and Rabbit is a legacy cipher. Prefer `AES-256-GCM-SIV` or
`ASCON-AEAD128` unless interoperability or another explicit requirement
dictates a different suite.

Processing is intentionally whole-file. Very large or attacker-controlled files
can exhaust memory, and plaintext can be exposed through swap or crash dumps.
Keys stored beside the executable are only as secure as that host account and
directory. The application does not provide password derivation, key rotation,
or recovery.

The no-clobber publication API is generally atomic on Windows and modern Linux
filesystems, but does not guarantee atomicity on every platform and can leave an
extra temporary hard link after a crash or filesystem error. Use trusted,
access-controlled executable and destination directories. On Windows, generated
files inherit the parent directory's ACL; verify that it excludes untrusted
users.

Before high-value deployment, arrange an independent review, establish key
backup/rotation procedures, and validate the target platform's filesystem and
access-control behavior.

## Tests

```text
cargo fmt -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-targets --locked
cargo test --release --all-targets --locked
cargo audit
```

The suite includes official known-answer vectors for AES-256-GCM-SIV,
Serpent-256, Threefish-1024, final NIST Ascon-AEAD128, Rabbit,
HMAC-SHA-512, AEGIS-256, and AEGIS-128L, plus boundary-size, large-value,
wrong-key, tamper, truncation, no-clobber, key-format, and end-to-end CLI tests.
