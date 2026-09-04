# seal

**Modern, secure, streaming file encryption CLI written in pure Zig 0.16.**

```
seal encrypt  secret.pdf
seal decrypt  secret.pdf.seal
```

## Features

| Feature                    | Detail                                              |
|---------------------------|-----------------------------------------------------|
| AEAD                      | **XChaCha20-Poly1305** (24-byte nonces)             |
| Key derivation            | **Argon2id** (64 MiB, t=3, p=4) – memory-hard       |
| Streaming                 | 64 KiB chunks – constant memory, any file size      |
| Header                    | Versioned + authenticated via per-chunk AD          |
| Nonce construction        | 16-byte random + 8-byte big-endian counter          |
| Memory safety             | All keys & plaintext wiped with `crypto.secureZero` |
| Password handling         | Hidden prompt (POSIX + Windows) / `--pass-file`     |
| Overwrite protection      | Refuses to clobber unless `--force`                 |
| Progress                  | Shown for files > 1 MiB                             |
| Dependencies              | **Zero** – only Zig standard library                |

## Build (Zig 0.16.0+)

```bash
zig build                  # debug
zig build -Doptimize=ReleaseSafe
# binary → zig-out/bin/seal
```

## Usage

```bash
# Encrypt (creates secret.pdf.seal)
seal encrypt secret.pdf

# Decrypt
seal decrypt secret.pdf.seal -o secret.pdf

# Force overwrite
seal encrypt data.bin -o data.bin.seal --force

# Non-interactive
echo -n 'my strong passphrase' > /tmp/pass
seal encrypt archive.tar --pass-file /tmp/pass
shred -u /tmp/pass
```

### Options

```
-o, --output <path>     Output path
-f, --force             Overwrite existing file
    --pass-file <path>  Read password from file (no trailing newline needed)
-h, --help
```

## File format

```
┌──────────────────────────────────────────────────────────┐
│ MAGIC "SEAL01" (6) │ VERSION u8 │ SALT (16) │ t│m│p (12) │  ← HEADER
├──────────────────────────────────────────────────────────┤
│ NONCE (24) │ CIPHERTEXT (≤64 KiB) │ TAG (16)             │  ← chunk 0
│ NONCE (24) │ CIPHERTEXT (≤64 KiB) │ TAG (16)             │  ← chunk 1
│ …                                                        │
└──────────────────────────────────────────────────────────┘
```

- Each chunk’s associated data is its 64-bit index (prevents reordering/splicing).
- Last chunk may be shorter than 64 KiB.
- Authentication failure on any chunk aborts and removes the partial output.

## Security notes

- Passwords are **never** accepted on the command line (they would appear in `ps` / shell history).
- Argon2id parameters are stored in the header so future versions can raise them without breaking old files.
- XChaCha20’s large nonce space makes random nonces + counter completely safe even for petabyte-scale archives.
- This tool protects **confidentiality and integrity** of files at rest. It does **not** protect against:
  - side-channel attacks on the running process
  - evil-maid / cold-boot attacks
  - compromised OS

For maximum security use a strong, unique passphrase (or a high-entropy password from a manager) and keep the `.seal` files offline or on encrypted storage.

## License

MIT
