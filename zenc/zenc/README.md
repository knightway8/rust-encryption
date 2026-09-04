# zenc

`zenc` is a Linux-first file encryption CLI written for **Zig 0.16.0**.

It uses only Zig's standard cryptographic primitives plus libc for a no-echo terminal password prompt:

- Argon2id password KDF (default: 256 MiB, 3 passes, 4 lanes)
- Fresh 256-bit random salt per file
- XChaCha20-Poly1305 AEAD
- Fresh 128-bit random nonce prefix per file plus a 64-bit per-record counter
- 1 MiB independently authenticated records
- Random final-block padding so exact plaintext length is encrypted
- Encrypted/authenticated metadata for plaintext size and chunk count
- Header and record index bound into AEAD associated data
- Atomic output with mode `0600`
- No password-in-argv option
- Password confirmation when encrypting interactively
- Password-file mode for scripts
- Secret/key buffers explicitly zeroed after use

## Important status

This is a security-conscious **v1 implementation, not an externally audited cryptographic product**. The design intentionally uses established primitives rather than inventing a cipher, but the surrounding implementation and file format still deserve independent review before protecting irreplaceable/high-value data.

## Build

Requires Zig 0.16.0 and a Linux/POSIX libc development environment.

```sh
zig build -Doptimize=ReleaseSafe
./zig-out/bin/zenc version
```

Run the format tests:

```sh
zig build test
```

## Use

Encrypt:

```sh
./zig-out/bin/zenc encrypt photo.jpg
# creates photo.jpg.zenc
```

Decrypt:

```sh
./zig-out/bin/zenc decrypt photo.jpg.zenc
# creates photo.jpg
```

Refuse to overwrite by default. To replace an existing destination atomically:

```sh
./zig-out/bin/zenc decrypt --force photo.jpg.zenc
```

Choose an output path:

```sh
./zig-out/bin/zenc encrypt -o backup.enc important.tar
```

Verify every authentication tag without writing plaintext:

```sh
./zig-out/bin/zenc verify backup.enc
```

Inspect the public format/KDF parameters without a password:

```sh
./zig-out/bin/zenc info backup.enc
```

For automation, avoid putting a password in argv or an environment variable. Use a permission-protected file:

```sh
chmod 600 /run/user/$UID/zenc-pass
./zig-out/bin/zenc encrypt --password-file /run/user/$UID/zenc-pass secret.bin
```

The password-file reader removes trailing CR/LF only; all other bytes are part of the password.

## KDF tuning

The default is deliberately expensive:

```text
256 MiB memory, 3 iterations, 4 lanes
```

For a lower-memory machine:

```sh
./zig-out/bin/zenc encrypt --kdf-memory-mib 64 file.bin
```

KDF settings are stored in and authenticated by each encrypted file, so decrypt does not need matching command-line options.

## File format v1

The byte-level interoperability specification is in [FORMAT.md](FORMAT.md).

The first 128 bytes are a versioned public header containing:

- magic + version
- algorithm IDs
- chunk size
- Argon2id parameters
- 32-byte salt
- 16-byte nonce prefix
- encrypted metadata + AEAD tag
- reserved authenticated bytes

The encrypted metadata contains the exact plaintext size and record count.

Each data record is exactly:

```text
1 MiB ciphertext || 16-byte Poly1305 tag
```

The final plaintext record is padded with cryptographically secure random bytes before encryption. Even an empty file gets one encrypted record. This means ciphertext length reveals only the number of 1 MiB buckets, not the exact plaintext length.

Metadata uses nonce counter `2^64-1`; data records use counters `0..N-1`. The complete encoded header and each record index are authenticated as associated data, so reordering, deleting, duplicating, truncating, or modifying records fails verification.

## Threat model

`zenc` is intended to protect file contents at rest when an attacker obtains the encrypted file but not the password. It provides confidentiality and integrity, not anonymity, endpoint security, or protection after an attacker controls the machine while plaintext/passwords are in use.

A strong password still matters. Argon2id makes guesses expensive; it cannot turn a weak password into a high-entropy secret.

## Why no `--password STRING`?

Command-line arguments are commonly exposed to shell history, process inspection, logs, and debugging tools. `zenc` intentionally does not implement that interface.

## License

MIT
