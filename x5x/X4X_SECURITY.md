# Security design

## Threat model

x4x protects file contents against an attacker who obtains, modifies,
truncates, appends to, or rearranges an encrypted file but does not know its
password. It also aims to leave an existing source or destination intact after
I/O errors, malformed input, failed authentication, or a process crash before
the final rename.

It does not conceal file names, encrypted-file size, access patterns, or timing.
It does not prevent deletion or rollback to an older valid ciphertext. It
cannot protect a password captured by malware, a compromised OS, terminal
logging, swap, hibernation, or a core dump. Availability is outside the
cryptographic threat model.

## Version 1 file format

All integers are unsigned big-endian. Parsers must reject unknown values and
nonzero reserved fields.

The fixed 64-byte header is:

| Offset | Size | Meaning |
|---:|---:|---|
| 0 | 8 | ASCII magic `X4XCRYPT` |
| 8 | 1 | format version (`1`) |
| 9 | 1 | cipher identifier (`1` = XChaCha20-Poly1305) |
| 10 | 1 | KDF identifier (`1` = Argon2id v1.3) |
| 11 | 1 | flags (must be zero) |
| 12 | 4 | Argon2 memory cost in KiB |
| 16 | 4 | Argon2 iteration count |
| 20 | 4 | Argon2 parallelism |
| 24 | 4 | plaintext chunk size |
| 28 | 16 | random salt |
| 44 | 16 | random nonce prefix |
| 60 | 4 | reserved (must be zero) |

The production writer uses Argon2id with 65,536 KiB, three iterations, one
lane, and a 32-byte output. Readers accept only 8,192–524,288 KiB, 1–10
iterations, and 1–16 lanes. The accepted chunk-size range is 4 KiB–16 MiB.
These limits are checked before invoking Argon2 or allocating a frame.

Each frame consists of an 8-byte frame header followed by `plaintext_length +
16` bytes of ciphertext and Poly1305 tag:

| Offset | Size | Meaning |
|---:|---:|---|
| 0 | 4 | plaintext length |
| 4 | 1 | bit 0 is the final-frame marker; other bits must be zero |
| 5 | 3 | reserved (must be zero) |

Non-final frames must be exactly the declared chunk size. A final frame is
mandatory, including for empty input, and may contain zero through one full
chunk. Nothing may follow it.

For frame number `i`, the 24-byte XChaCha nonce is the 16-byte random prefix
followed by `i` as a 64-bit big-endian integer. The associated data is:

```text
64-byte header || 64-bit frame number || 8-byte frame header
```

This construction authenticates the complete public header and gives every
frame a unique nonce and position. The final marker makes truncation to any
earlier valid frame detectable. Random salt and nonce values come from the
operating system CSPRNG and are generated independently for every encryption.

## Output transaction

Input and output paths are checked for aliasing. Existing destinations are
always rejected. Data is written to a randomly named private temporary file in
the destination directory, flushed and synchronized, and then published using
an atomic no-clobber persist operation. Keeping the temporary file in the same
directory avoids cross-filesystem rename behavior. On Unix the containing
directory is synchronized after publication.

Decryption follows the same transaction and therefore does not expose a named
destination containing unauthenticated plaintext. The private temporary file
may contain authenticated plaintext while decryption is in progress; its drop
handler removes it after a failure. Storage media, journaling, snapshots, and
forensic recovery remain outside the erasure guarantees.

## Compatibility policy

Version 1 constants and byte layout must not change. A future incompatible
format must use another version byte and a separate parser. New parameter
values cannot be silently accepted where version 1 requires rejection.
