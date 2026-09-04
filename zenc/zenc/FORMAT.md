# ZENC v1 file format

All integers are unsigned little-endian. Offsets are byte offsets from the
start of the file. The format is deliberately versioned and algorithm IDs are
explicit so future versions do not have to reinterpret existing ciphertext.

## Public header (128 bytes)

| Offset | Size | Meaning |
|---:|---:|---|
| 0 | 8 | Magic: `5a 45 4e 43 0d 0a 1a 0a` (`ZENC\\r\\n\\x1a\\n`) |
| 8 | 2 | Format version: `1` |
| 10 | 1 | AEAD ID: `1` = XChaCha20-Poly1305 |
| 11 | 1 | KDF ID: `1` = Argon2id |
| 12 | 4 | Flags: must be zero in v1 |
| 16 | 4 | Plaintext record size (v1 writer uses 1,048,576) |
| 20 | 4 | Argon2 memory cost in KiB |
| 24 | 4 | Argon2 iteration/time cost |
| 28 | 4 | Argon2 parallelism |
| 32 | 32 | Random salt |
| 64 | 16 | Random nonce prefix |
| 80 | 16 | Encrypted metadata ciphertext |
| 96 | 16 | Metadata Poly1305 tag |
| 112 | 16 | Reserved: must be zero in v1 |

The accepted v1 record size range is 64 KiB through 16 MiB and it must be a
power of two. KDF parameters are bounded by the implementation before Argon2
is invoked.

## Key derivation

Argon2id derives a 32-byte key directly from the password and the 32-byte salt
stored in the header. The Argon2 parameters are the values stored at offsets
20..31.

## Nonces

Every AEAD nonce is 24 bytes:

```text
nonce = nonce_prefix[16] || little_endian_u64(counter)
```

Data records use counters `0` through `chunk_count - 1`.
Encrypted metadata uses counter `2^64 - 1`, which data records are forbidden
to reach.

## Encrypted metadata

The metadata plaintext is 16 bytes:

```text
little_endian_u64(exact_plaintext_size)
little_endian_u64(chunk_count)
```

Metadata associated data is the 96-byte concatenation:

```text
header[0..80] || header[112..128]
```

This intentionally excludes the metadata ciphertext/tag fields themselves but
binds the format version, algorithms, KDF parameters, salt, nonce prefix, and
reserved bytes to the metadata authentication tag.

After authentication, an implementation must verify:

```text
chunk_count == max(1, ceil(exact_plaintext_size / chunk_size))
```

## Data records

Each record is fixed-size:

```text
chunk_size bytes ciphertext || 16-byte Poly1305 tag
```

The final plaintext record is filled with cryptographically secure random
padding to `chunk_size` before encryption. An empty file therefore still has
one encrypted data record.

For record `i`, associated data is:

```text
complete 128-byte encoded header || little_endian_u64(i)
```

The AEAD nonce uses counter `i`. Binding both the header and index means a
record cannot be silently moved, duplicated, reordered, or transplanted into a
different ZENC file.

## Required validation before plaintext commit

A conforming decryptor must not commit plaintext output unless all of these
checks succeed:

1. Header magic, version, IDs, flags, record size, and KDF bounds are valid.
2. Metadata authenticates under the password-derived key.
3. Metadata's size and chunk count are internally consistent.
4. Physical encrypted-file size is exactly
   `128 + chunk_count * (chunk_size + 16)`.
5. Every data record authenticates with its expected record index.
6. The plaintext destination is committed only after the final tag succeeds.

The reference CLI implements the destination as an atomic temporary file and
links/replaces it only after complete authentication.

## Information leakage

The public header reveals the format, algorithms, KDF cost, salt, nonce
prefix, and chunk size. The encrypted file length reveals the number of fixed
size records. The exact plaintext byte length is encrypted. With the v1
writer's 1 MiB records, an observer learns the plaintext's 1 MiB size bucket,
not its exact length.

The format does not store the original filename, timestamps, permissions, or
other filesystem metadata.
