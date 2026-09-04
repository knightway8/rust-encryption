# Version 1 encrypted-file format

This document specifies the canonical `ALGOENC1` wire format. All multibyte
integers are unsigned and little-endian. Byte ranges below are half-open:
`[start, end)`. Literal strings are their ASCII bytes with no terminator.

Version 1 is deliberately rigid. A reader must reject unknown IDs, nonzero
reserved bytes, unknown flags, and any KDF or chunk parameter other than the
fixed values below. Extensibility requires a new format version; accepting
nearly-canonical encodings would make security reviews and test fixtures
ambiguous.

## File layout

```text
header (80 bytes)
data record 0
data record 1
...
data record D - 1
FINAL record D
EOF
```

Let:

- `P` be the plaintext length from the header;
- `C = 65,536` be the chunk size;
- `D = ceil(P / C)`, with `D = 0` when `P = 0`;
- `T = 16` for suite IDs 1–8 and `T = 32` for IDs 9–30.

The exact encoded size is:

```text
80 + P + (D + 1) * (16 + T)
```

The extra record is the mandatory authenticated FINAL record. No bytes may
follow it.

## Fixed 80-byte header

| Offset | Size | Field | Version 1 value or meaning |
|---:|---:|---|---|
| 0 | 8 | magic | ASCII `ALGOENC1` |
| 8 | 2 | version | `1` |
| 10 | 2 | header length | `80` |
| 12 | 2 | suite ID | One of `1..=30`; see [Algorithms](ALGORITHMS.md) |
| 14 | 1 | KDF ID | `1`, meaning Argon2id |
| 15 | 1 | header flags | `0` |
| 16 | 4 | Argon2 memory | `65,536` KiB |
| 20 | 4 | Argon2 time cost | `3` passes |
| 24 | 2 | Argon2 parallelism | `1` lane |
| 26 | 2 | reserved | all zero |
| 28 | 4 | plaintext chunk size | `65,536` bytes |
| 32 | 8 | plaintext length | `P`, in bytes |
| 40 | 16 | Argon2 salt | fresh random bytes per encryption |
| 56 | 24 | nonce seed | fresh random bytes per encryption |

The header is visible, so it discloses the suite, exact plaintext length, and
KDF profile. It has no standalone tag. Instead, all 80 bytes are included in
the associated data or MAC of every record, including the FINAL record. Thus a
header is trusted only after at least one record authenticator has verified.

The decoder checks the fixed KDF values before invoking Argon2id. An input file
therefore cannot request attacker-selected memory, time, or parallelism costs.

## Fixed 16-byte record header

| Offset | Size | Field | Data record | FINAL record |
|---:|---:|---|---|---|
| 0 | 8 | record index | `i`, starting at zero | `D` |
| 8 | 4 | plaintext length | `1..=65,536` | `0` |
| 12 | 1 | flags | `0` | `1` (`FINAL`) |
| 13 | 3 | reserved | all zero | all zero |

A record is encoded as:

```text
record header (16) || ciphertext (record plaintext length) || tag (T)
```

CTR, stream-cipher, and the selected AEAD modes do not expand the ciphertext
body; the authenticator is stored after it. Data record indices must be exactly
`0, 1, ..., D-1`. Every data record except possibly the last has length `C`;
the last has the exact remaining length. The FINAL header is canonical:
index `D`, length zero, flags `1`, reserved bytes zero. Sealing it produces no
ciphertext body and one tag.

The reader must reject missing, duplicated, reordered, oversized, undersized,
or extra records; an unexpected length or index; EOF before FINAL; and any
trailing bytes after FINAL. These structural checks supplement authentication
and avoid accepting multiple encodings of the same plaintext.

## Password KDF and key schedule

Password bytes are used exactly as supplied. Interactive input supplies the
bytes represented by the entered password without the terminal newline. A
password file supplies every file byte, including any CR or LF. Empty passwords
and inputs over 1 MiB are invalid.

Argon2id uses version `0x13` and this fixed profile:

```text
password = exact password bytes
salt     = header[40..56]
m_cost   = 65,536 KiB
t_cost   = 3
p_cost   = 1
output   = 32-byte master key
```

The master key is input keying material for HKDF-SHA256. HKDF's salt is the
literal:

```text
algos/envelope/v1/hkdf
```

For every record index `i`, derive a fresh encryption/suite key with:

```text
info = "enc" || suite_id_le_u16 || i_le_u64
L    = the suite key length from Algorithms.md
K_i  = HKDF-Expand(info, L)
```

AES-CMAC-SIV keys are compound: `L = 32` for AES-128-CMAC-SIV (two 16-byte
AES keys) and `L = 64` for AES-256-CMAC-SIV (two 32-byte AES keys).

For Encrypt-then-HMAC suites only, derive one 32-byte file MAC key:

```text
info  = "mac" || suite_id_le_u16
L     = 32
K_mac = HKDF-Expand(info, 32)
```

The purpose prefix, suite ID, and record index provide domain separation. The
MAC and encryption keys are not reused for one another, different suites do not
receive the same subkeys from one master, and each record receives a different
encryption key.

## Record nonce derivation

Let `S` be the 24-byte nonce seed, `i` the record index, and `N` the suite nonce
length.

For `N <= 24`:

1. Copy `S[0..N]`.
2. XOR the eight little-endian bytes of `i` into the final eight bytes of that
   copy.

Equivalently:

```text
nonce = S[0..N]
nonce[N-8..N] ^= i_le_u64
```

All version 1 nonce sizes are at least eight bytes. This rule covers 8-, 12-,
16-, and 24-byte nonces.

HC-256 is the one `N = 32` case. It uses concatenation rather than XOR:

```text
nonce = S[0..24] || i_le_u64
```

The FINAL record uses index `D`, so it receives its own key and nonce just like
any data record.

## Associated data

For every data or FINAL record, construct:

```text
AAD = "algos/envelope/v1/record" || header_80 || record_header_16
```

`header_80` and `record_header_16` are the exact serialized bytes read from or
written to the file. There are no length prefixes or NUL terminators in this
concatenation.

Including both headers binds the suite, KDF profile, salt, nonce seed,
plaintext length, record order, record length, and FINAL marker to each tag.

## Native AEAD records: suites 1–8

Suites 1–8 call their AEAD construction with `K_i`, the derived nonce, the
record plaintext, and `AAD`. Their 16-byte authentication tag is stored after
the ciphertext. The empty FINAL record is a normal AEAD sealing operation over
an empty plaintext and still produces a 16-byte tag.

For suites 5 and 6, the pinned `aes-siv` AEAD mapping feeds two S2V associated
data components in this exact order: `[AAD, nonce]`. The resulting 16-byte
synthetic IV is the detached tag stored after the ciphertext; it is not
prepended to the ciphertext as in some AES-SIV APIs.

## Encrypt-then-HMAC records: suites 9–30

These suites use a custom, versioned Encrypt-then-HMAC construction:

1. Encrypt the record using `K_i` and the derived nonce.
2. Compute a full HMAC-SHA256 tag with `K_mac` over the exact concatenation:

```text
"algos/envelope/v1/hmac"
|| AAD
|| nonce_length_u8
|| nonce
|| ciphertext
```

3. Store all 32 HMAC bytes after the ciphertext.

On decryption, HMAC verification must complete successfully before the
ciphertext is passed to the cipher. Tags are never truncated. The generic
128-bit block-cipher suites use `Ctr128BE`, meaning a big-endian 128-bit counter
initialized from the complete 16-byte nonce. BelT uses its standardized
`belt-ctr` construction. Salsa20, XSalsa20, and HC-256 use their native stream
cipher initialization rather than a CTR adapter.

This composition is specific to this repository and format. It should not be
described as a standardized AEAD mode, even when both of its primitives are
standardized.

## Compatibility rules

- Suite IDs are on-disk protocol values and must never be renumbered.
- Version 1 constants and domain strings are protocol values and must never be
  edited in place.
- A binary accepts only its compiled-in suite ID.
- Readers must not guess algorithms, KDF settings, nonce rules, tag lengths, or
  endianness.
- A future incompatible change requires a new version and dedicated decoder;
  silently broadening the version 1 decoder is not compatible evolution.
