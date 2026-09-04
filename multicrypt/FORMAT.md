# multicrypt format version 1

This document is normative for files written by `multicrypt` 0.1.x. All
multi-byte integers are unsigned and big-endian. Any change to a suite's
algorithm, key derivation, counter convention, nonce length, tag length, or
authentication input requires a new suite identifier or format major version.

## Encrypted file

```text
authenticated header || ciphertext || authentication tag
```

The fixed header is 88 bytes, followed by the suite nonce:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 8 | Magic: `MCRYPTF\0` |
| 8 | 1 | Major version: `1` |
| 9 | 1 | Minor version: `0` |
| 10 | 2 | Suite identifier |
| 12 | 2 | Flags: `0` |
| 14 | 2 | Header length: `88 + nonce_length` |
| 16 | 2 | Nonce length |
| 18 | 2 | Authentication-tag length |
| 20 | 4 | Reserved: `0` |
| 24 | 8 | Plaintext length |
| 32 | 8 | Ciphertext length |
| 40 | 16 | Key identifier |
| 56 | 32 | Per-file random HKDF salt |
| 88 | variable | Nonce or initial counter block |

For every v1 suite, ciphertext length equals plaintext length. The physical file
length must equal `header_length + ciphertext_length + tag_length`; trailing
data is invalid. The complete header, including salt and nonce, is
authenticated.

## Suite registry

| ID | Suite | Derived ENC key | Nonce | Tag |
| ---: | --- | ---: | ---: | ---: |
| 1 | AES-256-GCM-SIV | 32 | 12 | 16 |
| 2 | Serpent-256-CTR + HMAC-SHA-512 | 32 | 16 | 64 |
| 3 | Threefish-1024-CTR + HMAC-SHA-512 | 128 | 128 | 64 |
| 4 | Ascon-AEAD128, NIST SP 800-232 | 16 | 16 | 16 |
| 5 | Rabbit + HMAC-SHA-512 | 16 | 8 | 64 |
| 6 | AEGIS-256 | 32 | 32 | 32 |
| 7 | AEGIS-128L | 16 | 16 | 32 |

Serpent uses a 256-bit key and `Ctr128BE` across its complete 16-byte block.
Threefish uses a 1024-bit key, a zero 128-bit tweak, and `Ctr128BE`; the first
112 bytes of its IV block are fixed nonce bytes and the final 16 bytes are the
big-endian counter. Rabbit follows RFC 4503.

AEGIS-256 and AEGIS-128L use the current draft-18 computation with a 256-bit
tag. Until AEGIS is finalized, these two suite definitions should be treated as
experimental interoperability profiles.

## Key files

Every suite has a separate 48-byte key file:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 8 | Magic: `MCKEYF\0\0` |
| 8 | 1 | Major version: `1` |
| 9 | 1 | Minor version: `0` |
| 10 | 2 | Suite identifier |
| 12 | 2 | Master-secret length: `32` |
| 14 | 2 | Reserved: `0` |
| 16 | 32 | Random master secret |

Key filenames are part of application configuration, not encrypted-file
metadata. The typed key header prevents accidental use of one suite's key file
for another suite.

## Key derivation

HKDF-SHA-512 uses the 32-byte header salt and the suite's 32-byte master secret.
Encryption and MAC keys are expanded independently:

```text
info = "MCRYPT-FILE-v1\0" || suite_id_be16 || 0x00 || "ENC"
info = "MCRYPT-FILE-v1\0" || suite_id_be16 || 0x00 || "MAC"
```

Only the three encrypt-then-MAC suites derive a MAC key. Their MAC key is 64
bytes. The public key identifier is:

```text
first_16_bytes(
  SHA-256("MCRYPT key-id v1\0" || suite_id_be16 || master_secret)
)
```

## Authentication

AES-256-GCM-SIV, Ascon-AEAD128, AEGIS-256, and AEGIS-128L use the complete
header as AEAD associated data and store a detached tag after the ciphertext.

Serpent, Threefish, and Rabbit use encrypt-then-MAC:

```text
HMAC-SHA-512(
  mac_key,
  "MCRYPT-AUTH-v1\0" || complete_header || ciphertext
)
```

The full 64-byte HMAC tag is stored. It must be verified in constant time before
the stream cipher is applied.
