# x3x encrypted file formats

All multibyte integers are little-endian. The fixed header is 64 bytes:

| Offset | Length | Meaning |
| ---: | ---: | --- |
| 0 | 8 | ASCII X3XCRYPT |
| 8 | 1 | format version: 1 for key-file encryption, 2 for password encryption |
| 9 | 1 | algorithm identifier |
| 10 | 1 | authentication tag length |
| 11 | 1 | nonce-seed length used by the algorithm |
| 12 | 4 | plaintext chunk size, currently 1,048,576 |
| 16 | 8 | exact plaintext length |
| 24 | 32 | fresh operating-system random nonce seed; also the Argon2id salt in version 2 |
| 56 | 8 | version-specific keying parameters described below |

## Keying versions

Version 1 reads the algorithm's exact-size external key file. Bytes 56 through
63 are reserved and must all be zero.

Version 2 derives an internal key from a password and never uses an external key
file. Its final eight header bytes are:

| Offset | Length | Meaning |
| ---: | ---: | --- |
| 56 | 4 | Argon2 memory cost in KiB, little-endian |
| 60 | 2 | Argon2 iteration count, little-endian |
| 62 | 1 | Argon2 lane count |
| 63 | 1 | password KDF identifier, currently 1 for Argon2id v1.3 |

New version-2 files use 524,288 KiB (512 MiB), four iterations, and four lanes.
The decoder bounds stored parameters before allocating memory: memory must be
from 65,536 through 524,288 KiB, iterations from 3 through 4, and lanes from 1
through 4, with at least 8 KiB per lane. These limits ensure that an
unauthenticated header cannot demand more work than a file created by x3x.

Argon2id derives a 64-byte root from the exact UTF-8 password bytes and the
32-byte random nonce-seed field as salt. HKDF-SHA-512, salted with that same
field and labeled with the format version and algorithm identifier, expands the
root to the algorithm's exact internal key length. The root, expanded key, and
password buffers are zeroized.

Version 1 binaries reject version 2 and direct the user to the matching password
binary. Version 2 binaries likewise reject version 1 and direct the user to the
matching key-file binary.

Algorithm identifiers are 1 AES-256-GCM-SIV, 2 XChaCha20-Poly1305, 3
Serpent-256, 4 Threefish-1024, 5 Ascon-AEAD128, 6 Rabbit, 7 AEGIS-256, and 8
AEGIS-128L.

## AEAD records

There is one record per 1 MiB plaintext chunk. An empty file still has one
zero-length record so its header receives an authentication tag. A record is
ciphertext of the same length as its plaintext followed by a 16-byte tag.

The per-record nonce begins as the algorithm-sized prefix of the 32-byte nonce
seed. The big-endian 64-bit record index is XORed into its last eight bytes.
This preserves all random nonce bits while making every record nonce distinct
within a file.

Associated data is 80 bytes: the 64-byte header, 64-bit record index, 32-bit
record plaintext length, one byte that is 1 only for the final record, and three
zero bytes. It binds record order, the declared file length, algorithm, nonce
seed, chunk boundaries, and final record.

Decryption calculates the only valid total encrypted length from the header and
refuses truncated or trailing data before producing the requested output.

## Serpent, Threefish, and Rabbit records

These formats contain the header, ciphertext with the same length as the
plaintext, and a final 64-byte HMAC-SHA-512 tag.

HKDF-SHA-512 uses the 32-byte nonce seed as salt and the raw key file as input
key material. Domain-separated labels produce independent encryption keys,
tweaks or IVs, and 64-byte MAC keys for each algorithm and file.

Serpent uses its 256-bit derived key as a counter-mode keystream generator over
128-bit big-endian counters. Threefish-1024 uses a derived 1024-bit key and
128-bit tweak as a counter-mode keystream generator; the big-endian 128-bit
counter occupies the last 16 bytes of each 128-byte counter block. Rabbit uses a
derived 128-bit key and 64-bit IV. HMAC covers the exact header followed by all
ciphertext and is verified in constant time before the temporary plaintext is
installed at its requested name.

Any incompatible future change requires a new format version.
