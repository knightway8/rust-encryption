# filecrypt format version 1

All integers are unsigned and little-endian. All offsets and sizes below are
bytes. A decoder must reject non-canonical values, unknown values, nonzero
reserved bytes, missing records, and trailing bytes.

## File header (96 bytes)

| Offset | Size | Field |
|---:|---:|---|
| 0 | 8 | ASCII magic `FCRYPT01` |
| 8 | 2 | Format version, `1` |
| 10 | 1 | Suite: `1` = AES-256-GCM-SIV, `2` = XChaCha20-Poly1305 |
| 11 | 1 | Flags, zero |
| 12 | 4 | Plaintext chunk size, exactly `1,048,576` |
| 16 | 8 | Total plaintext length |
| 24 | 32 | Random HKDF salt |
| 56 | 20 | STREAM nonce prefix field |
| 76 | 20 | Reserved, zero |

AES-256-GCM-SIV uses bytes 56–63 as its 8-byte STREAM nonce prefix and
requires bytes 64–75 to be zero. XChaCha20-Poly1305 uses all 20 bytes.

The maximum plaintext length is `0x7fffffff * 1,048,576` bytes. The number of
DATA records is `ceil(plaintext_length / 1,048,576)`; it is zero for an empty
plaintext.

## Key derivation

`key.key` is the 32-byte HKDF input keying material. The header's 32-byte salt
is the HKDF-Extract salt. HKDF uses SHA-256 and expands exactly 32 bytes with
one of these byte-exact `info` values:

```text
filecrypt/v1/aes-256-gcm-siv/stream-le31/key
filecrypt/v1/xchacha20-poly1305/stream-le31/key
```

The resulting per-file key initializes the selected AEAD.

## STREAM construction

Version 1 uses RustCrypto's `StreamLE31` construction. For STREAM position
`i`, the AEAD nonce is the stored prefix followed by the four-byte little-endian
value `i | (last << 31)`. DATA records have `last = 0`; the END record has
`last = 1`. DATA records occupy positions starting at zero. The END record's
position equals the number of DATA records.

Each AEAD has a 16-byte postfix authentication tag. The associated data for
every AEAD operation is the exact 96-byte file header followed by that record's
exact 16-byte record header.

## Record header (16 bytes)

| Offset | Size | Field |
|---:|---:|---|
| 0 | 1 | Type: `1` = DATA, `2` = END |
| 1 | 1 | Flags, zero |
| 2 | 2 | Reserved, zero |
| 4 | 4 | Ciphertext length, including the 16-byte AEAD tag |
| 8 | 8 | Sequence number |

The header is followed immediately by `ciphertext_length` ciphertext bytes.

Every DATA record except the last contains exactly 1,048,576 plaintext bytes.
The last contains the remaining nonzero plaintext bytes. Thus each DATA
ciphertext length is its canonical plaintext length plus 16, and its sequence
number is its zero-based DATA index.

## Authenticated END plaintext (24 bytes)

The mandatory END record is the STREAM last record. Its sequence number equals
the number of DATA records and its ciphertext length is exactly 40. Its
decrypted plaintext is:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 8 | ASCII footer magic `FCRYPTEN` |
| 8 | 8 | DATA-record count |
| 16 | 8 | Total plaintext length |

The footer count and length must equal the values derived from the header and
the records actually processed. The byte immediately after the END ciphertext
must be physical EOF. An empty file consists of the file header followed by a
single authenticated END record.

## Publication and filesystem requirements

These requirements describe safe handling of the plaintext and key; they are
not additional bytes in the version 1 wire format.

A conforming decryptor must not expose the requested final output pathname
until every record, the END footer, and physical EOF have verified. The
reference CLI implements that rule as follows:

1. It creates a randomly named protected staging subdirectory inside the
   destination's parent directory, keeping staging and publication on the same
   filesystem. The staged file is created inside that directory.
2. The staging directory and staged file are restricted to the current user.
   Unix uses private permission bits. Windows uses a protected current-user
   DACL and does not rely on permissive inherited directory ACLs. Failure to
   apply or verify these protections aborts the operation.
3. After writing, the open staged file is synchronized. Immediately before
   publication, the CLI checks that the staged pathname still identifies that
   open file; a replacement or redirection aborts publication.
4. The CLI performs one atomic, no-replace publication within the destination
   directory. If any object already occupies the final pathname, including one
   created concurrently, that object is preserved and publication fails. The
   CLI does not fall back to copying or to an operation that can replace an
   existing destination.
5. After publication, the final pathname is checked against the identity of the
   staged file. An identity mismatch is reported as possible tampering rather
   than treated as success.

Key generation follows the same protected staging and identity-checked,
no-replace publication contract. On Windows, both generated and externally
provided `key.key` files must satisfy the protected current-user DACL policy;
the reference CLI fails closed when it cannot enforce or verify that policy.

Atomic namespace publication and crash durability are different properties.
The staged file is synchronized before publication. The no-replace primitive
synchronizes the affected parent directories on Unix and requests a
write-through move on Windows. Filecrypt nevertheless does not claim that
every platform, filesystem, or storage device can make the resulting directory
entry power-loss durable. A publication primitive can also report a late
durability or cleanup failure after installing the no-replace destination. In
that case the reference CLI reports that the final path **was created** and
that crash durability is uncertain. A caller must not assume the path is
absent or retry by replacing it. Even a successful return cannot strengthen
guarantees beyond those offered by the operating system, storage device, and
filesystem after sudden power loss.

The reference publication contract is scoped to supported local Windows and
Linux filesystems that provide reliable file-identity and atomic no-replace
operations. Network shares, FUSE-style filesystems, cloud-synchronized
folders, removable media, and unusual filesystems are outside that guarantee.
The CLI fails when the required primitives report that they are unavailable,
but cannot compensate for a filesystem which falsely claims local-filesystem
semantics. A crash can leave a protected staging subdirectory; it is not a
published output.

## Audit status

Version 1 and the reference implementation have not received an independent
end-to-end security audit. RustCrypto's ChaCha20-Poly1305 implementation
reports an NCC Group audit with no significant findings. The upstream
AES-GCM-SIV crate states that it has not received a dedicated audit, and no
dependency audit should be interpreted as covering filecrypt's HKDF usage,
STREAM framing, parser, key handling, or filesystem publication protocol.
