# Cipher-suite registry

This is the complete version 1 registry. It has exactly 30 entries. Each row is
a distinct suite because the full construction and/or key size differs, but the
rows do not represent 30 unrelated primitive families.

`K` is the per-record suite-key length, `N` is the record nonce length, and `T`
is the stored tag length, all in bytes. Encrypt-then-HMAC (EtM) rows also use a
separate 32-byte file HMAC key. IDs and binary names are stable protocol and CLI
identifiers.

| ID | Binary | Construction | K | N | T | Status |
|---:|---|---|---:|---:|---:|---|
| 1 | `aes128-gcm-file` | AES-128-GCM | 16 | 12 | 16 | Native AEAD; mainstream |
| 2 | `aes256-gcm-file` | AES-256-GCM | 32 | 12 | 16 | Native AEAD; mainstream |
| 3 | `aes128-gcm-siv-file` | AES-128-GCM-SIV | 16 | 12 | 16 | Native AEAD; specialized/misuse-resistant |
| 4 | `aes256-gcm-siv-file` | AES-256-GCM-SIV | 32 | 12 | 16 | Native AEAD; specialized/misuse-resistant |
| 5 | `aes128-cmac-siv-file` | AES-128-CMAC-SIV | 32 (2×16) | 16 | 16 | Native AEAD; specialized/misuse-resistant |
| 6 | `aes256-cmac-siv-file` | AES-256-CMAC-SIV | 64 (2×32) | 16 | 16 | Native AEAD; specialized/misuse-resistant |
| 7 | `chacha20-poly1305-file` | ChaCha20-Poly1305 | 32 | 12 | 16 | Native AEAD; mainstream |
| 8 | `xchacha20-poly1305-file` | XChaCha20-Poly1305 | 32 | 24 | 16 | Native AEAD; widely deployed, less standardized |
| 9 | `aes128-ctr-hmac-file` | AES-128-CTR + HMAC-SHA256 | 16 | 16 | 32 | Custom EtM; AES is mainstream |
| 10 | `aes192-ctr-hmac-file` | AES-192-CTR + HMAC-SHA256 | 24 | 16 | 32 | Custom EtM; AES-192 is uncommon |
| 11 | `aes256-ctr-hmac-file` | AES-256-CTR + HMAC-SHA256 | 32 | 16 | 32 | Custom EtM; AES is mainstream |
| 12 | `camellia128-ctr-hmac-file` | Camellia-128-CTR + HMAC-SHA256 | 16 | 16 | 32 | Custom EtM; niche |
| 13 | `camellia192-ctr-hmac-file` | Camellia-192-CTR + HMAC-SHA256 | 24 | 16 | 32 | Custom EtM; niche |
| 14 | `camellia256-ctr-hmac-file` | Camellia-256-CTR + HMAC-SHA256 | 32 | 16 | 32 | Custom EtM; niche |
| 15 | `aria128-ctr-hmac-file` | ARIA-128-CTR + HMAC-SHA256 | 16 | 16 | 32 | Custom EtM; regional/niche |
| 16 | `aria192-ctr-hmac-file` | ARIA-192-CTR + HMAC-SHA256 | 24 | 16 | 32 | Custom EtM; regional/niche |
| 17 | `aria256-ctr-hmac-file` | ARIA-256-CTR + HMAC-SHA256 | 32 | 16 | 32 | Custom EtM; regional/niche |
| 18 | `twofish128-ctr-hmac-file` | Twofish-128-CTR + HMAC-SHA256 | 16 | 16 | 32 | Custom EtM; older/niche |
| 19 | `twofish192-ctr-hmac-file` | Twofish-192-CTR + HMAC-SHA256 | 24 | 16 | 32 | Custom EtM; older/niche |
| 20 | `twofish256-ctr-hmac-file` | Twofish-256-CTR + HMAC-SHA256 | 32 | 16 | 32 | Custom EtM; older/niche |
| 21 | `serpent128-ctr-hmac-file` | Serpent-128-CTR + HMAC-SHA256 | 16 | 16 | 32 | Custom EtM; older/niche |
| 22 | `serpent192-ctr-hmac-file` | Serpent-192-CTR + HMAC-SHA256 | 24 | 16 | 32 | Custom EtM; older/niche |
| 23 | `serpent256-ctr-hmac-file` | Serpent-256-CTR + HMAC-SHA256 | 32 | 16 | 32 | Custom EtM; older/niche |
| 24 | `sm4-ctr-hmac-file` | SM4-CTR + HMAC-SHA256 | 16 | 16 | 32 | Custom EtM; regional/niche |
| 25 | `kuznyechik-ctr-hmac-file` | Kuznyechik-CTR + HMAC-SHA256 | 32 | 16 | 32 | Custom EtM; regional/niche |
| 26 | `cast6-ctr-hmac-file` | CAST6-256-CTR + HMAC-SHA256 | 32 | 16 | 32 | Custom EtM; older/niche |
| 27 | `belt-ctr-hmac-file` | BelT-CTR + HMAC-SHA256 | 32 | 16 | 32 | Custom EtM; regional/niche |
| 28 | `salsa20-hmac-file` | Salsa20 + HMAC-SHA256 | 32 | 8 | 32 | Custom EtM; older/niche |
| 29 | `xsalsa20-hmac-file` | XSalsa20 + HMAC-SHA256 | 32 | 24 | 32 | Custom EtM; niche |
| 30 | `hc256-hmac-file` | HC-256 + HMAC-SHA256 | 32 | 32 | 32 | Custom EtM; older/niche |

The status column describes present-day deployment familiarity and the nature
of this repository's construction; it is not a claim that a primitive is
broken. More obscure choices have fewer implementations, reviewers, test
vectors, and interoperability opportunities. That increases engineering risk
even in the absence of known cryptanalytic breaks.

## Native AEAD subset

IDs 1–8 are implemented through authenticated-encryption interfaces. They bind
the version 1 associated data and produce a 16-byte tag for every record.

- AES-GCM and ChaCha20-Poly1305 are the most conventional choices in this
  catalog.
- AES-GCM-SIV and AES-CMAC-SIV are designed to be more tolerant of nonce misuse,
  but that property does not repair weak passwords, broken randomness, or
  application-level mistakes.
- XChaCha20-Poly1305's extended nonce is widely used in practice, but its exact
  construction is less universally standardized than ChaCha20-Poly1305.
- The SIV names include the underlying AES key width. Their suite keys are
  compound, which explains the 32- and 64-byte `K` values.

Native AEAD does not make the surrounding password container audited. The
format, KDF integration, record sequencing, file handling, and dependency
versions still require review.

## Custom Encrypt-then-HMAC subset

IDs 9–30 are not claims of 22 new standardized AEAD algorithms. They use this
repository's versioned construction:

```text
per-record cipher with a per-record HKDF key
then full HMAC-SHA256 over domain || AAD || nonce encoding || ciphertext
```

The HMAC key is independently derived, and decryption verifies the HMAC before
running the cipher. See [Format](FORMAT.md) for the byte-level definition.
These are reasonable ingredients for experimentation and comparative testing,
but the complete compositions have not been independently standardized or
audited. Prefer a well-reviewed native AEAD system for production data.

IDs 9–26 use big-endian 128-bit CTR for their 128-bit block cipher. ID 27 uses
the `belt-ctr` construction supplied for BelT. IDs 28–30 are native stream
ciphers, not CTR wrappers.

## Selection guidance

There is intentionally no automatic default and no “best algorithm” claim.
When evaluating this project:

- start with the native AEAD subset;
- choose based on platform support, applicable standards, and independent audit
  requirements, not key length alone;
- treat all 22 custom EtM suites and all niche/legacy primitives as research or
  compatibility options;
- retain independent backups regardless of suite;
- record the exact application version and binary needed for long-term
  decryption.

Every binary refuses a file whose header names another suite. This explicit
mapping prevents algorithm substitution and makes the chosen implementation
obvious during an audit.

