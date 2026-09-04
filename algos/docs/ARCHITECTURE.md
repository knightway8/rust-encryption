# Architecture and audit guide

The central design rule is: **30 fixed entry points, one security-sensitive
implementation**. Binary wrappers select a `Suite`; they do not copy KDF,
cipher, parser, or file-I/O logic. This keeps the intended variation visible in
one registry and makes cross-suite tests table-driven.

## Module ownership

| File | Owns | Audit focus |
|---|---|---|
| [`src/lib.rs`](../src/lib.rs) | Crate boundary and public `Suite`, `Error`, and CLI surface | No hidden alternate implementation; unsafe Rust remains forbidden |
| [`src/suites.rs`](../src/suites.rs) | Stable IDs, names, binary names, native/custom classification, key/nonce/tag sizes, `ALL_SUITES` | Exactly 30 unique and internally consistent entries |
| [`src/format.rs`](../src/format.rs) | 80-byte header and 16-byte record-header encoding, canonical validation, checked length math | No ambiguous encodings or unchecked attacker-controlled lengths |
| [`src/kdf.rs`](../src/kdf.rs) | Fixed Argon2id profile, HKDF domain separation, per-record keys, MAC key, nonce derivation | Exact constants, key separation, counter bounds, zeroization |
| [`src/crypto.rs`](../src/crypto.rs) | Primitive dispatch, native AEAD sealing/opening, CTR/stream encryption, EtM tag calculation | Correct variant and sizes; authenticate EtM before decrypting |
| [`src/envelope.rs`](../src/envelope.rs) | Chunk sequencing, AAD construction, FINAL enforcement, full-file validation, temporary output and no-clobber commit | No truncation/splice acceptance and no partial published plaintext |
| [`src/cli.rs`](../src/cli.rs) | Common Clap contract, exact password-file reading, hidden prompt, path checks, error reporting | Passwords never enter argv or diagnostics; same-file/output policy |
| [`src/error.rs`](../src/error.rs) | Error taxonomy and user-facing messages | Authentication errors do not expose secrets or unauthenticated plaintext |
| `src/bin/*.rs` | One constant suite choice per executable | Wrapper name and suite match `Cargo.toml` and `Suite::binary_name()` |

[`Cargo.toml`](../Cargo.toml) disables automatic binary discovery and explicitly
lists the 30 wrappers. This makes an accidental 31st binary or missing wrapper a
reviewable manifest change. Cryptographic dependencies use exact version
requirements, while [`Cargo.lock`](../Cargo.lock) freezes the resolved graph.

## Encryption flow

1. The CLI resolves input, output, and password source; rejects empty or
   oversized passwords, same-file paths, and an existing destination.
2. The envelope layer records the source length and obtains a fresh 16-byte salt
   and 24-byte nonce seed from the operating-system RNG.
3. The KDF layer runs the fixed Argon2id v1 profile, then derives separated
   record and (where needed) MAC keys with HKDF-SHA256.
4. The envelope writes the canonical header to a temporary file in the output
   directory.
5. For each 65,536-byte chunk, it constructs the canonical record header and
   AAD, then asks the selected suite to seal the record.
6. It seals a mandatory empty FINAL record whose index equals the number of data
   records.
7. After the bytes read are confirmed to have the originally recorded length
   and all writes succeed, it flushes and `sync_all`s the temporary file, then
   publishes it at the requested path with a no-overwrite commit.

Any failure before step 7 leaves no newly published destination. The source is
read-only throughout.

## Decryption flow

1. The envelope reads exactly 80 header bytes and canonically validates all
   fixed fields before running the KDF.
2. It rejects a suite ID that does not equal the binary's compiled-in suite.
3. It checks length arithmetic and the encrypted file's expected size before
   accepting record-controlled allocations.
4. It derives keys, then reads records in exact index and length order.
5. Native AEAD records are opened with the canonical AAD. EtM tags are verified
   in full before their ciphertext is decrypted.
6. Plaintext goes only to a temporary destination. The envelope requires a
   valid empty FINAL record and EOF immediately afterward.
7. Only after the whole envelope authenticates does the no-overwrite commit
   publish the plaintext under the requested name.

Late corruption can therefore place bytes in an unpublished named temporary
file, but not in the requested output path. A local account able to inspect the
destination directory is outside this protection boundary and may be able to
observe temporary-file activity. This is also why decrypt-to-stdout and
in-place replacement are not offered.

## Cross-cutting invariants

The following properties belong to the shared core and must not migrate into
individual wrappers:

- suite IDs are stable `u16` protocol values;
- every format integer is fixed-width little-endian;
- header and record encodings are canonical;
- KDF settings are fixed before expensive work starts;
- encryption and MAC keys use different HKDF purposes;
- encryption keys are separated by suite ID and record index;
- every record authenticates the exact 80-byte header and 16-byte record header;
- record indices are contiguous, data lengths match the declared plaintext
  length, FINAL is mandatory, and trailing bytes are forbidden;
- EtM authentication happens before decryption;
- destination publication is no-overwrite and occurs only after full success;
- passwords, keys, and unauthenticated plaintext do not enter error messages.

The byte strings, sizes, endianness, and formulas that define these invariants
are in [Format](FORMAT.md). This document describes ownership, not a competing
protocol specification.

## Changing or adding a suite

The version 1 catalog is fixed at 30. Replacing or extending it is a protocol
decision, not a one-line implementation tweak. A reviewer should require all
of the following in one change:

1. Decide whether the work is a new format version. Never reuse or renumber an
   existing ID and never silently reinterpret old ciphertext.
2. Update the single `Suite` registry, including key, nonce, tag, name, binary,
   and native-AEAD classification.
3. Add or update the explicit `Cargo.toml` entry and thin `src/bin` wrapper.
4. Add the exact primitive dispatch. Check the crate type names, key layout,
   nonce layout, tag representation, CTR endianness, and dependency version.
5. Add authoritative primitive known-answer tests in both directions. If no
   independent whole-construction vector exists, label a local fixture as a
   regression vector rather than a correctness proof.
6. Run the shared all-suite envelope, tamper, truncation, boundary, and CLI
   atomicity matrices.
7. Update [Algorithms](ALGORITHMS.md), [Format](FORMAT.md) if a new version is
   involved, [Testing](TESTING.md), and [Security](SECURITY.md).

For AI-assisted edits, first ask the model to identify the owning module and
state which invariants could change. Keep generated changes small, demand exact
test-vector provenance, and review the resulting diff and dependency tree. A
passing round trip is not evidence that a cryptographic implementation matches
its standard.

## Deliberate non-features

- No auto-selected suite or generic “decrypt anything” executable.
- No algorithm negotiation.
- No variable or file-controlled Argon2 work factor in version 1.
- No compression, filename/metadata storage, stdin/stdout data stream, in-place
  rewrite, append mode, resume mode, or force overwrite.
- No claim of a stable general-purpose Rust library API; the on-disk IDs and
  version 1 bytes are the compatibility boundary.
- No unsafe Rust in this crate.

These constraints reduce parser states and prevent convenience features from
weakening the all-or-nothing output guarantee.

## Concurrent source modification

Encryption records the input's length before reading, uses exact-length reads,
and checks for an extra byte afterward. It therefore detects a source that
shrinks or grows during the operation. It does **not** take a filesystem
snapshot, lock the input, or detect a same-length rewrite that races the read.
Do not modify an input while encrypting it; otherwise the authenticated result
may represent a mixture of source states.
