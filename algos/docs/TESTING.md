# Testing and verification

The test strategy separates primitive correctness, construction correctness,
container integrity, and CLI/file behavior. This distinction matters: an
encrypt/decrypt round trip can pass when encryption and decryption share the
same mistake.

## Standard local checks

Run these from the repository root:

```text
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
```

Also run the test suite in release mode before a release candidate:

```text
cargo test --release --all-targets
```

Argon2id's production profile intentionally costs 64 MiB and three passes.
Large combinatorial tests should exercise internal fixed-master-key seams so
that corruption cases test crypto and parsing without rerunning Argon2id
thousands of times. A smaller hidden “test KDF” must never be available in a
production binary. Keep a smaller number of end-to-end tests that use the real
password KDF.

To run the deliberately slow production-KDF round trip through all 30 process
entry points:

```text
cargo test --test cli_contract slow_every_binary_process_round_trip -- --ignored --exact --test-threads=1
```

## Automated coverage in this revision

The current tree provides these concrete layers:

- [`tests/primitive_vectors.rs`](../tests/primitive_vectors.rs) calls the
  cryptographic crates directly. It contains named, independently sourced
  vectors for every primitive family and every key width used by the registry,
  plus inverse, fragmented-stream, and authentication-mutation checks where
  applicable.
- Unit tests in [`src/envelope.rs`](../src/envelope.rs) round-trip all 30 suites
  at empty, block-adjacent, one-chunk, and exact two-chunk boundaries with a
  fixed master key. They cover every suite with a wrong key and changed tag; they also cover
  all header-byte mutations, truncation/append, record reorder/splice, fresh
  header material, and cross-suite rejection on representative or exhaustive
  scopes appropriate to each case.
- Unit tests in [`src/format.rs`](../src/format.rs),
  [`src/kdf.rs`](../src/kdf.rs), [`src/crypto.rs`](../src/crypto.rs), and
  [`src/cli.rs`](../src/cli.rs) cover canonical encodings, checked length math,
  Argon2id and HKDF reference cases, key/nonce separation, all adapter branches,
  tag rejection, exact password-file bytes, and password bounds. Bounded
  property cases exercise arbitrary 80-byte/16-byte parser inputs and arbitrary
  binary envelope payloads across generated suite IDs.
- [`tests/cli_contract.rs`](../tests/cli_contract.rs) verifies suite-specific
  help for all 30 binaries, production-Argon2 round trips for a native and an
  EtM representative, generic wrong-password behavior, late-corruption output
  safety, and no-overwrite behavior. Its ignored release gate runs a full
  production-KDF process round trip through every binary.

Important gaps are kept explicit: this revision includes a frozen regression
vector for the exact production Argon2id/HKDF wrapper, but does not yet include
a whole-container interoperability vector or broad fuzzing beyond the bounded
parser/payload property cases, injected RNG/read/write failures, a no-clobber
race test, or the full platform/path matrix later in this document. The
sections below are the required direction for future hardening, not claims that
every listed case is already automated.

## Test layers

| Layer | Purpose | Failure caught |
|---|---|---|
| Primitive known-answer tests | Compare exact key/nonce/input/output bytes with an authoritative source | Wrong algorithm variant, key width, nonce layout, counter endianness, or tag representation |
| KDF known-answer tests | Check Argon2id, HKDF-SHA256, info strings, output lengths, and nonce formulas | A self-consistent but incompatible key schedule |
| Deterministic record tests | Freeze exact version 1 AAD, ciphertext, and tag bytes | Accidental wire-format or composition drift |
| All-suite envelope matrix | Apply the same round-trip and corruption cases to all 30 `Suite` values | A forgotten or inconsistent registry/dispatch branch |
| Format/parser tests | Feed canonical and malformed headers/records | Ambiguity, panic, excessive allocation, truncation acceptance |
| CLI/process tests | Execute all 30 compiled binaries | Wrapper mismatch, prompt/argument drift, non-atomic output behavior |
| Property tests | Explore arbitrary plaintext and malformed byte sequences | Boundary interactions missed by hand-written examples |

Do not call a locally generated ciphertext an independent known-answer test.
Use “regression vector” when the expected value was produced by this same code.
For a KAT, record the standard, document, or independent implementation; exact
variant and byte ordering are part of that provenance.

## Required per-suite matrix

Shared table-driven tests should run each case for every entry in `ALL_SUITES`:

- empty plaintext (which must still produce and require FINAL);
- one byte and the complete byte range `00..ff`;
- repetitive and high-entropy inputs;
- sizes `0`, `1`, `15`, `16`, `17`, `65,535`, `65,536`, `65,537`,
  `131,071`, `131,072`, and `131,073`;
- multiple randomized round trips, with a fixed failing seed printed by the
  property framework;
- two encryptions of identical input/password differ because salt and nonce seed
  are fresh;
- wrong password and wrong derived key fail authentication;
- changing the suite ID or invoking every wrong suite binary fails;
- bit flips in header, record header, ciphertext, and tag fail;
- truncation at every structural boundary and representative interior offsets
  fails;
- deletion, duplication, reordering, and cross-file splicing of records fail;
- bytes appended after a valid FINAL fail;
- record-index and checked-length overflow helpers fail without huge files.

For a short encrypted fixture, flipping every individual input byte is a useful
exhaustive authentication test. Run that below the password KDF so it remains
fast.

## Primitive and composition vectors

At minimum, use independent vectors for:

- AES-GCM from NIST GCM/CAVP material;
- AES-GCM-SIV from RFC 8452;
- AES-CMAC-SIV from RFC 5297-compatible AES-SIV vectors;
- ChaCha20-Poly1305 from RFC 8439;
- XChaCha20-Poly1305 from a pinned upstream implementation/vector set;
- AES, Camellia, ARIA, Twofish, Serpent, SM4, Kuznyechik, CAST6, and BelT block
  cipher encrypt/decrypt operations with every supported key width;
- Salsa20, XSalsa20, and HC-256 keystream behavior;
- HMAC-SHA256 from RFC 4231;
- HKDF-SHA256 from RFC 5869;
- Argon2id with a published vector using version `0x13`.

For CTR suites, a block-cipher KAT is not enough. Add an exact multi-block CTR
fixture that detects a wrong initial counter or wrong counter endianness. Add a
two-record fixture with identical zero plaintext to ensure record key/nonce
state is not accidentally reused. For the three native stream ciphers, test
their native IV/nonce setup rather than describing them as CTR.

For every EtM suite, independently test that:

- the record encryption result is correct;
- the MAC covers the exact domain, AAD, nonce-length byte, nonce, and ciphertext;
- all 32 tag bytes are checked;
- a failed tag prevents the decrypt routine from being invoked;
- encryption and MAC keys differ and change when suite ID or record index should
  change them.

## Format and parser cases

Header tests should mutate each interpretation field: magic, version, header
length, suite, KDF, flags, memory cost, time cost, lanes, reserved bytes, chunk
size, plaintext length, salt, and nonce seed. Fixed fields must be rejected
before KDF work. Variable authenticated fields may parse, but must fail record
authentication after mutation.

Record tests should cover invalid flags, nonzero reserved bytes, zero-length
data records, nonzero FINAL length, wrong indices, impossible remaining lengths,
missing FINAL, duplicate FINAL, and trailing bytes. Arbitrary short byte strings
must not panic, hang, or trigger allocations derived from unchecked lengths.

Direct unit tests should cover both nonce branches:

```text
N <= 24: seed[0..N], with index_le_u64 XORed into its last eight bytes
N == 32: seed[0..24] || index_le_u64
```

Include carries and high-bit indices, not only indices zero and one.

## File-system and CLI cases

Process-level tests should enumerate the manifest's 30 binary names and compare
them with `ALL_SUITES`. For every binary, `--help` must work and identify the
expected fixed suite, and at least one process-level round trip should confirm
the wrapper mapping.

The common CLI tests should also verify:

- missing and contradictory arguments produce a nonzero exit without secrets;
- interactive encryption confirms the password;
- password-file bytes are exact, including trailing LF, CRLF, NUL, and non-UTF-8
  bytes where the platform permits them;
- empty and over-1-MiB passwords are rejected;
- missing input, directory input/output, missing parent, same path, hard-link
  alias, and existing destination fail safely;
- Unicode and space-containing paths work;
- an output created by a race is not overwritten;
- wrong password, malformed header, early or late tag failure, truncated FINAL,
  input read error, output write error, and RNG failure publish no destination;
- an existing destination remains byte-for-byte unchanged on every failure;
- temporary files are cleaned up on ordinary failure;
- source files are never modified or deleted.

Atomic publication does not imply crash durability. Platform-specific tests may
exercise interruption around the final commit, but documentation and tests must
not claim directory `fsync` semantics that the implementation does not provide.

## Review gate for future edits

A cryptography-affecting change is not ready merely because `cargo test` is
green. Its review should include:

1. the exact standards/crate variant and test-vector provenance;
2. a diff of all protocol constants and suite metadata;
3. all 30 suite-matrix cases;
4. deterministic interoperability/regression fixture review;
5. dependency advisory and license review;
6. tests proving authentication failure has no published plaintext;
7. `cargo fmt`, strict Clippy, debug tests, and release tests on every supported
   operating system.

When a platform-specific case cannot be automated, record the manual procedure
and result rather than silently omitting it.
