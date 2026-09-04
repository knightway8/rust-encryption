# Security model and limitations

This project aims to provide password-based confidentiality and integrity for a
single file while making its cryptographic choices easy to inspect. It has not
received an independent security audit. Treat it as experimental software, keep
independent backups, and do not rely on it as the sole protection for valuable,
safety-critical, or regulated data.

## Threat model

The intended attacker can read, copy, delete, truncate, reorder, splice, append
to, or modify an encrypted file and can perform offline password guesses. The
attacker does not already know the password, control the running process, or
subvert the operating system, compiler, CPU, RNG, Rust dependencies, or this
executable.

Under those assumptions, and assuming the selected primitives and
implementation are sound, the format is designed so that:

- plaintext records are confidential;
- modifications to the header, record metadata, ciphertext, or tags are
  detected;
- missing, duplicated, reordered, spliced, or appended records are rejected;
- truncation is rejected, including an empty file or a file ending exactly on a
  chunk boundary;
- decryption failure never publishes the requested plaintext output;
- an existing destination is not overwritten.

Authentication proves only that the file was made by someone with the password.
It does not identify a sender, provide a signature or non-repudiation, prevent
deletion or rollback to an older valid ciphertext, or recover a forgotten
password.

## Construction summary

Version 1 derives a 32-byte master key with Argon2id version `0x13`, a fresh
16-byte salt, 64 MiB of memory, three passes, and one lane. HKDF-SHA256 then
separates keys by purpose, suite ID, and record index. Each encryption also uses
a fresh random 24-byte nonce seed. Exact formulas are normative in
[Format](FORMAT.md).

Every record authenticates:

```text
the complete 80-byte file header
the complete 16-byte record header
the ciphertext
and, for EtM suites, the encoded nonce
```

The mandatory empty FINAL record is authenticated like a data record. Together
with the authenticated plaintext length and exact index/length validation, it
closes the common “valid prefix” truncation hole in chunked formats.

Suite IDs 1–8 use native AEAD constructions with 16-byte tags. Suite IDs 9–30
use a repository-specific Encrypt-then-HMAC design with independent encryption
and MAC keys and full 32-byte HMAC-SHA256 tags. EtM tags are checked before
decryption.

## Algorithm status

There are exactly 30 suites, not 30 unrelated primitive families. Variants of
AES, Camellia, ARIA, Twofish, and Serpent account for multiple entries. See the
full [Algorithm registry](ALGORITHMS.md).

- AES-GCM and ChaCha20-Poly1305 are the most conventional native AEAD options in
  the catalog.
- AES-GCM-SIV and AES-CMAC-SIV are specialized misuse-resistant AEAD designs.
- XChaCha20-Poly1305 is widely deployed but less universally standardized.
- The 22 CTR/stream + HMAC suites use a custom composition, even when their
  component primitives are standardized.
- Camellia, ARIA, Twofish, Serpent, SM4, Kuznyechik, CAST6, BelT, Salsa20,
  XSalsa20, and HC-256 have smaller, older, or region-specific ecosystems than
  the mainstream AEAD choices. This means less interoperability and often less
  contemporary implementation scrutiny; it does not by itself assert a known
  break.

The niche and custom suites exist for study and comparative coverage. They are
not recommended over a mature, independently audited native-AEAD product for
production secrets. A large key size or “misuse-resistant” label does not
compensate for unaudited surrounding code.

## Password risks

The KDF slows guessing; it cannot turn a weak password into a strong key. The
header exposes the salt and KDF settings, as password-hash designs require, so a
stolen file permits unlimited offline guessing. Use a long, randomly generated
password that is unique to this data.

Version 1 fixes its Argon2id cost instead of accepting file-controlled settings.
This makes parsing predictable and prevents a malicious header from requesting
unbounded KDF resources. The fixed 64-MiB profile can become too weak as
hardware improves or unsuitable on constrained systems; changing it requires a
new format version.

Password files are exact byte sources. A trailing newline changes the password.
They also move the secret into a filesystem object that backups, malware, or
other users may read. Interactive input avoids command-line arguments and hides
terminal echo, but the password still exists transiently in process memory.

## Randomness, keys, and nonces

Salt and nonce-seed bytes come from the operating-system RNG; encryption aborts
if it fails. Randomness is essential for password-salt uniqueness and for
different ciphertext across repeated encryptions.

Record keys are independently expanded for the suite ID and record index. EtM
MAC keys use a separate HKDF purpose. Record nonces combine the random file seed
with the record index, including a dedicated 32-byte construction for HC-256.
Record indices are never allowed to repeat within a valid envelope.

These defenses reduce accidental key/nonce reuse inside the format. They do not
make it safe to clone internal derived keys into another protocol, bypass the
envelope API, weaken the RNG, or ignore index/length errors.

Sensitive buffers use supported zeroization facilities where practical, but
zeroization is best effort. Copies may exist in allocator internals, I/O
buffers, terminal libraries, registers, swap, crash dumps, hibernation images,
or platform caches. The project does not lock memory or defend against a
privileged local observer.

## Metadata leakage

Encryption does not hide:

- the format magic and version;
- selected suite and KDF profile;
- the exact plaintext byte length, stored in the header;
- record count and encrypted-file size;
- input/output filenames, paths, timestamps, ownership, permissions, access
  patterns, or the fact that encryption occurred.

The format does not compress or pad data and does not preserve original file
metadata inside the envelope.

## Output safety boundary

Encryption and decryption write a temporary file in the destination directory
and publish the requested name only after the complete operation succeeds. The
commit refuses to replace an existing path, including one created during a
race. Input and output aliases are rejected, and there is no in-place or force
mode.

This protects the requested destination from partial output during ordinary
application errors and ensures late authentication failure exposes no final
plaintext file. It is not transactional storage and does not promise survival
across power loss, kernel failure, disk-controller reordering, filesystem
corruption, or hostile replacement of directories/mounts. “Atomic” must not be
interpreted as a directory-`fsync` durability guarantee. Temporary-file cleanup
after a process kill also depends on the operating system.

During decryption, already authenticated records are written to a named
temporary file before later records and FINAL have been checked. The final path
is not published, but a local user who can inspect or interfere with the
destination directory is outside the stated threat model. Use a destination
directory whose access controls exclude untrusted local accounts.

The source remains in place after successful encryption and decryption. Secure
deletion is outside scope; deleting a file cannot reliably erase copies from
SSDs, snapshots, journaling filesystems, cloud synchronization, or backups.

Encryption detects an input that grows or shrinks relative to its initially
recorded length. It does not lock or snapshot the file and cannot detect every
same-length concurrent rewrite. Do not edit or replace the source while an
encryption operation is reading it.

## Parser and denial-of-service limits

All version 1 interpretation fields are fixed and canonically checked. Length
arithmetic is checked, records are capped by the fixed 65,536-byte chunk size,
and the expected total size is derived before normal decryption. The KDF profile
is validated before expensive work.

Valid inputs can still consume time proportional to file length, and each
password attempt intentionally consumes Argon2 resources. Filesystem or device
behavior can block I/O. This is a CLI, not a service with quotas or admission
control.

## Side channels and error handling

Wrong-password and corrupted-record failures share a generic authentication
error. Secrets and unauthenticated plaintext should never be formatted into an
error. Cryptographic comparison behavior is delegated to the selected RustCrypto
implementations.

The project is not designed or formally verified to resist every timing,
cache, power, speculative-execution, fault-injection, or microarchitectural side
channel. File size, processing duration, success/failure, and I/O patterns are
observable. A compromised machine can capture the password or plaintext before
encryption or after decryption.

## Operational guidance

- Prefer a mature audited encryption product for important data.
- If evaluating this repository, prefer the native AEAD subset and make an
  explicit, documented suite choice.
- Use a strong unique password and a trusted password manager.
- Keep at least one tested backup; periodically perform a recovery test.
- Retain the exact program version and dependency lockfile needed for archival
  ciphertext.
- Verify downloaded binaries and protect the host before entering a password.
- Never treat successful encryption as permission to erase the only plaintext
  copy until recovery has been independently tested.

Security reports should include the suite ID, application revision, platform,
and the smallest non-secret reproducer possible. Do not include real passwords,
keys, or sensitive plaintext in an issue or test fixture.
