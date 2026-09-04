# filecrypt

`filecrypt` is a bounded-memory file-encryption CLI for Windows and Linux. It
supports AES-256-GCM-SIV and XChaCha20-Poly1305, processes files in 1 MiB
authenticated records, and refuses to replace any existing output.

## Build

Requires Rust 1.85 or newer:

```console
cargo build --release
```

The executable is `target/release/filecrypt` on Linux and
`target\\release\\filecrypt.exe` on Windows. Keep `key.key` in that exact
directory beside the executable. The current working directory is never
searched for a key.

Create a new key safely (this fails if `key.key` already exists):

```console
filecrypt keygen
```

The file contains exactly 32 **raw binary bytes**. It is not hex text and no
newline is allowed. Back it up separately; losing it makes every encrypted file
unrecoverable. On Unix, filecrypt rejects a key with group or other permission
bits, so an externally installed key should normally use mode `0600`. On
Windows, filecrypt requires a protected DACL for `key.key` which grants access
to the current user without inheriting broader access from the containing
directory. Key generation applies that DACL and key loading verifies it; the
operation fails closed if the protection cannot be established or checked.

## Usage

The requested short form encrypts a file:

```console
filecrypt 1 INPUT OUTPUT
filecrypt 2 INPUT OUTPUT
```

`1` selects AES-256-GCM-SIV. `2` selects XChaCha20-Poly1305. The explicit form
is also available:

```console
filecrypt encrypt 1 INPUT OUTPUT
filecrypt encrypt 2 INPUT OUTPUT
filecrypt decrypt INPUT OUTPUT
```

Decryption obtains the algorithm from the authenticated file header. Paths may
contain spaces or non-UTF-8 bytes on Unix. Use `--` before paths beginning with
`-` when desired. Exit status is 0 for success, 1 for an operational or
authentication failure, and 2 for invalid CLI usage.

No command overwrites a regular file, symlink, hard link, directory, or key.
Encryption and decryption are never in-place; choose a destination that does
not exist.

## Security and integrity design

- `key.key` is a uniformly random 256-bit master key. A random 256-bit salt and
  HKDF-SHA-256 derive a separate per-file key, with different domain labels for
  the two algorithms.
- The RustCrypto STREAM LE31 construction authenticates frame ordering and the
  final-frame state. Every DATA record additionally authenticates the exact
  file header, record type, ciphertext length, and sequence number as AEAD
  associated data.
- A mandatory encrypted END record authenticates the total plaintext length
  and DATA-record count. Empty files therefore still contain an authenticated
  final record. Missing, duplicated, reordered, truncated, modified, or
  appended records fail decryption.
- Attacker-controlled lengths are validated against fixed bounds before any
  allocation. Memory use is bounded to a small multiple of the 1 MiB record
  size. The format supports plaintexts up to roughly 2 PiB.
- Output is written inside a randomly named, current-user-only staging
  subdirectory created within the destination's parent directory. On Unix the
  staging directory and file are private; on Windows they receive a protected
  current-user DACL instead of inheriting a potentially broad parent DACL.
- Before publication, filecrypt synchronizes the staged file and verifies that
  its pathname still identifies the open file. It then uses a same-filesystem,
  atomic no-replace publication operation and verifies that the new destination
  identifies the file that was staged. A destination created concurrently is
  preserved. There is no copying, replacing, or non-atomic fallback.
- During decryption, the requested final pathname is not made visible until all
  authentication checks and physical EOF verification succeed. Key generation
  uses the same protected, identity-checked no-replace publication discipline.
- Master keys, per-file keys, cipher key schedules, and chunk buffers use
  best-effort zeroization on drop. This does not provide `mlock`, swap
  protection, or protection from a compromised process or operating system.

The encrypted format is intentionally versioned; files produced by version 1
are expected to remain decryptable by future compatible releases.

## Operational limits

- This tool authenticates file contents and its own format metadata, not the
  original filename, timestamps, permissions, or ownership. Decrypted outputs
  are newly created private files rather than metadata clones.
- A static local key cannot detect rollback: replacing an encrypted file with
  an older, otherwise valid copy will still authenticate. Detecting rollback
  requires trusted external state or signatures.
- Do not modify a source file while it is being encrypted. Filecrypt detects
  length changes, but portable filesystem APIs cannot provide a coherent
  snapshot against every concurrent writer.
- The staging, identity, atomicity, and no-replace guarantees are scoped to
  supported local Windows and Linux filesystems with ordinary local-file
  semantics. Network shares, FUSE-style filesystems, cloud-synchronized
  folders, removable media, and unusual filesystems may not provide the
  required identity or atomic namespace operations. Filecrypt fails rather
  than deliberately falling back to a copy or replacement, but it cannot make
  a misbehaving filesystem honor local-filesystem guarantees.
- A forced process termination can leave a private staging subdirectory beside
  the intended output. It is not a successfully published output and never
  authorizes replacing an existing destination; remove it only after ensuring
  no filecrypt process is using it.
- If an error explicitly says a path "was created" but durability is
  uncertain, that path already exists and was not overwritten; inspect and
  retain it rather than retrying over it. Its survival across an immediate
  system crash is the uncertain part. Atomic publication prevents partial
  visibility, but it is not by itself a guarantee of persistence after sudden
  power loss. Filecrypt synchronizes the staged file before publication and
  requests durable namespace publication (including parent-directory sync on
  Unix and a write-through move on Windows), but does not claim that every
  platform, filesystem, or storage device can make the resulting directory
  entry power-loss durable.

## Audit status

This application, its file format, and its complete cryptographic and
filesystem construction have not received an independent security audit.
RustCrypto's ChaCha20-Poly1305 implementation reports an NCC Group audit with
no significant findings, while the upstream AES-GCM-SIV crate states that it
has not received a dedicated audit. Those facts do not constitute an audit of
STREAM framing, key handling, publication logic, or filecrypt as a whole.
Passing tests, Clippy, or an advisory scanner is not a substitute for a
security review.

## Verification

```console
cargo test --all-targets
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --check
```

These commands describe the intended verification workflow; they do not imply
that every target has been exercised. In particular, native Windows build,
test, DACL, and publication checks must run on Windows. No native Windows test
result is claimed here.
