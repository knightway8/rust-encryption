# otp1

`otp1` atomically XORs a file with `key.key`. Byte `n` of the file is XORed
with byte `n` of the key, so applying the same key a second time restores the
original bytes. Its command line and raw XOR file format are unchanged by the
optional authentication support described below.

```text
otp1 [--] <input-file>
```

The key is loaded from the directory reported by the operating system as
containing the running `otp1` executable, not from the current working
directory. It may be longer than the input, but it must not be shorter.

## Reliability behavior

- File contents and key bytes are streamed in fixed 64 KiB chunks. The XOR
  transform uses about 128 KiB of data buffers regardless of file size (plus
  small I/O and operating-system overhead); it never loads either whole file
  into memory. Atomic replacement still requires temporary disk space for one
  complete transformed copy of the input.
- The key length is checked before input content is read or a temporary output
  is created.
- The complete result is written to a newly created sibling file, the source's
  basic platform permissions are applied, and its data is synchronized before
  the input path is atomically replaced.
- On Unix, the containing directory is synchronized after the replacement. On
  Windows, the output file is synchronized before the standard atomic
  replacement operation; portable Rust does not expose directory syncing. A
  successful Windows operation therefore cannot explicitly confirm that the
  replacement directory entry has reached durable storage.
- Ordinary errors before replacement leave the original path untouched and
  attempt to clean up the temporary file. A crash, forced termination, cleanup
  error, or hostile directory race can leave a stale `.otp1-*.tmp` file.
- Exit status `3` specifically means replacement completed but crash durability
  could not be confirmed. Do **not** retry automatically: another XOR would
  reverse the completed operation. The unavailable directory-sync capability on
  Windows does not itself produce status `3`; a successful Windows operation
  normally exits `0` with the limitation described above.
- Symbolic-link inputs and keys, multiply-hard-linked inputs, non-regular files,
  and an input that aliases the key are rejected to avoid ambiguous or unsafe
  results. Unix and Windows are the supported target families.

On Windows, operations also require the filesystem or remote-filesystem
provider to supply a stable 128-bit file identifier. `otp1` fails closed when
that identity is unavailable, as does `otp1-auth`; some unusual or network
filesystems may therefore be unusable even though Windows itself is supported.

The input directory and executable/key directory must be trusted against
concurrent changes for the entire operation. `otp1` rechecks open handles and
path identities immediately before replacement, but portable pathname APIs
cannot make the final check and rename one conditional operation. Do not run it
while another process may write, rename, hard-link, or rotate the input, key, or
temporary output.

Both programs locate their keys using `std::env::current_exe`. The reported path
can vary when an executable was launched through a symbolic link or renamed
while running, and it is not a security trust root. Do not run either program
set-user-ID, set-group-ID, as Administrator, or with other elevated privileges
unless the executable path and its containing directory are controlled by the
same trusted administrator and cannot be redirected or replaced by a less
privileged user.

Atomic replacement preserves Unix mode bits and Windows file attributes
represented by `std::fs::Permissions`, but it can change the input's inode,
ownership, or timestamps. In particular, a newly created Windows replacement
inherits security from its directory; the source file's DACL is not copied.
ACLs, extended attributes, alternate data streams, sparse layout,
platform-specific flags, and security labels may not be preserved. Atomicity
and power-loss behavior ultimately depend on the filesystem, especially on
network filesystems. This is not secure erasure; old blocks, snapshots, backups,
open descriptors, or storage-device history may retain plaintext.

## Optional authenticated envelopes

`otp1-auth` is a separate binary which adds an authenticated envelope around an
existing raw `otp1` ciphertext. It does not XOR or otherwise alter the enclosed
ciphertext, and `otp1` continues to work exactly as before once a valid envelope
has been removed.

```text
otp1-auth keygen
otp1-auth seal [--force-raw] [--] <file>
otp1-auth verify [--] <file>
otp1-auth unwrap [--] <file>
```

- On Unix, `keygen` obtains 32 bytes from the operating system's random source
  and creates `auth.key` beside the running `otp1-auth` executable with mode
  `0600`. It never overwrites an existing path. On Windows, `keygen` fails
  closed because the portable implementation cannot establish a private DACL;
  provision the file manually as described below.
- `seal` atomically replaces a raw ciphertext with an authenticated envelope.
  A file beginning with the `OTP1AUTH` marker is refused, whether or not the
  rest of that file is valid, so an envelope cannot accidentally be sealed
  twice. Because raw OTP ciphertext can contain any byte sequence, use the
  explicit `seal --force-raw <file>` option when a legitimate raw ciphertext
  happens to begin with that marker. This option can also deliberately nest an
  envelope, so it should not be a workflow default.
- `verify` checks the complete envelope and authentication tag without changing
  its contents or replacing its path. Reading the envelope and `auth.key` may
  update their access timestamps according to operating-system and mount policy.
- `unwrap` checks the complete envelope and then atomically restores the exact
  enclosed ciphertext. Authentication or format failure leaves the envelope
  in place.

`auth.key` must contain exactly 32 **raw bytes**; it is not a hexadecimal string,
password, or `key.key`. It is resolved beside the operating-system-reported
`otp1-auth` executable rather than in the current working directory. Keep
`auth.key` and `key.key` separate and secret. Anyone with `auth.key` can create
envelopes that pass verification, while reuse of OTP bytes for authentication
would violate the key-management assumptions of the one-time pad. Symbolic-link
and multiply-hard-linked authentication keys are rejected.
On Unix, an existing `auth.key` must be owned by the effective user running
`otp1-auth` and is rejected if any group/other permission bit is set; use mode
`0600` or stricter.

On Windows, generate exactly 32 bytes with a cryptographically secure operating-
system tool, store those raw bytes as `auth.key` beside `otp1-auth`, and restrict
the file's DACL to only the account that should authenticate files (plus any
required trusted administrators). Do not use a password, textual hexadecimal
output, `key.key`, or a file in a broadly writable executable directory.

`keygen` creates the final key path directly so that it can refuse to overwrite
an existing key. A crash or cleanup failure after creation can leave a partial
or complete `auth.key` even when no success was reported. Inspect its exact
length and protection, then deliberately preserve or remove it before retrying;
never automate deletion merely because `keygen` returned an error. Exit status
`3` means the complete key was created but its directory
durability could not be confirmed, so it must not be retried automatically.

### Required order of operations

To encrypt and authenticate a file:

```text
otp1 <file>
otp1-auth seal <file>
```

To authenticate and decrypt it:

```text
otp1-auth verify <file>
otp1-auth unwrap <file>
otp1 <file>
```

`unwrap` performs its own complete verification, so the separate `verify`
command is useful as a check that leaves file contents and paths intact, but is
not a substitute for the check inside `unwrap`. If a workflow requires
authentication, it must reject a raw file rather than falling back to running
`otp1`; otherwise removing the envelope would become a downgrade attack. Never
run `otp1` on an expected authenticated file until `unwrap` has succeeded.

There is necessarily an unauthenticated interval after `unwrap` exposes the raw
ciphertext and before `otp1` transforms it. The corresponding interval exists
between `otp1` and `seal` during encryption. Keep the containing directory
trusted and exclude concurrent writers throughout the combined workflow.

### Envelope and I/O behavior

Version 1 consists of a canonical 32-byte header, the unchanged ciphertext,
and a full 32-byte HMAC-SHA-256 tag. The header identifies `OTP1AUTH`, the
format version and header length, zero flags and reserved fields, and the
unsigned 64-bit ciphertext length. Multi-byte integers use network byte order.
The MAC covers, in order:

```text
"otp1-auth/envelope/v1\0" || canonical header || unchanged ciphertext
```

Including the domain, header, and declared length prevents fields or payloads
from being reinterpreted without detection. HMAC follows
[RFC 2104](https://www.rfc-editor.org/rfc/rfc2104), with HMAC-SHA-256 test-vector
conventions described by [RFC 4231](https://www.rfc-editor.org/rfc/rfc4231).

Seal, verify, and unwrap stream with a fixed 64 KiB payload buffer, so their
memory use does not grow with the file. Seal and unwrap write a complete newly
created sibling file, apply the source's basic platform permissions, synchronize
it, then stream the staged bytes back through authentication before replacing
the original path. This read-back pass catches staged content corruption while
the original is still intact. The source and key are rechecked immediately
before the atomic replacement. This requires enough temporary disk space for
the complete result. The same platform durability, stale-temporary-file,
metadata, filesystem, trusted-directory, and concurrent pathname limitations
documented for `otp1` also apply to `otp1-auth`.

On Windows, applying source permissions means copying supported file attributes;
it does not copy the source DACL or ownership. Windows also lacks the portable
directory synchronization used on Unix. Consequently, exit status `3` can
report a failed post-commit directory synchronization on platforms where one is
attempted, but it cannot report the absence of that capability on Windows: a
successful Windows mutation normally exits `0` after synchronizing the output
file and performing the replacement.

`otp1-auth` uses these exit statuses:

- `0`: success.
- `1`: an operational error, such as an unavailable file or invalid key length.
- `2`: invalid command-line usage.
- `3`: the mutating operation committed, but directory crash durability could
  not be confirmed. Do not retry automatically; inspect the file first.
- `4`: `verify` or `unwrap` rejected an invalid envelope or authentication tag.
  The file was not unwrapped. Treat this as a hard authentication failure and
  do not pass the file to `otp1`.

### Authentication limits

Authentication only describes the bytes present when `seal` ran. Damage or
malicious modification which happened before sealing is authenticated as part
of the new envelope. A valid tag also does not prevent deletion or replacement
with an older, valid envelope; preventing rollback requires trusted external
state such as a monotonic counter or manifest. HMAC proves possession of the
shared `auth.key`, not the identity of a particular author.

The implementation clears its dedicated userspace authentication-key buffer
on drop, but cannot guarantee removal from operating-system caches, swap, crash
dumps, backups, storage history, or every intermediate machine state. Atomic
replacement is not secure erasure. Protect both key files, backups, and the
executable directory accordingly.

## Cryptographic limits

Raw XOR has no authentication. Damage, truncation, a wrong key, or malicious
bit flips cannot be detected by the raw file format. `otp1-auth` can detect
changes made after sealing, but it does not repair the key-reuse or randomness
requirements of XOR. This is a true one-time pad only when `key.key` bytes are
generated uniformly at random, kept secret, at least as long as the input, and
never reused for another message.

## Development

Run the complete suite with:

```text
cargo test --all-targets
cargo clippy --all-targets --all-features -- -D warnings
```

The project declares Rust 1.97 as its minimum supported toolchain. For CI and
release builds, add Cargo's `--locked` option (for example,
`cargo test --locked --all-targets`) so the command fails if the checked-in
dependency resolution would need to change.

The authentication implementation uses the RustCrypto `hmac` and `sha2`
crates, `getrandom` for operating-system key generation, and `zeroize` for the
in-process authentication-key buffer. Exact dependency versions are recorded
in `Cargo.lock`; build and test with `--locked` when that exact resolution is a
requirement.
