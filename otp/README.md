# otp

otp is a file-oriented, authenticated one-time-pad application with deliberately
strict safety rules. It creates two copies of a pad for exactly one message:

- the **sender** copy can encrypt once;
- the **receiver** copy can decrypt once;
- the pad capacity must exactly equal the message length;
- existing output files are never overwritten.

The file contents are encrypted with uniformly random bytes from the operating
system. A separate random key authenticates the encrypted header and ciphertext
with HMAC-SHA-256, so damaged or modified data is rejected before plaintext is
created.

## Build

~~~console
cargo build --release
~~~

The executable is target/release/otp (otp.exe on Windows). Rust 2024 edition and
a current stable Rust toolchain are required.

## Quick start

Suppose message.bin is the file to send.

1. Create an exact-length pair:

   ~~~console
   otp pad create --for-file message.bin \
     --sender alice-send.otppad \
     --receiver bob-receive.otppad
   ~~~

2. Transfer bob-receive.otppad to Bob through a confidential, authenticated
   channel. Do not send it beside the ciphertext.

3. Encrypt with the sender copy:

   ~~~console
   otp encrypt --input message.bin \
     --pad alice-send.otppad \
     --output message.otp
   ~~~

4. Send message.otp over any channel.

5. Decrypt with the receiver copy:

   ~~~console
   otp decrypt --input message.otp \
     --pad bob-receive.otppad \
     --output message.bin
   ~~~

Both pad files are now marked consumed and retained. Destroy them only when you
are sure recovery is no longer needed:

~~~console
otp pad destroy --pad alice-send.otppad --yes
otp pad destroy --pad bob-receive.otppad --yes
~~~

pad destroy is irreversible and only a best-effort overwrite and truncation. It
intentionally leaves a zero-length placeholder instead of unlinking a path that
could have been replaced concurrently. Flash storage, copy-on-write filesystems,
snapshots, backups, and journaling can preserve old data.

Publishing two files cannot be atomic across arbitrary directories. The receiver
copy is published first because it cannot encrypt. If sender publication then
fails, the error names the receiver copy and tells you to inspect both paths;
explicitly destroy any orphan before retrying pad creation. A distinct error
also reports the rare case where an output was renamed into place but its parent
directory could not be synchronized. In that case, inspect the named output and
never retry the operation with its consumed pad.

## Commands

~~~text
otp pad create (--length SIZE | --for-file FILE) --sender FILE --receiver FILE
otp pad info --pad FILE
otp pad destroy --pad FILE --yes
otp encrypt --input FILE --pad FILE --output FILE
otp decrypt --input FILE --pad FILE --output FILE
~~~

Sizes are exact byte counts or integers followed by B, KB, MB, GB, TB, KiB, MiB,
GiB, or TiB. Decimal units use powers of 1000; binary units use powers of 1024.

Use --state-dir DIR to select the durable reuse-ledger directory. Otherwise the
application uses OTP_STATE_DIR, then the platform's per-user state directory.
Changing or deleting this directory creates a new reuse namespace and can let a
restored fresh-looking pad copy bypass the ledger. Keep one durable directory
for the lifetime of every pad created under that account.

## Safety properties

- **Exact single use.** The managed CLI has no offsets, reusable prefixes,
  cycling, password-derived pads, deterministic seeds, or raw-XOR escape
  hatches. The library's low-level XOR helper is documented as unsuitable for
  real encryption.
- **Independent secrets.** The pad bytes, authentication key, and public pad ID
  come directly from the OS random-number generator.
- **Authenticate before plaintext.** Decryption verifies the complete encrypted
  file before it creates a temporary plaintext output.
- **Fail closed.** Encryption durably reserves the sender pad before ciphertext
  can be committed. A failure after that point burns the pad rather than making
  reuse appear safe.
- **Two reuse barriers.** A marker inside the pad and a create-once local ledger
  both record use. The ledger also catches copied or restored pad files on the
  same account when the same state directory is retained.
- **Atomic output.** Output is written to an owner-only temporary file in the
  destination directory, flushed, and atomically persisted without clobbering an
  existing path.
- **Corruption detection.** Each secret pad file contains a private SHA-256
  checksum, and each encrypted file has a full HMAC-SHA-256 tag.
- **Bounded memory.** Files are processed in 64 KiB chunks.
- **Secret cleanup in memory.** Buffers holding pad material, authentication
  secrets, and plaintext are zeroed when released where Rust can control them.
- **Restricted key access.** Generated files are owner-only on Unix, and pads
  with group or world permission bits are refused. On Windows, protection also
  depends on the destination directory's inherited ACL.

## What one-time-pad security does and does not mean

The XOR encryption has perfect confidentiality only if all of these assumptions
hold:

1. every pad byte is independently and uniformly random;
2. the pad remains completely secret;
3. a pad is never reused, copied back from a snapshot, or processed outside this
   application;
4. endpoint machines are not compromised.

The application cannot prevent a copied pad from being used on another machine,
use after deleting or changing the ledger, direct editing of its files, OS-level
key capture, or recovery from storage snapshots. The local ledger is defense in
depth, not a mathematical proof of non-reuse.

The encrypted file reveals its length, format version, and a random pad
identifier. Authentication is computational and relies on HMAC-SHA-256; the XOR
confidentiality does not. No filename, timestamp, original path, compression, or
plaintext checksum is placed in the encrypted file.

For two-way communication, create two independent pairs: one for Alice-to-Bob
and a separate pair for Bob-to-Alice.

See [SECURITY.md](SECURITY.md) for the threat model and format details.

## Tests

~~~console
cargo test
cargo clippy --all-targets --all-features -- -D warnings
~~~

The suite covers core XOR invariants, deterministic generation, format parsing,
boundary sizes, binary and empty round trips, role separation, exact-length
enforcement, reuse and restored-copy blocking, tampering, wrong pads, truncation,
trailing data, output atomicity, corruption, Unicode paths, CLI usage, and
explicit destruction.
