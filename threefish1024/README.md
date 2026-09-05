# threefish1024

`threefish1024` is a command-line program for authenticated, streaming file
encryption built around the Threefish-1024 block cipher. It takes regular files
as positional arguments in **input, then output** order and uses a 1024-bit
binary master key.

> **Security notice:** this project defines a custom Threefish counter-mode and
> encrypt-then-MAC construction. It has not been independently audited. Treat it
> as experimental, review it for your threat model, and do not rely on it as the
> only copy of important data.
>
> The upstream RustCrypto `threefish` crate also labels itself a hazardous
> low-level primitive: it has not received a security audit and has not been
> thoroughly assessed for constant-time execution on common processors.

## Build and install

Rust 1.98.1 or newer is required.

```console
cargo build --release --locked
```

From the workspace root, the executable is written to
`target/release/threefish1024` (or `target\release\threefish1024.exe` on
Windows). From this member directory the same workspace output is at
`../target/release/threefish1024`. To install it into Cargo's bin directory from
this member directory:

```console
cargo install --path . --locked
```

## Usage

The exact command forms are:

```text
threefish1024 [--key FILE] keygen
threefish1024 [--key FILE] kegen
threefish1024 [--key FILE] encrypt [--force] FILE_IN FILE_OUT
threefish1024 [--key FILE] decrypt [--force] FILE_IN FILE_OUT
```

`kegen` is a supported alias for `keygen`.

A typical round trip is:

```console
threefish1024 keygen
threefish1024 encrypt report.pdf report.pdf.tf1024
threefish1024 decrypt report.pdf.tf1024 restored-report.pdf
```

The first positional path is always read and the second is always written. The
program refuses to use the same file for both, and it refuses any operation
that would use or replace the master key as data.

### Key location

Unless `--key FILE` is supplied, every command uses `key.key` in the process's
**current working directory**. This is the directory from which the command is
run, not the directory containing the executable, input, or output. Changing
directories therefore changes which default key is used.

For an explicit key location:

```console
threefish1024 --key /secure/keys/archive.key keygen
threefish1024 --key /secure/keys/archive.key encrypt source.bin source.bin.enc
threefish1024 --key /secure/keys/archive.key decrypt source.bin.enc recovered.bin
```

`keygen` creates exactly 128 bytes (1024 bits) from the operating system's
cryptographic random source. The key is raw binary data, not text, a passphrase,
or a hexadecimal string. Key generation never overwrites an existing path.

On Unix, generated keys are created with mode `0600`, and encryption or
decryption rejects a key that grants any group or other-user permission. Key
paths must be regular files and may not be symbolic links. Other operating
systems use their native access controls; review the resulting ACL yourself.

> **Back up `key.key` before encrypting valuable data.** If this key is lost or
> damaged, there is no password reset or recovery mechanism and the encrypted
> files cannot be decrypted. Keep multiple tested backups in separately secured
> locations, and never store the only key backup beside the only ciphertext
> backup.

### Existing outputs and `--force`

Encryption and decryption do not overwrite an existing output by default:

```console
threefish1024 encrypt source.bin archive.enc
threefish1024 decrypt archive.enc restored.bin
```

Pass `--force` (or `-f`) to replace the destination:

```console
threefish1024 encrypt --force source.bin archive.enc
threefish1024 decrypt --force archive.enc restored.bin
```

Output is written to a mode-`0600` temporary file on Unix (or a file inheriting
the destination directory's ACL on other systems), flushed and synchronized,
and then published in the same directory. A failed encryption does not normally
publish a partial ciphertext. Decryption does not publish any plaintext until
the entire encrypted file has authenticated. With `--force`, publication
replaces the old destination; without it, publication uses no-clobber behavior.
Key generation follows the same staged publication pattern but never offers an
overwrite option.

The final rename is atomic on filesystems that provide atomic same-directory
rename semantics. Filesystem, network-share, and operating-system guarantees
still apply; synchronization of the file does not make every storage stack
immune to power loss.

## Authenticated file format

All multi-byte integers in the version 1 header are little-endian. An encrypted
file contains:

| Offset | Size | Contents |
| ---: | ---: | --- |
| 0 | 8 | Magic bytes `TF1024\0\0` |
| 8 | 2 | Format version (`1`) |
| 10 | 2 | Algorithm identifier (`1`) |
| 12 | 4 | Header length (`80`) |
| 16 | 8 | Flags/reserved bytes (zero) |
| 24 | 8 | Plaintext length |
| 32 | 32 | Random per-file HKDF salt |
| 64 | 16 | Random per-file Threefish tweak |
| 80 | N | Ciphertext, the same length as the plaintext |
| 80 + N | 64 | HMAC-SHA-512 authentication tag |

The fixed overhead is therefore **144 bytes**: an 80-byte header and a 64-byte
tag. The plaintext length is visible in the header, and the ciphertext length
also reveals it.

HKDF-SHA-512 derives separate 128-byte encryption and 64-byte authentication
keys from the master key and the random per-file salt. Threefish-1024 is used as
a counter-mode keystream generator with the per-file tweak. HMAC-SHA-512
authenticates a domain separator, the complete header, and the ciphertext
(encrypt-then-MAC). A fresh salt and tweak make repeated encryption of the same
file produce different output.

Decryption verifies the declared length, rejects trailing or truncated data,
and checks the authentication tag before publishing plaintext. Authentication
failure means either that the wrong key was supplied or that the encrypted file
was modified; the program intentionally does not distinguish those cases.

## Limitations

- The construction and container format are project-specific and unaudited;
  interoperability should not be assumed.
- Only regular files are supported. There is no standard-input or
  standard-output streaming interface.
- This is key-file encryption, not password-based encryption. Human passwords
  do not have enough entropy to be used as the 128-byte key, and no deliberately
  slow password-hardening function is provided.
- File names, directory structure, timestamps, permissions, ciphertext size,
  and plaintext length are not encrypted. There is no padding or metadata
  preservation.
- The program cannot recover a lost key and does not provide key rotation,
  escrow, or secure deletion. Operating-system caches, swap, backups, and
  storage snapshots may retain data.
- Atomic publication prevents ordinary partial-output exposure, but crash
  durability and rename behavior ultimately depend on the destination
  filesystem and platform.
- The tool does not try to defeat a local adversary who can concurrently
  rewrite input/output path components. Keep keys and working directories out
  of locations writable by untrusted users.
- Keep the plaintext input unchanged while encryption is running. Concurrent
  same-length edits can produce an authenticated file containing a mixed-time
  view of the input.

## Development and tests

Run the same core checks used by continuous integration:

```console
cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
cargo test --release --locked --all-targets --all-features
cargo build --release --locked
```

Dependency auditing requires `cargo-audit`:

```console
cargo install cargo-audit --version 0.22.2 --locked
cargo audit --deny warnings
```
