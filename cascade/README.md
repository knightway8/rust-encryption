# cascade

`cascade` encrypts or decrypts exactly one file per invocation. It supports manual
cascades: encrypt the output again with another suite, then decrypt the layers in
reverse order.

## Build and use

```text
cargo build --release
./target/release/cascade keygen

./target/release/cascade A E input.bin output.a
./target/release/cascade X E output.a output.ax
./target/release/cascade X D output.ax recovered.a
./target/release/cascade A D recovered.a recovered.bin
```

The grammar is deliberately small and case-sensitive:

```text
cascade keygen
cascade <A|S|X|T> <E|D> <INPUT> <OUTPUT>
```

`A`, `S`, `X`, and `T` are uppercase-only algorithm selectors. `E` and `D` are
uppercase-only operations. There is no automatic cascade mode and no overwrite
flag.

Secure file operations are supported on Unix platforms. The Windows build fails
closed for `keygen`, encryption, and decryption because this version does not
implement or validate a private Windows DACL.

`keygen` creates all four raw binary keys in the directory containing the actual
executable, not the current working directory:

| Selector | Suite | Key file | Bytes |
|---|---|---|---:|
| `A` | AES-256-GCM-SIV | `aes.key` | 32 |
| `S` | Serpent-256-CBC + HMAC-SHA-512 | `ser.key` | 32 |
| `X` | XChaCha20-Poly1305 | `cha.key` | 32 |
| `T` | Threefish-1024-CBC + HMAC-SHA-512 | `thr.key` | 128 |

Back up these files securely before encrypting important data. Losing or replacing
a key makes its ciphertext unrecoverable. `keygen` refuses to change anything if
any target key already exists at its initial preflight check. On pre-install or
publication failures where installation state is unambiguous, it attempts to roll
back keys installed by that invocation. A reported post-install cleanup or sync
failure deliberately preserves the installed entries for inspection. Key creation
is not crash-atomic: a killed process or system failure can leave a partial new
set. In any of these cases, inspect the four exact key names and any private
`.cascade-key-*` temporary files before deciding what to preserve or remove; do not
regenerate over keys that may protect existing data.

On Unix, generated key and output files use mode `0600`; existing keys with
group/other permissions or a different owner are rejected. The executable/key
directory itself must be owned by the process's effective user and must not be
writable by group or other users.

## Cryptographic construction

Every file gets a fresh 32-byte random salt and suite-specific random nonce/IV.
HKDF-SHA-512 derives per-file, domain-separated keys from the relevant root key.
The exact serialized v1 header is authenticated.

- AES uses AES-256-GCM-SIV with a 12-byte nonce and detached 16-byte tag.
- XChaCha uses XChaCha20-Poly1305 with a 24-byte nonce and detached 16-byte tag.
- Serpent uses a derived 256-bit key in CBC mode with PKCS#7 padding, followed by
  encrypt-then-HMAC-SHA-512 under a separate derived 512-bit MAC key.
- Threefish uses a derived 1024-bit key in CBC mode with PKCS#7 padding, followed
  by encrypt-then-HMAC-SHA-512 under a separate derived 512-bit MAC key. The
  RustCrypto cipher-trait constructor uses Threefish's fixed all-zero tweak.

For Serpent and Threefish, the HMAC covers a suite-specific domain label, the
complete header, and all ciphertext. Decryption verifies it in constant time before
CBC decryption or padding removal, preventing padding-oracle and malleability bugs.

The envelope is:

```text
32-byte fixed header || 32-byte salt || nonce/IV || ciphertext || tag
```

It records magic, version, suite, canonical header/nonce lengths, and authenticated
plaintext length. A cascade treats the complete inner envelope as ordinary input
bytes, so no special cascade metadata is needed.

## File safety and limits

- Inputs must be regular files; symbolic links and special files are rejected.
- Existing outputs are never overwritten, including links.
- Output is written to a private temporary file in the destination directory,
  synced, then atomically installed with no-clobber semantics.
- The destination directory is opened once and all checks, temporary-file work,
  publication, cleanup, and syncing use that retained descriptor. Replacing its
  pathname cannot redirect an in-progress operation to a replacement directory.
- On Unix, the destination directory must be owned by the process's effective
  user. Any destination directory writable by group or other users is rejected,
  including a sticky `1777` directory. Use an owned private subdirectory instead
  of writing directly to a shared `/tmp`.
- Authentication completes before decrypted output is created.
- This build intentionally processes a whole file in memory and caps each input at
  1 GiB. It is not a streaming format. Encryption also requires the complete output
  envelope to remain within that cap, ensuring every successful output can be read
  by a later decrypt or cascade invocation. Peak memory is multiple times the file
  size (input, cryptographic work/output, and final envelope); the 1 GiB limit is a
  format guard, not a promise that a particular machine has enough RAM.
- Root keys, derived keys, input buffers, and decrypted buffers are zeroized on
  drop where the Rust type system and dependencies permit it. This does not erase
  filesystem caches, swap, prior input files, or compiler-created copies.
- A process or system crash, or an explicitly reported cleanup failure, can leave
  a mode-`0600` `.cascade-output-*` temporary entry in the bound output directory.
  During decryption it contains plaintext. Inspect and remove stale temporary
  files using the same care as the intended output.

See [SECURITY.md](SECURITY.md) for the threat model and audit caveats.
