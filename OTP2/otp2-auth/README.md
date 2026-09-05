# otp2-auth

`otp2-auth` is an independent Linux application for detached authentication of
arbitrary regular files. It never encrypts, wraps, rewrites, or replaces the
file being authenticated. Instead, it creates a small sidecar which can travel
with the original file through cloud or other untrusted storage.

This is a separate Cargo package and release from `otp2`. It has no source,
workspace, runtime, or key dependency on the encryption application.

```text
otp2-auth keygen
otp2-auth tag [--replace] [--output <sidecar>] [--] <file>
otp2-auth verify [--tag <sidecar>] [--] <file>
```

By default, tagging `archive.tar` creates `archive.tar.otp2auth`; verification
uses that same default. `--output` and `--tag` allow the sidecar to live under
any regular filename. Use `--` before a file whose name begins with `-`.

The secret `auth.key` is resolved beside the Linux-reported path of the running
`otp2-auth` executable, not in the current working directory. `keygen` creates
32 random raw bytes as a mode-`0600` file and never replaces an existing path.

## Cloud workflow

Keep `auth.key` local and secret. The file and sidecar are safe to upload:

```text
otp2-auth keygen
otp2-auth tag quarterly-backup.tar

# Upload both files. After downloading them again:
otp2-auth verify quarterly-backup.tar
```

Upload the data first and its sidecar last so the sidecar can act as a
readiness marker. A verifier must require both objects and must treat every
nonzero result as failure; never fall back to accepting an unsigned file.

Authentication covers the exact file bytes and unsigned 64-bit byte length. It
does not cover the local filename, path, inode, owner, permissions, timestamps,
ACLs, extended attributes, sparse layout, or cloud-provider metadata. A file
and its sidecar can therefore be renamed or copied together and still verify.
When using an explicit sidecar path after a rename:

```text
otp2-auth verify --tag original-name.otp2auth renamed-file
```

That portability has an important consequence: an attacker can replay or move
an older valid file-and-sidecar pair. This format does not prove freshness,
detect deletion, or bind a pair to a cloud object name. Use immutable/versioned
object IDs plus trusted external state or a signed manifest when rollback or
object-slot substitution must be prevented. Provider ETags are not portable
authentication tags.

## What is accepted

The file contents may be empty, binary, sparse, very large, non-UTF-8, or begin
with any marker. Both operations stream through a zeroizing 64 KiB buffer, so
memory use is bounded independently of file size. Tag creation never opens the
payload writable and needs only the fixed-size temporary sidecar, not a second
copy of the payload.

For safe, nonblocking behavior, terminal file, sidecar, and key paths must be
regular files rather than symbolic links, directories, pipes, sockets, or
devices. Ancestor symbolic links are resolved before their directories are
pinned. Hard-linked payloads are accepted because the payload is read-only;
authentication keys and sidecars selected for replacement must have one link.

`auth.key` must contain exactly 32 raw bytes, be owned by the effective user,
have no group or other permission bits (mode `0600` or stricter), have one hard
link, and not alias the payload or sidecar. It is not a password or hexadecimal
text. Anyone who possesses it can both verify and create valid tags, so HMAC is
not a public signature and cannot prove authorship to another key holder.

## Sidecar version 1

Every sidecar is exactly 64 bytes:

| Offset | Size | Meaning |
| ---: | ---: | --- |
| 0 | 8 | `otp2TAG\0` magic |
| 8 | 2 | version `1`, big-endian |
| 10 | 2 | canonical header length `32` |
| 12 | 4 | flags, currently zero |
| 16 | 8 | exact file length, big-endian |
| 24 | 8 | reserved, all zero |
| 32 | 32 | full HMAC-SHA-256 tag |

The tag is:

```text
HMAC-SHA-256(
  auth.key,
  "otp2-auth/detached/v1\0" || canonical_header || exact_file_bytes
)
```

HMAC follows [RFC 2104](https://www.rfc-editor.org/info/rfc2104/). Initial
publication relies on the Linux
[`RENAME_NOREPLACE`](https://man7.org/linux/man-pages/man2/renameat2.2.html)
contract.

Unknown versions, noncanonical lengths, nonzero flags/reserved fields,
truncation, appended sidecar bytes, a different file length, a wrong key, or a
tag mismatch fail closed. Comparison uses the RustCrypto HMAC implementation's
constant-time verification path.

## Filesystem and failure behavior

Linux-only directory descriptors anchor path operations after resolution.
Terminal paths are inspected without following symlinks and opened with
nonblocking, no-follow flags. Sidecars are streamed to a random, exclusively
created mode-`0600` sibling, synchronized, read back, and then published:

- Initial creation uses Linux `renameat2(RENAME_NOREPLACE)`, so a race cannot
  overwrite an existing destination.
- Existing sidecars are refused unless `--replace` is explicit. Replacement
  accepts only a regular, non-symlink, single-link destination, rechecks its
  identity, and then atomically renames the complete new sidecar over it.
- The containing directory is synchronized after publication.
- Pre-commit failures leave an existing destination and the payload untouched
  and attempt identity-checked temporary cleanup. A crash, forced termination,
  cleanup error, or hostile directory race may leave `.otp2-auth-*.tmp`.

Linux has no general inode-conditional replacement primitive, so another
same-directory writer can race the last existing-sidecar identity check and
replacement. A payload can also change immediately after a successful check.
Keep payload, key, and sidecar directories trusted and exclude concurrent
writers during tagging and verification. Access timestamps may change under
the active mount policy even though file contents and paths are not modified.

`keygen` writes, protects, synchronizes, and validates a random sibling before
publishing it with `RENAME_NOREPLACE`. The final `auth.key` path is therefore
either absent or complete; an existing path is never overwritten. A crash or
outcome-ambiguous filesystem error may leave a private temporary entry, a
complete final key, or uncertain namespace state. Inspect both names before
retrying and never automate deletion based only on an error result.

Exit statuses are:

- `0`: a sidecar was created or verification succeeded.
- `1`: operational failure, including missing files, an unsafe path, or an
  invalid key.
- `2`: invalid command-line usage.
- `3`: the sidecar/key committed without confirmed directory durability, or a
  filesystem error made the commit outcome unknowable. **Do not retry** until
  the destination and any temporary entry have been inspected.
- `4`: the sidecar format or authentication tag did not validate.

## Security and deployment limits

HMAC authenticates what the tagger read. It cannot establish that the bytes
were trustworthy before tagging, provide confidentiality, prevent a valid
pair's deletion or rollback, or safely expose the shared key to untrusted
verifiers. Use a public-key signature system when verification must not grant
forging capability.

The dedicated userspace key and streaming buffers are cleared on drop, but the
program cannot erase copies in kernel caches, swap, crash dumps, backups,
storage history, or every compiler/machine intermediate. Do not run it
set-user-ID, set-group-ID, with Linux capabilities, or otherwise privileged.
`std::env::current_exe` is convenient key discovery, not a trust root; keep the
executable and its directory controlled by the same trusted administrator.

Before production use, qualify the exact kernel, local filesystem, mount
options, storage stack, crash behavior, and operational handling of exits `3`
and `4`. Network, FUSE, overlay, removable, and fault-injecting filesystems are
unsupported until tested in their exact deployment. The project is extensively
tested but does not claim a third-party security certification or formal
cryptographic audit.

## Development

```text
cargo fmt --all -- --check
cargo test --locked --all-targets --no-fail-fast
cargo clippy --locked --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps
cargo build --locked --release --bins
```

The package is Linux-only, declares Rust 1.98.1 as its minimum, and pins Rust
1.98.1 for development and Ubuntu 24.04 CI. Dependencies are locked; CI checks
formatting, tests, Clippy warnings, documentation, and release builds.
