# otp2

`otp2` is a deliberately narrow Linux application: it atomically XORs a
regular file with the corresponding bytes from `key.key`. XOR is its own
inverse, so the same command decrypts a file previously encrypted with the same
key bytes.

```text
otp2 [--] <input-file>
```

`key.key` is loaded from the directory Linux reports as containing the running
`otp2` executable, not from the current working directory. It may be longer
than the input but must not be shorter.

This package performs encryption/decryption only. Authentication, detached
sidecars, cloud-storage workflows, and authentication-key management belong to
the independent `otp2-auth` application and are not dependencies or optional
features of this package.

## Platform and key requirements

`otp2` supports Linux only. Windows, macOS, BSD, and other targets fail at
compile time. The checked-in toolchain and CI use Rust 1.98.1 and Ubuntu 24.04;
production deployments must also qualify their exact kernel, filesystem, mount
options, and storage stack.

`key.key` is a raw byte stream, not hexadecimal text or a password. It must:

- be a regular file rather than a symbolic link, pipe, socket, directory, or
  device;
- be owned by the effective user running `otp2`;
- have no group or other permission bits (mode `0600` or stricter);
- have exactly one hard link; and
- contain at least as many bytes as the input.

Never reuse any `key.key` byte for a different message. This construction is a
true one-time pad only when every used key byte was generated independently and
uniformly at random, remains secret, and is used once.

## Reliability behavior

- Input and key bytes are streamed through two zeroizing 64 KiB buffers. Memory
  use does not grow with file size, but the operation needs temporary disk
  space for one complete transformed copy.
- Key length and file safety checks happen before input content is read or a
  temporary output is created.
- The result is written to a newly and exclusively created mode-`0600` sibling
  file. The input's Linux mode bits are then applied, and the staged data is
  synchronized before atomic replacement.
- A rename syscall is attempted only once, even if it reports interruption.
  After a rename error, `otp2` inspects the staged and destination identities
  through the pinned directory descriptor. If the staged inode is proven to be
  at the destination, the operation is treated as committed; if it is proven
  to remain only at its source name, the operation is treated as not committed.
  Any other namespace result has an uncertain commit outcome.
- The containing directory is synchronized after a proven replacement. Exit
  status `3` means either that replacement happened but a syscall result or
  directory crash durability was uncertain, or that the namespace could not
  prove whether replacement happened. **Do not retry automatically:** inspect
  the input and any `.otp2-*.tmp` entries first, because another XOR could
  reverse a completed operation.
- Failures proven to occur before commit use exit status `1` and attempt to
  remove only the known temporary inode. Cleanup syscalls are not retried after
  an outcome-ambiguous error, so a same-name substitute is not deleted by a
  retry. A crash, forced termination, cleanup failure, uncertain commit, or
  hostile directory race can leave a stale `.otp2-*.tmp` file.
- Symbolic-link or multiply-hard-linked inputs and keys, non-regular files, and
  an input which aliases its key are rejected.

The input and key directories must be trusted against concurrent changes.
Directory descriptors pin both resolved directories, so renaming an ancestor
or retargeting an ancestor symlink cannot redirect an operation after the
directories have been opened. Open handles and terminal path identities are
rechecked immediately before replacement.

Linux has no general inode-conditional replacement operation. Another writer
in the same pinned directory can therefore race the final identity check and
`renameat`. Do not run `otp2` while another process may write, rename,
hard-link, or rotate the input, key, or temporary output.

`std::env::current_exe` locates the key. Its reported path can vary when the
executable was launched through a symbolic link or renamed while running; it is
not a security trust root. Do not run `otp2` set-user-ID, set-group-ID, with
Linux capabilities, or with other elevated privileges unless the executable
path and containing directory are controlled by the same trusted
administrator.

Atomic replacement preserves Linux mode bits but changes the inode and may
change ownership or timestamps. ACLs, extended attributes, sparse layout,
inode flags, capabilities, and security labels are not preserved. Atomicity
and power-loss behavior depend on the filesystem, especially for network,
userspace, overlay, and removable filesystems. This is not secure erasure: old
blocks, snapshots, backups, open descriptors, or device history may retain
plaintext.

## Cryptographic limits

Raw XOR provides confidentiality only under the strict one-time-pad conditions
above. It provides no authentication or integrity: damage, truncation, a wrong
key, or malicious bit flips cannot be detected by this format. Use a separate
authentication application when integrity or origin must be checked, and never
silently treat a missing authentication artifact as success.

The dedicated userspace streaming buffers are cleared on drop, but the program
cannot remove copies from kernel caches, swap, crash dumps, backups, storage
history, or every compiler and machine intermediate.

## Production checklist

- Build with `cargo build --locked --release --bins` using the pinned toolchain,
  and retain the exact binary, `Cargo.lock`, and key-range records needed for
  recovery.
- Run as an unprivileged dedicated account. Keep the executable/key directory
  and all input directories controlled by trusted users throughout each
  operation.
- Use a qualified local filesystem with same-directory atomic rename and
  meaningful file and directory `fsync`. Treat other filesystems as unsupported
  until tested in the exact deployment configuration.
- Exclude concurrent writers, ensure enough free space for a complete staged
  copy, and handle exit status `3` as committed-or-outcome-uncertain rather than
  as permission to retry. Inspect the input and temporary entries before any
  recovery action.
- Generate uniformly random pad bytes, allocate nonoverlapping ranges outside
  this application, and keep tested backups and a recovery runbook.

The implementation is extensively tested but has not received a claimed
third-party security certification or formal cryptographic audit.

## Development

Run the same checks as CI:

```text
cargo fmt --all -- --check
cargo test --locked --all-targets --no-fail-fast
cargo clippy --locked --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps
cargo build --locked --release --bins
```

The project requires and pins Rust 1.98.1. CI runs on
Linux, the checkout action is pinned to an immutable commit, and Cargo plus
GitHub Actions dependencies are tracked by Dependabot.
