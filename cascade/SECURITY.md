# Security notes

## What the program defends

The format provides confidentiality and integrity against offline modification of
ciphertext when the corresponding adjacent key file remains secret. Wrong keys,
truncation, appended data, header changes, ciphertext changes, and tag changes are
rejected before plaintext is committed. Atomic no-overwrite output handling avoids
partial plaintext files on ordinary failures and ordinary target-name races.

Keys are binary machine keys, not passwords. There is no password stretching,
recovery mechanism, network protocol, automatic key rotation, or key escrow.
The outer envelope exposes the selected suite and exact plaintext length; it does
not store a filename. Cascading encrypts an inner envelope as data, so its suite
and contents are hidden while the outer layer remains intact.

## Boundaries

File operations fail closed on non-Unix platforms because private Windows DACL
creation and validation are not implemented. Unix mode and directory checks do not
model every extended ACL scheme.

An attacker running as the same operating-system account can generally read process
memory or replace files in user-writable directories; this program cannot defend
against that compromise. Unix permission checks are not a replacement for full
filesystem ACL or host hardening.

Output directories writable by group or other users are rejected, even when the
sticky bit is set, and both key and output directories must be owned by the
process's effective user. Use an owned private subdirectory instead of writing
directly to a shared `/tmp`.

The key directory and final output directory are each opened and validated once.
All later entry checks, opens, temporary-file operations, no-clobber publication,
rollback, and syncing are relative to that retained descriptor. Replacing the
spelled directory pathname therefore cannot redirect an in-progress operation to
a replacement directory. The implementation does not retain and validate every
ancestor in the path hierarchy. A privileged, same-account, or ancestor-directory
owner can still rename the bound directory itself, causing an availability or
pathname-identity failure: the operation remains bound to the original directory
inode, which may no longer be reachable under the path the caller supplied. Unix
mode checks also do not model every extended ACL or capability scheme.

The in-memory design exposes plaintext to RAM and may expose it to swap or crash
dumps. Atomic rename/link behavior and directory syncing also ultimately depend on
the destination filesystem and operating system.

A process or system crash can leave a partial newly generated key set or a private
`.cascade-key-*` file beside the executable. It can also leave a mode-`0600`
`.cascade-output-*` file in the output directory; during decryption that temporary
file contains plaintext. Normal error handling explicitly attempts to remove every
temporary entry. If that cleanup fails, the CLI reports the temporary name and the
primary failure together; panic unwinding has only best-effort cleanup. Crash
recovery must inspect and remove stale entries explicitly. Never regenerate or
delete an adjacent key merely because a prior `keygen` was interrupted: first
determine whether it protects existing ciphertext and restore from backup when
appropriate.

If directory syncing fails after installation, the CLI explicitly reports that the
output or complete key set is already present but may not be crash-durable. Verify
the installed files before retrying; a blind retry will correctly be refused by the
no-overwrite checks.

On systems or filesystems without atomic rename-no-replace, publication falls back
to an atomic fail-if-present hard link followed by removal of the private temporary
name. A crash between those operations can leave both names. If removal fails after
the final name was installed, the CLI explicitly reports the post-install state and
the temporary name rather than describing it as a failed pre-install commit.

AES-GCM-SIV and XChaCha20-Poly1305 are established authenticated constructions,
although XChaCha's cited specification remains an IETF draft and the RustCrypto
AES-GCM-SIV crate states that the crate as a whole has not had an independent audit
(some underlying primitives have). Serpent and Threefish are low-level block
ciphers and the RustCrypto crates label such use as hazardous; the Serpent
implementation also states that it has not had a dedicated security audit or
thorough constant-time assessment. This project wraps them in conventional CBC +
encrypt-then-HMAC with independent keys, but the complete container and those two
composed suites have not received an independent external cryptographic audit.
Internal review and extensive tests reduce implementation risk; they are not a
substitute for such an audit.

For high-value long-term data, prefer the AES-256-GCM-SIV or XChaCha20-Poly1305
suite unless compatibility or a separately reviewed policy requires Serpent or
Threefish.
