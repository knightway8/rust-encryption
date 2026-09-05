# Security model

## Scope

best protects file contents at rest against someone who obtains ciphertext but
does not know a strong password or possess an authorized private identity. It
detects changes to authenticated data, incorrect credentials, truncated streams,
and extra ciphertext. It does not authenticate who sent a file: anyone with a
public recipient can encrypt to it. Verify a recipient through a trusted channel.

The protocol is binary age v1, implemented by age 0.12.1. best adds constrained
CLI policy and filesystem transactions. No encryption primitive, random generator,
key wrapping protocol, or nonce scheme was invented for this project. X25519 has
classical security; this application does not offer post-quantum protection.

## Trust boundaries

The executable, OS, dependency supply chain, terminal, secret storage, and output
directory must be trusted. In particular, use a directory controlled by your own
account. A malicious user with control of the parent directory, administrator
rights, the same account, debugger access, or arbitrary code execution is outside
this boundary. Parent path components may resolve through links. Filesystems must
honor exclusive creation, no-replace publication, and permission semantics; local
NTFS and ordinary local Unix filesystems are the intended environments. Avoid FAT,
untrusted network shares, and cloud-synchronized folders for temporary plaintext
and keys. Windows protected ACL guarantees require an ACL-capable filesystem.

Plaintext must not be concurrently edited. Windows write/delete sharing is denied
on open inputs. Unix length/mtime checks catch ordinary changes but cannot provide
a coherent snapshot against a malicious concurrent writer. Snapshot or stop the
writer first. Permissions, sparse layout, timestamps, ACLs, alternate streams, and
extended attributes are not serialized: only the regular file's main byte stream.
Directories should be archived by an external tool first. Names and approximate
sizes remain visible. No compression, padding, or metadata confidentiality is
promised.

## Publication, failures, and interruption

No existing destination is overwritten, even if it appears during encryption.
Encryption and decryption use a random `.best-tmp-*` file in the destination
directory, so publication does not cross filesystems. The file contains only
ciphertext during encryption and can contain authenticated plaintext chunks during
decryption. The final destination appears only after complete verification.

Ordinary failures and observed Ctrl+C/SIGTERM cancellation remove the temporary
file through RAII. Cancellation is checked between transfer chunks and before
publication; a password KDF or a blocking filesystem call cannot be interrupted
until it returns. A signal arriving during the final publication can coincide
with a successful completed output. Verify reports no destination on cancellation;
key generation is a short transaction.

A process kill, power failure, abort, filesystem error, or failed cleanup can leave
a restricted temporary file behind. Decrypted content can exist in the filesystem,
page cache, swap, backups, crash dumps, or SSD history. There is no secure deletion
guarantee and deletion is not cryptographic erasure. Full-disk encryption is useful
for the OS and working directory. The implementation does not lock memory pages
or claim to erase all copies maintained by dependencies or the OS.

File contents are synced before publishing. Unix parent-directory sync errors are
reported after publication, explicitly noting that the complete destination may
already exist. Windows and network-filesystem crash durability ultimately depend
on the filesystem and storage device. `tempfile::persist_noclobber` does not promise
atomicity on every platform; it never replaces an existing path but on some Unix
fallbacks it can leave an additional temporary hard link to the same complete file.

## Resource limits and error handling

The input header is limited to 64 KiB before parsing. Password cost defaults to
`log2(N) <= 18`; the hard CLI/library ceiling is 20. That ceiling is approximately
1 GiB per operation, so do not increase it for untrusted data. Individual secret
files and key counts are bounded. Use `--max-bytes` and external process quotas
when handling untrusted files repeatedly. This is a local file tool, not a network
decryption oracle or a multi-tenant service.

The age 0.12.1 excessive-work Display implementation can overflow while formatting
certain required/target pairs. best formats its own bounded decryption messages
and tests all 65,536 pairs. Error messages never intentionally include passwords,
private-key lines, or plaintext. File-path success diagnostics use escaped debug
formatting to prevent control characters from being printed literally.

## Deployment and review

Rust and package versions are pinned by `rust-toolchain.toml` and `Cargo.lock`.
Run formatting, strict Clippy, both test profiles, RustSec audit, and independent
age interoperability checks before distributing a release. CI configurations are
provided, but a local pass is not evidence of a completed remote CI run. Keep
originals and recovery material until you have verified an independent restoration.
There is no password or private-key recovery mechanism.

No independent security audit, penetration test, FIPS validation, signing identity,
or warranty is claimed. Upstream age Rust crate documentation labels pre-1.0
versions beta. Obtain independent cryptographic and platform review for production
deployments with high-value data. When reporting an issue, provide a minimal
synthetic reproducer and platform/version details; never include real secrets.
