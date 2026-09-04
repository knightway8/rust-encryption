# ezcrypt

`ezcrypt` is a Windows 11 command-line tool for authenticated, crash-safe file encryption. It accepts exactly one file path and decides what to do from the final suffix:

- `report.pdf` becomes `report.pdf.ez`.
- `report.pdf.ez` becomes `report.pdf`.
- `.ez` matching is ASCII case-insensitive on Windows, so `.EZ` and `.eZ` decrypt too.

The password is read from the console with echo disabled. Encryption asks for confirmation; decryption asks once. Passwords are deliberately not accepted as command-line arguments, where they could appear in process listings and shell history.

There is no password recovery. Test a decryptable backup before relying on the tool for irreplaceable data.

## Build and use

```powershell
cargo build --release
target\release\ezcrypt.exe "C:\path\to\report.pdf"
```

The program refuses to overwrite an existing destination. A leading-dash filename can be passed after `--`:

```powershell
target\release\ezcrypt.exe -- "-notes.txt"
```

## Cryptography and file format

- XChaCha20-Poly1305 authenticated encryption.
- Argon2id v1.3 password derivation with a fresh 128-bit salt, 64 MiB of memory, three passes, and one lane by default.
- A fresh 128-bit random XChaCha nonce prefix for every encryption.
- A fixed, explicitly encoded version-1 header.
- Independent 1 MiB authenticated chunks for bounded memory use.
- Separate header and end authenticators, so header edits, wrong passwords, reordered or missing chunks, truncation, and trailing bytes are detected.
- Passwords, derived keys, plaintext scratch buffers, and Argon2 working memory are zeroized when dropped.

The header is not secret and reveals the original byte length and KDF parameters. The filename and file metadata are also visible to the filesystem.

## Data-integrity model

The supported reliability boundary is a local, fixed, real drive-letter NTFS volume on Windows 11. The program deliberately rejects UNC/device and SUBST-style paths, removable or mapped drives, reserved device names, ambiguous trailing-dot/space names, other filesystems, Windows reparse points, non-regular files, alternate data streams, multiple hard links, and storage modes it cannot faithfully preserve (EFS, compressed, sparse, integrity/no-scrub, offline, or recall-on-access files).

For every operation, ezcrypt:

1. Opens and retains exclusive source access plus no-delete handles for every directory component from the volume root through the source's parent; every reparse component is rejected.
2. Creates a cryptographically random sibling temporary file with `CREATE_NEW`, write-through semantics, and POSIX delete-pending state. The pending state blocks raced hard links and alternate streams and normally deletes the temp if the process exits.
3. Copies the source DACL, including its protected/inherited state, and flushes it before writing any transformed bytes.
4. Streams the complete transform into the temp. Decryption authenticates every chunk before writing it, and no unauthenticated plaintext is published as the final destination.
5. Flushes the temp, reads every byte back, and compares a BLAKE3 digest. Encryption additionally decrypts and authenticates the complete temp again and compares its plaintext digest with the source.
6. Copies supported timestamps and Windows attributes, flushes again, then rereads and hashes the source to confirm its content and identity did not change.
7. Clears the temp's pending deletion, rechecks its links, streams, and storage attributes, then publishes through the live handle with `FileRenameInfo` and `ReplaceIfExists = false`.
8. Flushes the published handle and keeps it exclusively open while putting the source into POSIX delete-pending state. It rechecks source identity, metadata, hard links, and alternate streams before explicitly closing the source handle.

The source DACL and common timestamps/DOS attributes are preserved. Owner, SACL, and NTFS extended attributes are not copied; do not use the tool where those metadata are required unchanged.

Creating `name.ez` and removing `name` are two different directory-entry changes; Windows does not provide a non-deprecated transaction that makes both one atomic event. Therefore the safe crash states are:

- Before publication: the original remains, possibly with an unadvertised random temporary file after sudden power loss. Its DACL is copied before data is written, but a decrypt temp could contain partial plaintext.
- Between publication and deletion: both complete files may remain.
- After deletion: only the complete destination remains.

The implementation prioritizes never losing the original before a complete, authenticated, flushed, read-back-verified output exists. A pre-publication error leaves the source intact. A post-publication cleanup error reports whether the source was definitely retained or whether removal could not be confirmed, and tells the user to inspect before retrying. As with any storage software, a device that ignores flush/write-through requests can weaken power-loss guarantees.

This is not secure erasure. Filesystem journals, SSD remapping, backups, shadow copies, and previously existing copies can retain plaintext after its directory entry is deleted.

## Tests

```powershell
cargo test
cargo clippy --all-targets --all-features -- -D warnings
```

The suite contains named tests covering path routing, CLI and secret handling, format validation and arithmetic, cryptographic boundary sizes, corruption and truncation, read/write failures, destination collisions, and real Windows filesystem behavior.

## Format stability

Version 1 files are self-describing and include their bounded Argon2id parameters. Unknown versions, flags, chunk sizes, unsafe KDF costs, or nonzero reserved bytes are rejected. Renaming an encrypted file does not invalidate it because filenames are intentionally not included in authenticated data.

The Windows commit strategy follows Microsoft's documented [`SetFileInformationByHandle`](https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-setfileinformationbyhandle), [`FILE_RENAME_INFO`](https://learn.microsoft.com/windows/win32/api/winbase/ns-winbase-file_rename_info), and [`FlushFileBuffers`](https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers) semantics. Transactional NTFS is not used because Microsoft has deprecated it.
