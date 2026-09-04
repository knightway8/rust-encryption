# asmcrypt

`asmcrypt` is a small x86-64 Linux file-encryption application written in
NASM assembly. The assembly implements the command-line interface, streaming
file I/O, authenticated file format, error handling, and cleanup. It calls
libsodium for the cryptographic operations rather than implementing a custom
cipher.

It uses:

- Argon2id password-based key derivation (3 passes, 256 MiB)
- XChaCha20-Poly1305 authenticated secret-stream encryption
- Random salts and stream headers
- 64 KiB streaming records, so whole files are not loaded into memory
- Hidden password entry and confirmation during encryption
- Anonymous `O_TMPFILE` output created with mode `0600`
- Atomic publication only after encryption/decryption fully succeeds
- Core dumps disabled and the main password/key/state buffers locked in RAM
- Authentication of both content and format metadata

## Build

On the Fedora 44 machine this was created for, NASM, GCC, and the required
libsodium runtime are already installed:

```bash
make
```

If building on another Fedora installation:

```bash
sudo dnf install nasm gcc libsodium libsodium-devel
```

The Makefile prefers `pkg-config`/`-lsodium` when the development package is
installed. On this machine it can also discover and link Fedora's versioned
runtime library automatically.

### Build manually using only `asmcrypt.asm`

The Makefile is convenient, but it is not required. The assembly file is the
only project source file needed. NASM, GCC, libc, and libsodium must still be
installed on the system.

First, use NASM to assemble the source into an object file:

```bash
nasm -f elf64 -g -F dwarf asmcrypt.asm -o asmcrypt.o
```

Then link that object file with libsodium to create the executable. On the
Fedora 44 machine this project was created for, the following command works
with the installed runtime library:

```bash
gcc -pie -Wl,-z,relro,-z,now,-z,noexecstack \
    -o asmcrypt asmcrypt.o /lib64/libsodium.so.26
```

If `libsodium-devel` is installed, the portable link command is:

```bash
gcc -pie -Wl,-z,relro,-z,now,-z,noexecstack \
    -o asmcrypt asmcrypt.o -lsodium
```

Test the resulting executable:

```bash
./asmcrypt
```

The intermediate object file is no longer required after linking and may be
removed:

```bash
rm asmcrypt.o
```

## Platform compatibility

The current assembly source targets the x86-64 System V ABI and Linux. It is
not a single binary that can be copied unchanged to every operating system or
CPU architecture.

### Other x86-64 Linux distributions

The source should compile with little or no code change on most modern x86-64
Linux distributions. Package names may differ, but NASM, GCC, libc, libsodium,
and `pkg-config` are the main requirements. With the libsodium development
package installed, use the portable `-lsodium` manual link command shown above.

Recompile the source on the destination distribution instead of copying the
Fedora executable. A binary built here records dependencies on Fedora's libc
and libsodium shared-library versions.

The safe publication code uses Linux `O_TMPFILE`, `/proc/self/fd`, `openat`,
and `linkat`. The destination filesystem must support `O_TMPFILE`; common
modern Linux filesystems such as Btrfs, ext4, and XFS do. See the Linux
[`open(2)` documentation](https://man7.org/linux/man-pages/man2/open.2.html).

### Windows Subsystem for Linux

The Linux build should work inside WSL when its dependencies are installed.
Prefer files stored in WSL's Linux filesystem. A Windows-mounted filesystem
such as `/mnt/c` may not support the `O_TMPFILE` operation this program uses.

### ARM Linux

This source is x86-64 assembly and will not compile for ARM or AArch64 CPUs.
An ARM Linux version would require rewriting the assembly instructions and
function-call ABI while preserving the same file format and cryptographic
operations.

### Native Windows

A native Windows build requires a separate source port rather than a different
NASM command alone. The port would need:

- NASM's [`win64` object format](https://www.nasm.us/doc/nasm09.html) instead
  of Linux ELF objects.
- The [Microsoft x64 calling convention](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention),
  including its register assignments and stack shadow space.
- Windows replacements for `prctl`, `O_TMPFILE`, `/proc/self/fd`, `openat`,
  `linkat`, terminal password entry, and other Linux-specific operations.
- A Windows libsodium library. Libsodium provides
  [prebuilt Windows libraries and build instructions](https://doc.libsodium.org/installation).

A correctly implemented Windows or ARM port can retain the exact version-1
encrypted-file format. That would allow files encrypted on Linux to be
decrypted by the port, and vice versa.

## Use

Encrypt a regular file:

```bash
./asmcrypt encrypt photo.jpg photo.jpg.enc
```

Decrypt it:

```bash
./asmcrypt decrypt photo.jpg.enc restored-photo.jpg
```

The passphrase is read privately from the terminal, never from a command-line
argument. Encryption asks for it twice. The program never deletes the input
and refuses to overwrite an existing output file. It writes to an anonymous
same-directory `O_TMPFILE` inode and atomically gives it the requested output
name only after authentication and syncing succeed. If decryption fails—or
the process is killed—the unpublished file disappears when its descriptor is
closed, so no partial result or orphan temporary pathname is exposed.

This publication mechanism is Linux-specific and requires a filesystem with
`O_TMPFILE` support (Fedora's usual Btrfs, ext4, and XFS filesystems support it)
plus a mounted `/proc` filesystem.

If the program reports that an output was published but a later directory
sync or close failed, the complete final output may already exist. Verify it
before deciding whether to remove or retry it.

## File format (version 1)

The 72-byte header contains the magic/version identifiers, fixed chunk and KDF
parameters, a random 16-byte salt, and libsodium's 24-byte secret-stream
header. The entire header is authenticated as associated data for every
record. All non-final records encrypt exactly 64 KiB; the final authenticated
record is between 17 and 65,553 bytes.

## Important

This is an educational application using well-established cryptographic
primitives, but the assembly application itself has not received an external
security audit. Keep backups and verify successful decryption before relying
on it for irreplaceable data.
