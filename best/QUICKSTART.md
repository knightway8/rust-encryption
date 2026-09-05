# best quick start

The complete Rust project is in this repository's `best/` directory.
Open PowerShell there and run `build.bat` to build the release executable at
`dist\best.exe`; `best.bat` launches it. Rust 1.98.1 and the Windows MSVC build
tools are required. Compiled executables are not checked into the repository.

Open PowerShell in that folder:

```powershell
.\best.bat encrypt "C:\path\file.txt"
.\best.bat decrypt "C:\path\file.txt.age" -o "C:\path\restored.txt"
.\best.bat verify "C:\path\file.txt.age"
```

Enter a long password at the hidden prompt. Encryption asks for confirmation.
The app keeps your originals and refuses to overwrite existing files.

Public-key mode:

```powershell
$recipient = .\best.bat keygen -o personal.key
.\best.bat encrypt "C:\path\file.txt" -r $recipient
.\best.bat decrypt "C:\path\file.txt.age" -i personal.key -o "C:\path\restored.txt"
```

Back up `personal.key` securely; it is an unencrypted private identity. Only the
printed public recipient is safe to share. Lost passwords/private keys cannot be
recovered.

Run `build.bat` to rebuild and `test.bat` for formatting, strict Clippy, and tests.
`xxxx11.bat` offers a developer menu. The old destructive source-reset helper has
been disabled and archived as text in `legacy/`.

Rust is pinned to 1.98.1. The app supports binary age files, password encryption,
multiple X25519 recipients, streaming, full-file verification, and restrictive file
permissions. Password derivation uses approximately 256 MiB. `--password-file`
supports automation; `--max-bytes` bounds plaintext size.

This directory includes the full source, lockfile, tests, documentation,
license notices, and validation logs. Read README.md and SECURITY.md before
production deployment. This implementation has extensive automated validation but
has not received an independent security audit.
