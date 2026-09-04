# x24

A standalone password-file encryptor with its own format and payload cipher family.

- KDF: PBKDF2-SHA512
- Payload algorithm: Kalyna-256/256-GCM
- Record protection: Kalyna-256/256-GCM native authenticated encryption
- Authentication tag: 32 bytes
- Key material: 32 bytes
- Nonce: 32 bytes
- Record size: 32768 bytes
- Format ID: 24

Usage: `x24 E|D <input> <output>`.

The header, record metadata, record order, and final-record marker are authenticated. Output is staged in the destination directory and committed without overwriting an existing file. x24 deliberately rejects every sibling format.

Security note: The crate is pre-1.0, provisional, and not independently audited. This custom file format has not received an independent cryptographic audit.