# x20

A standalone password-file encryptor with its own format and payload cipher family.

- KDF: scrypt
- Payload algorithm: Romulus-M
- Record protection: Romulus-M native authenticated encryption
- Authentication tag: 16 bytes
- Key material: 16 bytes
- Nonce: 16 bytes
- Record size: 65536 bytes
- Format ID: 20

Usage: `x20 E|D <input> <output>`.

The header, record metadata, record order, and final-record marker are authenticated. Output is staged in the destination directory and committed without overwriting an existing file. x20 deliberately rejects every sibling format.

Security note: Romulus-M is a NIST LWC finalist design; this pre-1.0 crate is not positioned as production-ready. This custom file format has not received an independent cryptographic audit.