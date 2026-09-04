# x23

A standalone password-file encryptor with its own format and payload cipher family.

- KDF: PBKDF2-SHA384
- Payload algorithm: BLAKE3-AEAD
- Record protection: BLAKE3-AEAD native authenticated encryption
- Authentication tag: 16 bytes
- Key material: 32 bytes
- Nonce: 24 bytes
- Record size: 1048576 bytes
- Format ID: 23

Usage: `x23 E|D <input> <output>`.

The header, record metadata, record order, and final-record marker are authenticated. Output is staged in the destination directory and committed without overwriting an existing file. x23 deliberately rejects every sibling format.

Security note: The crate describes this design as experimental and hazmat. This custom file format has not received an independent cryptographic audit.