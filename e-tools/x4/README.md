# x4

A standalone password-file encryptor with a payload cipher family not used by any sibling app.

- KDF: PBKDF2-SHA256
- Payload algorithm: AEGIS-256
- Construction: Native AEAD; 128-bit authentication tag
- Record size: 1048576 bytes
- Format ID: 4

Usage: `x4 E|D <input> <output>`.

The format authenticates its header, record metadata, order, and final-record marker. Decryption writes to a temporary file and commits it only after every record authenticates; output never overwrites an existing path. x4 rejects every sibling format.

Security note: This custom file format and its crate integration have not received an independent cryptographic audit.
