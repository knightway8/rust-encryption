# x1

A standalone password-file encryptor with a payload cipher family not used by any sibling app.

- KDF: Argon2id
- Payload algorithm: AES-256-GCM
- Construction: Native AEAD; 128-bit authentication tag
- Record size: 65536 bytes
- Format ID: 1

Usage: `x1 E|D <input> <output>`.

The format authenticates its header, record metadata, order, and final-record marker. Decryption writes to a temporary file and commits it only after every record authenticates; output never overwrites an existing path. x1 rejects every sibling format.

Security note: This custom file format and its crate integration have not received an independent cryptographic audit.
