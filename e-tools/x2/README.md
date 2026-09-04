# x2

A standalone password-file encryptor with a payload cipher family not used by any sibling app.

- KDF: scrypt
- Payload algorithm: ChaCha20-Poly1305
- Construction: Native AEAD; Poly1305 authentication
- Record size: 131072 bytes
- Format ID: 2

Usage: `x2 E|D <input> <output>`.

The format authenticates its header, record metadata, order, and final-record marker. Decryption writes to a temporary file and commits it only after every record authenticates; output never overwrites an existing path. x2 rejects every sibling format.

Security note: This custom file format and its crate integration have not received an independent cryptographic audit.
