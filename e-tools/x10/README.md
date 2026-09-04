# x10

A standalone password-file encryptor with a payload cipher family not used by any sibling app.

- KDF: PBKDF2-SHA256
- Payload algorithm: Xoodyak
- Construction: Native duplex AEAD
- Record size: 32768 bytes
- Format ID: 10

Usage: `x10 E|D <input> <output>`.

The format authenticates its header, record metadata, order, and final-record marker. Decryption writes to a temporary file and commits it only after every record authenticates; output never overwrites an existing path. x10 rejects every sibling format.

Security note: This custom file format and its crate integration have not received an independent cryptographic audit.
