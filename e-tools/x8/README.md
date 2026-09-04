# x8

A standalone password-file encryptor with a payload cipher family not used by any sibling app.

- KDF: scrypt
- Payload algorithm: MORUS-1280-128
- Construction: Native AEAD; 128-bit authentication tag
- Record size: 262144 bytes
- Format ID: 8

Usage: `x8 E|D <input> <output>`.

The format authenticates its header, record metadata, order, and final-record marker. Decryption writes to a temporary file and commits it only after every record authenticates; output never overwrites an existing path. x8 rejects every sibling format.

Security note: This custom file format and its crate integration have not received an independent cryptographic audit.
