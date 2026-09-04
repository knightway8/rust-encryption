# x13

A standalone password-file encryptor with a payload cipher family not used by any sibling app.

- KDF: Argon2id
- Payload algorithm: SNOW-V-GCM
- Construction: Native AEAD using SNOW-V with GCM authentication
- Record size: 1048576 bytes
- Format ID: 13

Usage: `x13 E|D <input> <output>`.

The format authenticates its header, record metadata, order, and final-record marker. Decryption writes to a temporary file and commits it only after every record authenticates; output never overwrites an existing path. x13 rejects every sibling format.

Security note: This custom file format and its crate integration have not received an independent cryptographic audit.
