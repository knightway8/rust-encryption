# x7

A standalone password-file encryptor with a payload cipher family not used by any sibling app.

- KDF: Argon2id
- Payload algorithm: ISAP-Keccak-128A
- Construction: Native lightweight AEAD
- Record size: 131072 bytes
- Format ID: 7

Usage: `x7 E|D <input> <output>`.

The format authenticates its header, record metadata, order, and final-record marker. Decryption writes to a temporary file and commits it only after every record authenticates; output never overwrites an existing path. x7 rejects every sibling format.

Security note: This custom file format and its crate integration have not received an independent cryptographic audit.
