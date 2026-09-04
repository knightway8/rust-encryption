# x6

A standalone password-file encryptor with a payload cipher family not used by any sibling app.

- KDF: PBKDF2-SHA512
- Payload algorithm: Deoxys-II-256
- Construction: Native nonce-misuse-resistant AEAD
- Record size: 65536 bytes
- Format ID: 6

Usage: `x6 E|D <input> <output>`.

The format authenticates its header, record metadata, order, and final-record marker. Decryption writes to a temporary file and commits it only after every record authenticates; output never overwrites an existing path. x6 rejects every sibling format.

Security note: This custom file format and its crate integration have not received an independent cryptographic audit.
