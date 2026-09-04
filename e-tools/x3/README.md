# x3

A standalone password-file encryptor with a payload cipher family not used by any sibling app.

- KDF: PBKDF2-SHA224
- Payload algorithm: Ascon-AEAD128
- Construction: Native lightweight AEAD
- Record size: 262144 bytes
- Format ID: 3

Usage: `x3 E|D <input> <output>`.

The format authenticates its header, record metadata, order, and final-record marker. Decryption writes to a temporary file and commits it only after every record authenticates; output never overwrites an existing path. x3 rejects every sibling format.

Security note: This custom file format and its crate integration have not received an independent cryptographic audit.
