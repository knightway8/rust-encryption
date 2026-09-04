# x9

A standalone password-file encryptor with a payload cipher family not used by any sibling app.

- KDF: PBKDF2-SHA224
- Payload algorithm: Gimli-AEAD
- Construction: Native AEAD; decryption occurs in a temporary buffer and is committed only after tag validation
- Record size: 1048576 bytes
- Format ID: 9

Usage: `x9 E|D <input> <output>`.

The format authenticates its header, record metadata, order, and final-record marker. Decryption writes to a temporary file and commits it only after every record authenticates; output never overwrites an existing path. x9 rejects every sibling format.

Security note: This custom file format and its crate integration have not received an independent cryptographic audit.
