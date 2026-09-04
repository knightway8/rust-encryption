# x5

A standalone password-file encryptor with a payload cipher family not used by any sibling app.

- KDF: PBKDF2-SHA384
- Payload algorithm: XSalsa20-Poly1305
- Construction: NaCl secretbox; canonical record metadata is sealed and checked inside the authenticated plaintext
- Record size: 32768 bytes
- Format ID: 5

Usage: `x5 E|D <input> <output>`.

The format authenticates its header, record metadata, order, and final-record marker. Decryption writes to a temporary file and commits it only after every record authenticates; output never overwrites an existing path. x5 rejects every sibling format.

Security note: This custom file format and its crate integration have not received an independent cryptographic audit.
