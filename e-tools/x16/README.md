# x16

A standalone password-file encryptor with a payload cipher family not used by any sibling app.

- KDF: PBKDF2-SHA256
- Payload algorithm: HC-128
- Construction: Encrypt-then-MAC with keyed BLAKE3 and independently derived encryption/MAC keys
- Record size: 131072 bytes
- Format ID: 16

Usage: `x16 E|D <input> <output>`.

The format authenticates its header, record metadata, order, and final-record marker. Decryption writes to a temporary file and commits it only after every record authenticates; output never overwrites an existing path. x16 rejects every sibling format.

Security note: This payload primitive is niche/legacy and the composition is educational; do not treat it as independently audited.
