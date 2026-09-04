# x15

A standalone password-file encryptor with a payload cipher family not used by any sibling app.

- KDF: PBKDF2-SHA224
- Payload algorithm: Enocoro-128v2
- Construction: Encrypt-then-MAC with HMAC-SHA3-256 and independently derived encryption/MAC keys
- Record size: 65536 bytes
- Format ID: 15

Usage: `x15 E|D <input> <output>`.

The format authenticates its header, record metadata, order, and final-record marker. Decryption writes to a temporary file and commits it only after every record authenticates; output never overwrites an existing path. x15 rejects every sibling format.

Security note: This payload primitive is niche/legacy and the composition is educational; do not treat it as independently audited.
