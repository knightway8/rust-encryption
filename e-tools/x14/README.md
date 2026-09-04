# x14

A standalone password-file encryptor with a payload cipher family not used by any sibling app.

- KDF: scrypt
- Payload algorithm: Strumok
- Construction: Encrypt-then-MAC with HMAC-SHA384 and independently derived encryption/MAC keys
- Record size: 32768 bytes
- Format ID: 14

Usage: `x14 E|D <input> <output>`.

The format authenticates its header, record metadata, order, and final-record marker. Decryption writes to a temporary file and commits it only after every record authenticates; output never overwrites an existing path. x14 rejects every sibling format.

Security note: This payload primitive is niche/legacy and the composition is educational; do not treat it as independently audited.
