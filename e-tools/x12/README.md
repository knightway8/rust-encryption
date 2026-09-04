# x12

A standalone password-file encryptor with a payload cipher family not used by any sibling app.

- KDF: PBKDF2-SHA512
- Payload algorithm: KCipher-2
- Construction: Encrypt-then-MAC with HMAC-SHA256 and independently derived encryption/MAC keys
- Record size: 262144 bytes
- Format ID: 12

Usage: `x12 E|D <input> <output>`.

The format authenticates its header, record metadata, order, and final-record marker. Decryption writes to a temporary file and commits it only after every record authenticates; output never overwrites an existing path. x12 rejects every sibling format.

Security note: This payload primitive is niche/legacy and the composition is educational; do not treat it as independently audited.
