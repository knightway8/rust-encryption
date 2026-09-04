# x17

A standalone password-file encryptor with a payload cipher family not used by any sibling app.

- KDF: PBKDF2-SHA384
- Payload algorithm: Turing
- Construction: Encrypt-then-MAC with HMAC-SHA512 and independently derived encryption/MAC keys
- Record size: 262144 bytes
- Format ID: 17

Usage: `x17 E|D <input> <output>`.

The format authenticates its header, record metadata, order, and final-record marker. Decryption writes to a temporary file and commits it only after every record authenticates; output never overwrites an existing path. x17 rejects every sibling format.

Security note: This payload primitive is niche/legacy and the composition is educational; do not treat it as independently audited.
