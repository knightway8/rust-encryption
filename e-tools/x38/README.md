# x38

Standalone password-based file encryption app x38.

- Payload algorithm: Twofish-256
- Record authentication: HMAC-SHA256 Encrypt-then-MAC
- Password KDF: PBKDF2-HMAC-SHA256 (173000 iterations in production)
- Format identity: app ID 38, version 2

Usage: `x38 E|D <input> <output>`

Twofish was an AES finalist. The low-level crate and this custom file construction are unaudited.

Ciphertexts are intentionally incompatible with every sibling app and with the former shared implementation.
