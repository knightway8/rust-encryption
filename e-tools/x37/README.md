# x37

Standalone password-based file encryption app x37.

- Payload algorithm: Serpent-256
- Record authentication: HMAC-SHA256 Encrypt-then-MAC
- Password KDF: PBKDF2-HMAC-SHA256 (172000 iterations in production)
- Format identity: app ID 37, version 2

Usage: `x37 E|D <input> <output>`

Serpent was an AES finalist. The low-level crate and this custom file construction are unaudited.

Ciphertexts are intentionally incompatible with every sibling app and with the former shared implementation.
