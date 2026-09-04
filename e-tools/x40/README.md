# x40

Standalone password-based file encryption app x40.

- Payload algorithm: SM4
- Record authentication: HMAC-SHA256 Encrypt-then-MAC
- Password KDF: PBKDF2-HMAC-SHA256 (175000 iterations in production)
- Format identity: app ID 40, version 2

Usage: `x40 E|D <input> <output>`

SM4 is a standardized block cipher. The low-level crate and custom file construction are unaudited.

Ciphertexts are intentionally incompatible with every sibling app and with the former shared implementation.
