# x44

Standalone password-based file encryption app x44.

- Payload algorithm: Threefish-256
- Record authentication: HMAC-SHA256 Encrypt-then-MAC
- Password KDF: PBKDF2-HMAC-SHA256 (179000 iterations in production)
- Format identity: app ID 44, version 2

Usage: `x44 E|D <input> <output>`

Threefish-256 is used directly as a tweakable block cipher in a custom counter construction with Encrypt-then-MAC. This format is unaudited.

Ciphertexts are intentionally incompatible with every sibling app and with the former shared implementation.
