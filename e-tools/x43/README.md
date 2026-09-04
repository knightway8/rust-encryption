# x43

Standalone password-based file encryption app x43.

- Payload algorithm: GIFT-128
- Record authentication: HMAC-SHA256 Encrypt-then-MAC
- Password KDF: PBKDF2-HMAC-SHA256 (178000 iterations in production)
- Format identity: app ID 43, version 2

Usage: `x43 E|D <input> <output>`

GIFT-128 is a lightweight block cipher. Its low-level crate is marked hazmat and this file construction is unaudited.

Ciphertexts are intentionally incompatible with every sibling app and with the former shared implementation.
