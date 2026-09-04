# x47

Standalone password-based file encryption app x47.

- Payload algorithm: Rabbit
- Record authentication: HMAC-SHA256 Encrypt-then-MAC
- Password KDF: PBKDF2-HMAC-SHA256 (182000 iterations in production)
- Format identity: app ID 47, version 2

Usage: `x47 E|D <input> <output>`

Rabbit is an older stream cipher. The low-level crate and this Encrypt-then-MAC file construction are unaudited.

Ciphertexts are intentionally incompatible with every sibling app and with the former shared implementation.
