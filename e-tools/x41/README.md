# x41

Standalone password-based file encryption app x41.

- Payload algorithm: Blowfish
- Record authentication: HMAC-SHA256 Encrypt-then-MAC
- Password KDF: PBKDF2-HMAC-SHA256 (176000 iterations in production)
- Format identity: app ID 41, version 2

Usage: `x41 E|D <input> <output>`

LEGACY / EDUCATIONAL ONLY: Blowfish has a 64-bit block and is subject to birthday-bound limits such as Sweet32. Do not use this app for sensitive data.

Ciphertexts are intentionally incompatible with every sibling app and with the former shared implementation.
