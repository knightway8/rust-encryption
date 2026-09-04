# x48

Standalone password-based file encryption app x48.

- Payload algorithm: TEA-32
- Record authentication: HMAC-SHA256 Encrypt-then-MAC
- Password KDF: PBKDF2-HMAC-SHA256 (183000 iterations in production)
- Format identity: app ID 48, version 2

Usage: `x48 E|D <input> <output>`

BROKEN / EDUCATIONAL ONLY: TEA has equivalent-key and related-key weaknesses and a 64-bit block. Do not use this app for sensitive data.

Ciphertexts are intentionally incompatible with every sibling app and with the former shared implementation.
