# x49

Standalone password-based file encryption app x49.

- Payload algorithm: Skipjack
- Record authentication: HMAC-SHA256 Encrypt-then-MAC
- Password KDF: PBKDF2-HMAC-SHA256 (184000 iterations in production)
- Format identity: app ID 49, version 2

Usage: `x49 E|D <input> <output>`

BROKEN / EDUCATIONAL ONLY: Skipjack has an 80-bit key, a 64-bit block, and historical cryptanalytic weaknesses. Do not use this app for sensitive data.

Ciphertexts are intentionally incompatible with every sibling app and with the former shared implementation.
