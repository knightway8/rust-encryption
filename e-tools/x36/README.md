# x36

Standalone password-based file encryption app x36.

- Payload algorithm: Camellia-256
- Record authentication: HMAC-SHA256 Encrypt-then-MAC
- Password KDF: PBKDF2-HMAC-SHA256 (171000 iterations in production)
- Format identity: app ID 36, version 2

Usage: `x36 E|D <input> <output>`

Camellia is standardized, but this custom CTR plus Encrypt-then-MAC file construction has not been independently audited.

Ciphertexts are intentionally incompatible with every sibling app and with the former shared implementation.
