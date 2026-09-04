# x35

Standalone password-based file encryption app x35.

- Payload algorithm: ARIA-256
- Record authentication: HMAC-SHA256 Encrypt-then-MAC
- Password KDF: PBKDF2-HMAC-SHA256 (170000 iterations in production)
- Format identity: app ID 35, version 2

Usage: `x35 E|D <input> <output>`

ARIA is a standardized 128-bit block cipher. This custom CTR plus Encrypt-then-MAC file construction has not been independently audited.

Ciphertexts are intentionally incompatible with every sibling app and with the former shared implementation.
