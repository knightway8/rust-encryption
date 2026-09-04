# x50

Standalone password-based file encryption app x50.

- Payload algorithm: RC4-drop3072
- Record authentication: HMAC-SHA256 Encrypt-then-MAC
- Password KDF: PBKDF2-HMAC-SHA256 (185000 iterations in production)
- Format identity: app ID 50, version 2

Usage: `x50 E|D <input> <output>`

BROKEN / EDUCATIONAL ONLY: RC4 is cryptographically broken. Dropping 3072 keystream bytes and authenticating records does not rehabilitate RC4. Do not use this app for sensitive data.

Ciphertexts are intentionally incompatible with every sibling app and with the former shared implementation.
