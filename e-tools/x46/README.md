# x46

Standalone password-based file encryption app x46.

- Payload algorithm: Spritz
- Record authentication: HMAC-SHA256 Encrypt-then-MAC
- Password KDF: PBKDF2-HMAC-SHA256 (181000 iterations in production)
- Format identity: app ID 46, version 2

Usage: `x46 E|D <input> <output>`

LEGACY / EDUCATIONAL ONLY: Spritz is an RC4-like sponge with published theoretical attacks, and the crate itself warns it is not robust. Do not use this app for sensitive data.

Ciphertexts are intentionally incompatible with every sibling app and with the former shared implementation.
