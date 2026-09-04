# x42

Standalone password-based file encryption app x42.

- Payload algorithm: BELT-DWP
- Record authentication: HMAC-SHA256 Encrypt-then-MAC
- Password KDF: PBKDF2-HMAC-SHA256 (177000 iterations in production)
- Format identity: app ID 42, version 2

Usage: `x42 E|D <input> <output>`

BELT-DWP is a standardized authenticated-encryption construction. This crate and surrounding password-file format are unaudited; records additionally use outer HMAC-SHA256.

Ciphertexts are intentionally incompatible with every sibling app and with the former shared implementation.
