# x45

Standalone password-based file encryption app x45.

- Payload algorithm: LEA-256
- Record authentication: HMAC-SHA256 Encrypt-then-MAC
- Password KDF: PBKDF2-HMAC-SHA256 (180000 iterations in production)
- Format identity: app ID 45, version 2

Usage: `x45 E|D <input> <output>`

LEA is a standardized lightweight block cipher. The crate is older and this custom file construction is unaudited.

Ciphertexts are intentionally incompatible with every sibling app and with the former shared implementation.
