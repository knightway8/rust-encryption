# x39

Standalone password-based file encryption app x39.

- Payload algorithm: Kuznyechik
- Record authentication: HMAC-SHA256 Encrypt-then-MAC
- Password KDF: PBKDF2-HMAC-SHA256 (174000 iterations in production)
- Format identity: app ID 39, version 2

Usage: `x39 E|D <input> <output>`

Kuznyechik is a national-standard block cipher. The Rust implementation and custom file construction are unaudited.

Ciphertexts are intentionally incompatible with every sibling app and with the former shared implementation.
