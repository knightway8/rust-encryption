# x19

A standalone password-file encryptor with its own format and payload cipher family.

- KDF: Argon2id
- Payload algorithm: Grain-128AEADv2
- Record protection: Grain-128AEADv2 (8-byte native tag) inside HMAC-SHA256 Encrypt-then-MAC
- Authentication: 32-byte outer HMAC verified in constant time before Grain decryption (40-byte total overhead)
- Key material: 48 bytes (16-byte Grain key + independent 32-byte HMAC key)
- Nonce: 12 bytes
- Record size: 32768 bytes
- Format ID: 19

Usage: `x19 E|D <input> <output>`.

The header, record metadata, record order, and final-record marker are authenticated. Output is staged in the destination directory and committed without overwriting an existing file. x19 deliberately rejects every sibling format.

Security note: The crate explicitly reports no security audit and its native tag check is not constant-time. The outer HMAC prevents unauthenticated inputs from reaching that check. This custom file format has not received an independent cryptographic audit.
