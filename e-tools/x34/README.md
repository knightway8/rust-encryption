# x34

A standalone password-file encryptor with its own format and payload cipher family.

- KDF: PBKDF2-SHA256
- Payload algorithm: Trivium
- Record protection: Trivium stream encryption + HMAC-SHA256 Encrypt-then-MAC
- Authentication: HMAC-SHA256 (32-byte tag; verified before decryption)
- Key material: 42 bytes
- Nonce: 10 bytes
- Record size: 65536 bytes
- Format ID: 34

Usage: `x34 E|D <input> <output>`.

The header, record metadata, record order, and final-record marker are authenticated. Output is staged in the destination directory and committed without overwriting an existing file. x34 deliberately rejects every sibling format.

Security note: This primitive or Rust implementation is legacy, specialized, or unaudited; it is included to make this app algorithmically independent. This custom file format has not received an independent cryptographic audit.