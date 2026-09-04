# x25

A standalone password-file encryptor with its own format and payload cipher family.

- KDF: Argon2id
- Payload algorithm: ZUC-128
- Record protection: ZUC stream encryption + HMAC-SHA256 Encrypt-then-MAC
- Authentication: HMAC-SHA256 (32-byte tag; verified before decryption)
- Key material: 48 bytes
- Nonce: 16 bytes
- Record size: 65536 bytes
- Format ID: 25

Usage: `x25 E|D <input> <output>`.

The header, record metadata, record order, and final-record marker are authenticated. Output is staged in the destination directory and committed without overwriting an existing file. x25 deliberately rejects every sibling format.

Security note: This primitive or Rust implementation is legacy, specialized, or unaudited; it is included to make this app algorithmically independent. This custom file format has not received an independent cryptographic audit.