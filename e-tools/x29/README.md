# x29

A standalone password-file encryptor with its own format and payload cipher family.

- KDF: PBKDF2-SHA384
- Payload algorithm: RC6-256
- Record protection: RC6-CTR + HMAC-SHA256 Encrypt-then-MAC
- Authentication: HMAC-SHA256 (32-byte tag; verified before decryption)
- Key material: 64 bytes
- Nonce: 16 bytes
- Counter layout: 64-bit record number followed by a 64-bit block counter
- Record size: 32768 bytes
- Format ID: 29

Usage: `x29 E|D <input> <output>`.

The header, record metadata, record order, and final-record marker are authenticated. Output is staged in the destination directory and committed without overwriting an existing file. x29 deliberately rejects every sibling format.

Security note: This primitive or Rust implementation is legacy, specialized, or unaudited; it is included to make this app algorithmically independent. This custom file format has not received an independent cryptographic audit.
