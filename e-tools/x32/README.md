# x32

A standalone password-file encryptor with its own format and payload cipher family.

- KDF: scrypt
- Payload algorithm: PRESENT-128
- Record protection: PRESENT-CTR + HMAC-SHA256 Encrypt-then-MAC
- Authentication: HMAC-SHA256 (32-byte tag; verified before decryption)
- Key material: 48 bytes
- Nonce: 8 bytes
- Counter layout: checked 32-bit record number followed by a 32-bit block counter
- Record size: 1048576 bytes
- Format ID: 32

Usage: `x32 E|D <input> <output>`.

The header, record metadata, record order, and final-record marker are authenticated. Output is staged in the destination directory and committed without overwriting an existing file. x32 deliberately rejects every sibling format.

Security note: This primitive or Rust implementation is legacy, specialized, or unaudited; it is included to make this app algorithmically independent. This custom file format has not received an independent cryptographic audit.
