# x27

A standalone password-file encryptor with its own format and payload cipher family.

- KDF: PBKDF2-SHA224
- Payload algorithm: SPECK128-256
- Record protection: SPECK-EAX authenticated encryption
- Authentication tag: 16 bytes
- Key material: 32 bytes
- Nonce: 16 bytes
- Record size: 262144 bytes
- Format ID: 27

Usage: `x27 E|D <input> <output>`.

The header, record metadata, record order, and final-record marker are authenticated. Output is staged in the destination directory and committed without overwriting an existing file. x27 deliberately rejects every sibling format.

Security note: This primitive or Rust implementation is legacy, specialized, or unaudited; it is included to make this app algorithmically independent. This custom file format has not received an independent cryptographic audit.