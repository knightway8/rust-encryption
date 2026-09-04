# x26

A standalone password-file encryptor with its own format and payload cipher family.

- KDF: scrypt
- Payload algorithm: SIMON128-256
- Record protection: SIMON-EAX authenticated encryption
- Authentication tag: 16 bytes
- Key material: 32 bytes
- Nonce: 16 bytes
- Record size: 131072 bytes
- Format ID: 26

Usage: `x26 E|D <input> <output>`.

The header, record metadata, record order, and final-record marker are authenticated. Output is staged in the destination directory and committed without overwriting an existing file. x26 deliberately rejects every sibling format.

Security note: This primitive or Rust implementation is legacy, specialized, or unaudited; it is included to make this app algorithmically independent. This custom file format has not received an independent cryptographic audit.