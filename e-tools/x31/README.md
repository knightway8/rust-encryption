# x31

A standalone password-file encryptor with its own format and payload cipher family.

- KDF: Argon2id
- Payload algorithm: SEED-128
- Record protection: SEED-EAX authenticated encryption
- Authentication tag: 16 bytes
- Key material: 16 bytes
- Nonce: 16 bytes
- Record size: 262144 bytes
- Format ID: 31

Usage: `x31 E|D <input> <output>`.

The header, record metadata, record order, and final-record marker are authenticated. Output is staged in the destination directory and committed without overwriting an existing file. x31 deliberately rejects every sibling format.

Security note: This primitive or Rust implementation is legacy, specialized, or unaudited; it is included to make this app algorithmically independent. This custom file format has not received an independent cryptographic audit.