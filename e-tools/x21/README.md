# x21

A standalone password-file encryptor with its own format and payload cipher family.

- KDF: PBKDF2-SHA224
- Payload algorithm: Saturnin-CTR-Cascade
- Record protection: Saturnin-CTR-Cascade native authenticated encryption
- Authentication tag: 32 bytes
- Key material: 32 bytes
- Nonce: 16 bytes
- Record size: 131072 bytes
- Format ID: 21

Usage: `x21 E|D <input> <output>`.

The header, record metadata, record order, and final-record marker are authenticated. Output is staged in the destination directory and committed without overwriting an existing file. x21 deliberately rejects every sibling format.

Security note: The crate reports no formal third-party audit and documents open security-proof obligations. This custom file format has not received an independent cryptographic audit.