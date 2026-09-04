# x22

A standalone password-file encryptor with its own format and payload cipher family.

- KDF: PBKDF2-SHA256
- Payload algorithm: MKV128-256-GCM
- Record protection: MKV128-256-GCM native authenticated encryption
- Authentication tag: 16 bytes
- Key material: 32 bytes
- Nonce: 12 bytes
- Record size: 262144 bytes
- Format ID: 22

Usage: `x22 E|D <input> <output>`.

The header, record metadata, record order, and final-record marker are authenticated. Output is staged in the destination directory and committed without overwriting an existing file. x22 deliberately rejects every sibling format.

Security note: The MKV128-GCM implementation reports an NCC Group audit with no significant findings, subject to its platform multiplication caveat. This custom file format has not received an independent cryptographic audit.