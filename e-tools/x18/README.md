# x18

A standalone password-file encryptor with its own format and payload cipher family.

- KDF: PBKDF2-SHA512
- Payload algorithm: NORX64-4-1
- Record protection: NORX64-4-1 native authenticated encryption
- Authentication tag: 32 bytes
- Key material: 32 bytes
- Nonce: 32 bytes
- Record size: 1048576 bytes
- Format ID: 18

Usage: `x18 E|D <input> <output>`.

The header, record metadata, record order, and final-record marker are authenticated. Output is staged in the destination directory and committed without overwriting an existing file. x18 deliberately rejects every sibling format.

Security note: The implementation is old and unaudited; x18 vendors it solely to replace a yanked transitive dependency with subtle 2.6. This custom file format has not received an independent cryptographic audit.