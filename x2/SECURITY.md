# Security policy

Please report suspected vulnerabilities privately to the project maintainer.
Do not include real passwords, plaintext, keys, or sensitive encrypted files in
an issue or diagnostic log.

The current supported container version is v1. Encrypted files should be backed
up before upgrading the application. Authentication failure intentionally does
not distinguish a wrong password from corrupted or modified ciphertext.

This project provides best-effort in-process zeroization and atomic destination
visibility in a stable, trusted output directory. It does not protect an
attacker-writable path namespace, compromised operating system, or physical
memory. See the security boundaries in `README.md` before relying on it for
high-value data.
