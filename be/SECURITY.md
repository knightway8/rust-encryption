# Security policy

## Supported version

Only the newest commit and release build are supported. Keep `Cargo.lock` under
version control and rebuild after dependency security updates.

## Threat model

`be` protects file contents and integrity when an attacker obtains ciphertext
but not `key.key`. It does not hide file names, file sizes, access times, or the
fact that age encryption is being used. It cannot protect plaintext or keys from
malware, an already-compromised account, memory inspection by a privileged
process, malicious hardware, or deletion.

`be` uses classic X25519 and is not post-quantum secure. Store-now/decrypt-later
adversaries are outside this version's threat model.

## Key handling

- Keep `key.key` secret and backed up offline.
- Never send or commit `key.key`; `.gitignore` excludes it by default.
- `key.pub` is public and may be copied to machines that only encrypt.
- On Unix, `be` refuses a secret key readable by group or other users.
- Securely deleting files from SSDs and journaled or cloud-synchronized file
  systems is not reliably achievable by this application.

## Reporting

Do not publish suspected vulnerabilities before the maintainer has had a chance
to investigate and prepare a fix.
