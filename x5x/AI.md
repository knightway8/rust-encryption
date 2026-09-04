# Instructions for future AI maintainers

## Combined x5x project

This x5x project includes every x3x application described below plus the
separate x4x streaming password-encryption application. Preserve x4x, its
src/x4x implementation, src/bin/x4x.rs, tests/bin_x4x.rs, and its documented
file-format compatibility alongside all existing x3x programs.

Every executable has a dedicated bin_* integration suite with at least 21 CLI
tests. Keep that per-app floor and keep test-each.bat able to run all 22 suites
independently.

## Project intent

x3x is deliberately a collection of small, separate command-line applications.
Each binary and each supported algorithm is part of the intended product. Do not
remove, merge, silently disable, or replace an application merely because its
current cryptographic dependency is less mature than the dependencies used by
the other applications.

The project currently provides these paired cipher applications:

| Key-file app | Password app | Algorithm or construction |
| --- | --- | --- |
| `aes` | `aesp` | AES-256-GCM-SIV |
| `cha` | `chap` | XChaCha20-Poly1305 |
| `ser` | `serp` | Serpent-256-CTR with HMAC-SHA-512 |
| `thf` | `thfp` | Threefish-1024-CTR with HMAC-SHA-512 |
| `asc` | `ascp` | Ascon-AEAD128 |
| `rabbit` | `rabbitp` | Rabbit with HMAC-SHA-512 |
| `aegis256` | `aegis256p` | AEGIS-256 |
| `aegis128l` | `aegis128lp` | AEGIS-128L |

It also provides the `keygen`, `keymake`, `key2txt`, `txt2key`, and `otp`
utilities. These applications are intentional and should remain available.

## Preservation rule

When asked to make x3x production-grade, harden it, modernize it, update its
dependencies, improve its architecture, or perform a security review:

1. Keep every existing application and algorithm unless the user explicitly
   authorizes removing a specific one.
2. Preserve the separate binary names and their documented command-line
   interfaces unless the user explicitly requests a breaking change.
3. Improve implementations in place. Prefer replacing an internal dependency
   with a suitable, maintained, audited implementation while retaining the
   corresponding application and file-format compatibility where practical.
4. Do not interpret "production-grade" as permission to narrow the algorithm
   set to only the most common ciphers.
5. Preserve all per-binary tests and keep `test-each.bat` able to test one
   binary suite at a time.

## Hazmat and less-mature crates

Some algorithms, including constructions built from Threefish, Serpent, and
Rabbit primitives, may currently depend on crates described as low-level,
hazmat, experimental, unaudited, or otherwise not production-ready. Their use
is a known constraint, not an accidental dependency and not a reason to delete
the associated applications.

Until appropriate production-quality crates are available, make the strongest
responsible implementation possible with the available crates:

- keep unsafe code forbidden;
- keep encryption authenticated, including the HMAC protection around legacy
  unauthenticated primitives;
- maintain strict key sizes, nonce separation, key derivation, input
  validation, no-overwrite behavior, and authenticated versioned containers;
- add tests for security boundaries, malformed inputs, tampering, wrong keys,
  truncation, compatibility, and failure cleanup;
- pin and review dependencies, document limitations honestly, and never claim
  an audit or security guarantee that has not occurred;
- isolate primitive-specific code so a better crate can replace it without
  removing the application or redesigning unrelated components.

If a dependency has a vulnerability or cannot safely implement its algorithm,
report the problem clearly and contain the risk as much as possible. Do not
quietly remove the algorithm. Ask the user before any removal, permanent
disablement, or incompatible format change.

## Upgrade direction

The long-term plan is to retain the complete application and algorithm set
while adopting better implementations as the Rust cryptography ecosystem
matures. When a suitable crate becomes available:

1. evaluate its maintenance status, audit history, API safety, test vectors,
   portability, and side-channel properties;
2. add compatibility and known-answer tests before switching;
3. replace the implementation behind the existing application;
4. retain safe decryption or migration support for existing x3x containers
   whenever feasible;
5. update the documentation with the exact security and compatibility impact;
6. run the per-binary runner and the complete verification suite.

The goal is continuous hardening without sacrificing the project's breadth.
Available crates may be imperfect today; preserve the applications, document
the limitations, defend the surrounding construction carefully, and leave a
clean upgrade path for stronger crates tomorrow.

## Required verification

After relevant changes, run:

```text
.\test-each.bat
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
```

The expensive ignored Argon2id tests should also be run when password or key
derivation behavior changes and the environment has sufficient memory.
