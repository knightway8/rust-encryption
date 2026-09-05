# best 1.0.0 validation

Validated on Windows x86_64 on 2026-09-05, with Rust 1.98.1
(`48a229cea 2026-09-01`), edition 2024.

## Results

| Check | Result |
| --- | --- |
| Default-profile tests | 675 passed, 0 failed, 0 ignored |
| Optimized release-profile tests | 675 passed, 0 failed, 0 ignored |
| Unit/adversarial tests | 393 passing cases |
| Filesystem and real CLI tests | 159 passing cases |
| Published C2SP/CCTV vectors | 123 passing cases, including explicit armor rejection |
| Property testing | 3 properties, 256 generated cases each per full run |
| Excessive-work error formatting | All 65,536 byte-value pairs checked without arithmetic panics |
| Formatting | Passed |
| Clippy, all targets, warnings denied | Passed |
| Documentation test command | Passed; no doctests defined |
| Linux target and Unix tests | Compile checked with x86_64-unknown-linux-gnu |
| Independent Go age 1.3.2 interoperability | 24 matching plaintext hashes; 11 sizes, 0 bytes through 64 MiB |
| RustSec audit | 0 known vulnerabilities, 0 warnings, no ignored advisories |

The independent interoperability run exercised both encryption directions,
complete verification, and multiple recipients. It was repeated against the actual
release binary rebuilt in the Desktop project. Official age's downloaded archive
was verified against its published SHA-256 digest:
`f48d8f8f9ebe903ab5027ed067652f2cc1db94bc206976430133b905dcd8e8c7`.

RustSec database: 1,239 advisories, commit
`5a0ebedfe8bdd2e295b171f4162f8c977bcad9a5`, last updated 2026-09-02.
The audited lockfile contains 222 packages including the application. A clean audit
means no matching published advisories; it is not a proof that every dependency is
free of defects.

`Cargo.lock` SHA-256:
`bcfa06cf5c86587c1925275337ff2bad8032d9e3f5c7c23883177bc2d25d3251`.

The Desktop release executable is 1,418,240 bytes. SHA-256:
`5469c33936cb8a4c49c79e8a9ae5a7f45e563bc8669fb6b242ea1fb1e7dfe606`.

## Findings fixed during development

- Short writes could make the upstream header serializer fail. Buffered output and
  an explicit final flush now handle that case, with boundary and injected-failure tests.
- Two legacy, unterminated stanza encodings were accepted by age. The app enforces
  canonical stanza termination; the relevant independent vectors now pass.
- age 0.12.1 can panic while formatting an excessive-work error. The app uses its own
  bounded messages and tests every required/target pair.
- Secret-file reads preallocate their bounded buffers to avoid discarded allocations
  during buffer growth.

## Limits of this validation

Linux was compile checked; Linux/macOS runtime tests and remote CI jobs were not
run in this Windows session. CI configuration is provided. The cargo-fuzz harness
is provided but no dedicated libFuzzer campaign was run. Property tests did run.
Interactive password entry uses rpassword; automation/password-file workflows were
tested in subprocesses. Cancellation checks and cleanup were tested programmatically;
crash/power-loss behavior and every physical storage device were not simulated.

No independent security audit, certification, code signing, or FIPS claim is made.
The upstream age Rust crate is pre-1.0 and documents beta status. SECURITY.md
describes temporary plaintext, filesystem trust, crash cleanup, and key-storage limits.
