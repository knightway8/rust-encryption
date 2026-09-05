# Validation guide

`test.bat` runs formatting, strict Clippy, the default-profile suite, and doctests.
`cargo test --release --all-targets --locked -- --test-threads=4` checks the
optimized artifact paths as well. No test is ignored to make the run pass.

## What is exercised

- Chunk boundaries, empty and binary inputs, short reads/writes, interrupted reads,
  failed writes/flushes, zero writes, and bounded header allocation.
- Every bit position of selected header/payload bytes; every truncation of a small
  ciphertext; appended garbage, concatenation, and reordered/duplicated chunks.
- One through 64 recipients, incorrect identities, multiple candidate identities,
  key generation, secret input validation, Unicode paths, and exact size caps.
- Full-file authentication before publication, no-clobber behavior for files,
  directories, hard links and racing destinations, cancellation, and temp cleanup.
- Real CLI subprocesses, usage errors/exit codes, quiet mode, public-key extraction,
  production-cost password encryption/decryption/verification and cost rejection.
- Windows protected DACLs and path/device rules; Unix permissions and symlink tests
  run on Unix. The Windows ACL test uses Windows PowerShell with a clean module path.
- 123 public C2SP/CCTV fixtures. Binary fixtures must match their expected success
  or failure; successful plaintext is checked against a published SHA-256 hash.
  The 31 ASCII armor fixtures exercise explicit rejection of an unsupported format.
  Strict canonical stanza termination rejects two legacy encodings that upstream
  age intentionally accepts. Fixture bytes are unchanged from age 0.12.1's testkit.
- Three property tests, each with 256 generated inputs by default: binary round
  trips, ciphertext corruption, and arbitrary malformed input. Saved regressions
  should be checked in when a property fails. Increase `PROPTEST_CASES` for soak runs.
- All 65,536 combinations of upstream scrypt required/target values are checked to
  ensure error formatting cannot underflow or overflow.

## Independent interoperability

`scripts/interop.ps1` compares the built best CLI with an independently installed
official Go age executable. It exercises both encryption directions, multiple file
sizes, binary inputs, paths with spaces, verification, and SHA-256 plaintext comparisons.

```powershell
.\scripts\interop.ps1 -AgeExe C:\tools\age\age.exe
```

The script creates only disposable synthetic data under a random system temp
directory. It deletes only that directory after checking its resolved location.
Acquire the reference binary from the official age releases and verify its digest.

## Fuzzing

The isolated `fuzz/` package is ready for cargo-fuzz on Linux/macOS with nightly
Rust and libFuzzer. It targets constrained header/decryption handling and bounds
all output using `--max-bytes` equivalent operation options. Seed the corpus with
synthetic age files and malformed headers, never real secrets.

```text
cargo install cargo-fuzz --locked
cargo +nightly fuzz run decrypt -- -max_total_time=300 -max_len=131072
```

The regular property tests run on stable Rust and Windows. A compiled harness is
not a completed fuzz campaign; see the delivered validation report for what was
actually run. Cross-platform CI configuration likewise does not imply its jobs
have already run.
