# Linux key and OTP utilities

This repository contains three independent, Linux-only Rust applications. It
is intentionally **not** a Cargo workspace: enter an application's directory
and compile or test that package by itself.

| Directory | Application | Brief description |
| --- | --- | --- |
| [`otp2/`](otp2/) | `otp2` | Atomically XORs a regular file with bytes from `key.key` beside the executable; running the same transformation again with the same key bytes reverses it. |
| [`otp2-auth/`](otp2-auth/) | `otp2-auth` | Creates and verifies detached HMAC-SHA-256 sidecars for arbitrary regular files without encrypting or rewriting the authenticated file. |
| [`versakey/`](versakey/) | VersaKey | Provides interactive deterministic key generators using several password-based derivation and stream-generation suites. |

Each application has its own `Cargo.toml`, `Cargo.lock`, source tree, tests,
release build, and documentation. See that directory's full README before
using it:

- [`otp2/README.md`](otp2/README.md)
- [`otp2-auth/README.md`](otp2-auth/README.md)
- [`versakey/README.md`](versakey/README.md)

## Build requirements

All packages are intended specifically for Linux, use Cargo edition 2024, and
require Rust 1.98.1 or newer. Each package pins Rust 1.98.1 for reproducible
development and CI while declaring it as the minimum supported version.

Build one application at a time, for example:

```text
cd otp2
cargo build --locked --release

cd ../otp2-auth
cargo build --locked --release

cd ../versakey
cargo build --locked --release --bins
```

The applications deliberately do not depend on one another. Building or using
one does not compile, install, or run either of the others.
