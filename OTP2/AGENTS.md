# Repository instructions

## Project layout

This repository contains three intentionally separate applications:

- `otp2/` — an atomic XOR file transformer.
- `otp2-auth/` — detached HMAC authentication for files.
- `versakey/` — deterministic `key.key` generation tools.

They are not members of a Cargo workspace and must remain independent. Do not
add a root `Cargo.toml`, shared crate, path dependency, common build output, or
cross-application source dependency. A change to one application must not
require either of the other applications to compile or run.

Run Cargo commands from the application directory being changed. Compile,
test, lint, document, and release each package separately.

## Platform and toolchain

All three applications target Linux specifically. Linux-only APIs and behavior
are intentional. Keep an explicit non-Linux compile-time rejection in every
package; do not add or claim Windows, macOS, BSD, or other platform support
without a new repository-level decision.

Every package must:

- use Cargo edition `2024`;
- declare `rust-version = "1.97.1"` as its minimum supported Rust version;
- include a `rust-toolchain.toml` pinned to Rust `1.97.1` with the minimal
  profile plus `clippy` and `rustfmt`; and
- keep its lockfile and dependencies compatible with Rust 1.97.1.

Newer Rust versions may also be used deliberately, but code and dependencies
must continue to compile with the declared Rust 1.97.1 minimum.

## Application boundaries

- `otp2` only transforms file contents with `key.key`. It must not absorb
  authentication, key generation, or cloud-workflow responsibilities.
- `otp2-auth` only creates and verifies detached authentication sidecars (and
  manages its own `auth.key`). It must not encrypt files or depend on `otp2`.
- `versakey` only generates deterministic key material. It must not transform
  or authenticate user files and must not depend on either OTP application.

Preserve each application's on-disk formats and deterministic outputs unless a
format or compatibility change is explicitly requested. Treat file-replacement,
key-handling, authentication, and crash-durability code as security-sensitive.

## Verification

For every changed application, run these commands from that application's own
directory:

```text
cargo fmt --all -- --check
cargo test --locked --all-targets --no-fail-fast
cargo clippy --locked --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps
cargo build --locked --release --bins
```

Add focused regression tests for bug fixes and meaningful tests for new
behavior. Do not add tests that only duplicate type-system or compiler checks.

Update the affected application's own README when its commands, behavior,
security properties, file formats, or limitations change. Keep the root README
to a short directory-level overview and direct readers to the application
README files for complete documentation.
