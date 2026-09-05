# Rust verification report

Source folder: `C:\Users\a1\Desktop\rust-encryptio`

All **67 application packages** now require **Rust 1.98.1**, use edition 2024,
and have a pinned toolchain with rustfmt and Clippy. The 50 `e-tools` applications
remain one Cargo workspace; the three OTP2 applications remain independent.
Assembly, Zig, archives, and existing compiled binaries were not changed.

Rust 1.98.1 is the latest stable release verified for this update, released
2026-09-03: [official Rust announcement](https://blog.rust-lang.org/2026/09/03/Rust-1.98.1/).
The compiler was installed and reports `rustc 1.98.1 (48a229cea 2026-09-01)`.
The project pins select it without changing the machine's global default.

## Results

**4,889 Windows tests passed**, with no failures in the final runs. This count
includes the three normally ignored production-cost tests. Every Windows-compatible
package passed formatting, Clippy with warnings denied, and documentation with
warnings denied. Tests compiled all targets and enabled all features.

| Project / workspace | Runtime tests | Clippy | Documentation |
| --- | ---: | --- | --- |
| `algos` | 61 passed | Pass | Pass |
| `be` | 186 passed | Pass | Pass |
| `cascade` | 50 passed | Pass | Pass |
| `e-tools` | 391 passed | Pass | Pass |
| `ezcrypt` | 411 passed | Pass | Pass |
| `filecrypt` | 78 passed | Pass | Pass |
| `multicrypt` | 41 passed | Pass | Pass |
| `otp` | 53 passed | Pass | Pass |
| `otp1` | 125 passed | Pass | Pass |
| `tf1024` | 11 passed | Pass | Pass |
| `threefish1024` | 22 passed | Pass | Pass |
| `versakey` | 120 passed | Pass | Pass |
| `x2` | 49 passed | Pass | Pass |
| `x5x` | 3,291 passed | Pass | Pass |
| `secure` | Not run: Linux required | Pass (Linux target) | Pass (Linux target) |
| `OTP2/otp2` | Not run: Linux required | Pass (Linux target) | Pass (Linux target) |
| `OTP2/otp2-auth` | Not run: Linux required | Pass (Linux target) | Pass (Linux target) |
| `OTP2/versakey` | Not run: Linux required | Pass (Linux target) | Pass (Linux target) |

The four Linux-only packages also passed compilation of their application and test
targets. Their runtime tests and Linux release builds could not run because this
Windows machine has no Linux/WSL environment. `cascade` additionally passed Clippy
for its Linux code and test targets; its Windows tests cover cryptographic routines
and the intentional refusal of file operations on Windows. Unix-only runtime tests
in otherwise portable packages likewise require the Linux runner. These checks do
not constitute an independent cryptographic security audit.

## Fixes and regression coverage

- **tf1024:** fixed Windows filename aliases such as `key.key.` bypassing the
  protected-key name check. Device names, alternate streams, forbidden characters,
  and trailing spaces/dots are rejected. A regression test failed on the original
  behavior before the fix. Five new tests cover the actual CLI, exact bytes, key
  preservation, existing destinations, corrupted/truncated/appended containers,
  length overflow, malformed keys, and rejection without leftover plaintext.
- **filecrypt and x2:** fixed directory inputs being reported as access errors on
  Windows before the intended regular-file validation could run. The file type is
  checked on the opened handle. Added an x2 CLI regression; existing filecrypt
  regressions now pass.
- **filecrypt tests:** private-key fixtures now receive the protected Windows DACL
  required by the app, so authentication/error tests exercise the intended paths.
- **cascade tests:** fixed syncing a read-only file handle on Windows.
- **otp1 tests:** restore the original Windows file permissions during cleanup.
- **All 50 e-tools apps:** added 100 production-CLI tests covering damaged ciphertext,
  truncation, appended data, output cleanup, and preservation of existing destinations.
- **Modern Rust APIs:** resolved newly enabled Clippy findings in cipher code and
  test helpers using fixed-size chunks, integer divisibility/ceiling division, and
  let chains. Kept explicit, documented platform-signature lint exceptions only.
- **Reproducibility:** added the missing `threefish1024/Cargo.lock`, updated old
  toolchain references in documentation/CI and OTP2's repository instructions,
  and retained existing dependency locks elsewhere. No file-format migration was made.

In total, **106 new tests** were added. Repeated verification runs are not counted
twice in the totals above.

## Repeat verification

From the Desktop folder, run this on Windows (slow tests are included):

```powershell
.\verify-rust.ps1
```

Use `-Projects tf1024,x2` to select projects, `-SkipSlow` for quick runs, or
`-BuildRelease` to additionally build release executables. Test builds use the
normal debug test profile; Windows release executables were not replaced.

On Linux, install Rust 1.98.1 with rustfmt and Clippy, then run:

```bash
bash verify-rust.sh
# Or just the four Linux-only packages:
bash verify-rust.sh secure OTP2/otp2 OTP2/otp2-auth OTP2/versakey
```

The Linux runner checks formatting, Clippy, all tests including ignored tests,
documentation, and release builds. It excludes the Windows-only `ezcrypt` app.
No shared build directory is introduced for the independent OTP2 applications.

`rust-update.patch` contains the textual changes. `rust-before-update.zip` contains
the original versions of replaced files and a list of newly added files.
`rust-verification-logs.zip` contains the test/lint/documentation logs and summaries.
