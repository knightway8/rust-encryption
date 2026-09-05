# Rust Encryption

A collection of command-line encryption apps and key utilities, mostly written
in Rust, with a few Zig and assembly projects too. The aim is to keep individual
tools approachable enough to read, experiment with, test, and customize—for
learning and for fun.

The collection explores password-based encryption, key files, public-key
encryption, streaming large files, multiple cipher suites, and one-time pads.
Each app has its own README with its commands, file formats, requirements, and
limitations. This page is a guide to finding your way around.

## Project guide

### File-encryption apps

| Project | Overview |
| --- | --- |
| [be](be/README.md) | Public-key file encryption using the standard age v1 format and X25519 recipient keys. |
| [cascade](cascade/README.md) | Applies one encryption layer at a time, with separate keys for AES, Serpent, XChaCha, and Threefish layers. File operations require Unix. |
| [ezcrypt](ezcrypt/README.md) | Windows file encryption using a password and a single path. The `.ez` extension selects encryption or decryption; successful operations replace the source with the completed output. |
| [filecrypt](filecrypt/README.md) | Streaming encryption with a binary key file, using AES-256-GCM-SIV or XChaCha20-Poly1305. |
| [multicrypt](multicrypt/README.md) | Seven authenticated encryption suites with separate, typed key files. Processes whole files in memory. |
| [secure](secure/README.md) | Linux-only password encryption using the standard age v1 format, with strict filesystem requirements. |
| [tf1024](tf1024/README.md) | Small Threefish-1024 encryption CLI that keeps its key, input, and output beside the executable. |
| [threefish1024](threefish1024/README.md) | A separate authenticated, streaming Threefish-1024 implementation with its own format and CLI. |
| [x2](x2/README.md) | Streaming password encryption using AES-256-GCM-SIV or XChaCha20-Poly1305. |

### Collections of apps

| Project | Overview |
| --- | --- |
| [algos](algos/README.md) | 30 executables, each fixed to one authenticated cipher suite, with a shared Rust library. Includes key-size variants and both modern and legacy primitives. |
| [e-tools](e-tools/README.md) | 50 standalone password-encryption apps, `x1` through `x50`, in one Cargo workspace. Each uses a different payload algorithm family and has its own README. Includes experimental and historically broken algorithms for study. |
| [x5x](x5x/README.md) | 22 independently usable executables combining the x3x encryption/key-tool collection and the x4x streaming password-encryption CLI. |

The top-level `x2` app is separate from `e-tools/x2`. Similar names or shared
cipher choices do not mean that apps can read each other's encrypted files.

### Pads, XOR, authentication, and key generation

| Project | Overview |
| --- | --- |
| [otp](otp/README.md) | Authenticated one-time-pad app with separate sender and receiver pad copies, exact message-length capacity, and single-use state. |
| [otp1](otp1/README.md) | Atomically XORs a file with `key.key`; includes an optional detached-authentication companion. |
| [versakey](versakey/README.md) | Five interactive password-based generators that deterministically produce `key.key`. |
| [OTP2/otp2](OTP2/otp2/README.md) | Linux-only atomic XOR file transformer using a key beside the executable. |
| [OTP2/otp2-auth](OTP2/otp2-auth/README.md) | Linux-only detached HMAC-SHA-256 authentication utility; authenticates files without encrypting them. |
| [OTP2/versakey](OTP2/versakey/README.md) | Separate Linux-only collection of deterministic key generators. |

The three [OTP2 utilities](OTP2/README.md) are independent Cargo packages.
Deterministic key generation and reversible XOR transformations should not be
confused with the random, single-use pad model implemented by `otp`.

### Other languages

| Project | Language | Overview |
| --- | --- | --- |
| [asmcrypt](asmcrypt/README.md) | x86-64 assembly | Linux file encryption written in NASM, using libsodium for cryptography. |
| [seal](seal/README.md) | Zig | Streaming password encryption using XChaCha20-Poly1305 and Argon2id. |
| [zenc](zenc/zenc/README.md) | Zig | Linux-first streaming password encryption with authenticated metadata and final-block padding. |

These projects have their own build instructions and are outside the Rust
verification described below.

## Build a Rust app

The Rust projects use **edition 2024** and pin **Rust 1.98.1** for reproducible
builds. With Rust installed through rustup, entering an app directory selects
its pinned toolchain. Install any platform prerequisites listed in that app's
README as well.

There is no repository-wide `Cargo.toml`. Build from the directory of the app
you want, for example:

```console
git clone https://github.com/knightway8/rust-encryption.git
cd rust-encryption/x2
cargo build --locked --release --bins
cargo test --locked --all-targets
```

Executables appear in that project's `target/release/` directory, with `.exe`
on Windows. For a collection such as `e-tools`, run Cargo from its workspace
directory and use `--workspace --bins` to build all its executables.

Read the app's README before running it: password prompts, key locations,
filenames, output replacement, and pad consumption differ between tools.

### Platform notes

- **ezcrypt** requires Windows 11 and supported local fixed NTFS storage.
- **secure** and all three **OTP2** utilities require Linux.
- **cascade** supports file operations on Unix; Windows builds reject those
  operations even though its portable cryptographic tests can run there.
- Other apps have their own platform and filesystem details in their READMEs.

## Tests and verification

The [Rust verification report](RUST_VERIFICATION.md) records the Rust 1.98.1
update across **67 application packages**, including the 50 `e-tools` members.
It reports **4,889 passing Windows tests**, plus formatting, Clippy, and
documentation checks. Linux-only packages passed compilation and lint checks;
their runtime tests still require a Linux environment.

To repeat the available checks, run the appropriate script from the repository
root:

```powershell
# Windows; includes the deliberately slow tests
.\verify-rust.ps1
```

```bash
# Linux; also builds release executables
bash verify-rust.sh
```

See the report for selecting individual projects, skipping slow Windows tests,
and the precise limits of the recorded results.

## Learning and experimenting

These are educational projects, including custom formats and experimental
constructions. Passing tests is not an independent cryptographic audit. Read
each app's security notes and use copies of files while experimenting.

Small, focused apps can also be useful for learning with an AI coding assistant.
When asking one to review or customize an app, describe your threat model: what
you need to protect, who might access the files or keys, and where the app will
run. Review the resulting code and tests rather than assuming generated code
is secure.
