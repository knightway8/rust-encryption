#!/usr/bin/env bash
# Run from any directory on Linux. Each OTP2 package keeps its own build output.
set -uo pipefail
root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
projects=(algos be cascade e-tools filecrypt multicrypt otp otp1 secure tf1024 threefish1024 versakey x2 x5x OTP2/otp2 OTP2/otp2-auth OTP2/versakey)
if (( $# )); then projects=("$@"); fi
failed=()
for project in "${projects[@]}"; do
    printf '\nVerifying %s with Rust 1.98.1\n' "$project"
    if ! (
        cd -- "$root/$project" &&
        cargo +1.98.1 fmt --all -- --check &&
        cargo +1.98.1 clippy --locked --workspace --all-targets --all-features -- -D warnings &&
        cargo +1.98.1 test --locked --workspace --all-targets --all-features --no-fail-fast -- --include-ignored --test-threads=2 &&
        RUSTDOCFLAGS='-D warnings' cargo +1.98.1 doc --locked --workspace --no-deps &&
        cargo +1.98.1 build --locked --workspace --release --bins
    ); then
        failed+=("$project")
    fi
done
printf '\nezcrypt is Windows-only and is covered by verify-rust.ps1.\n'
if (( ${#failed[@]} )); then
    printf 'Verification failed: %s\n' "${failed[*]}" >&2
    exit 1
fi
printf 'All selected projects passed.\n'
