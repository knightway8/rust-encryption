# Per-application test parity

The full x4x implementation has 147 tests attributable to it:

- 126 unit tests in `src/x4x`
- 21 process-level tests in `tests/bin_x4x.rs`

Each of the other 21 applications now also has 147 attributable tests:

- 21 application-specific behavior and security tests in its `tests/bin_*.rs`
  target
- 126 deterministic malformed-input cases in `tests/deep_apps.rs`

The deep corpus checks each application as a real child process. Depending on
the CLI shape, it varies argument arity, operation spellings, numeric syntax,
input names, output names, and which OTP operand is invalid. Every case checks
for the documented failure exit code, an empty standard output stream, the
normal error prefix, absence of panic output, and preservation of files that
must not be changed.

Run the complete deep corpus with:

```text
cargo test --locked --test deep_apps
```

Run the 126-case corpus for one application by using its module name as the
test filter, for example:

```text
cargo test --locked --test deep_apps -- "aes::"
cargo test --locked --test deep_apps -- "keygen::"
```

`test-deep-each.bat` runs each application's deep module independently and
fails fast. `test-each.bat` continues to run the 21 original behavior/security
tests for every binary independently.
