use std::process::ExitCode;
use versakey::cli::run_cli;
use versakey::{GeneratorConfig, GeneratorSuite};

// Changing any value changes the output. Keep these exact values for the
// original VersaKey compatibility contract.
const APPLICATION_SALT: &[u8] = b"versakey application salt 2026-08-11 v1";
const APPLICATION_PEPPER: &[u8] = b"VersaKey-build-pepper-change-me-v1";
const KEY_DOMAIN: &[u8] = b"versakey/key-file/aes256-ctr/v1";
const GENERATOR_SUITE: GeneratorSuite = GeneratorSuite::Argon2idAes256Ctr;
const GENERATOR_CONFIG: GeneratorConfig<'static> = GeneratorConfig {
    application_salt: APPLICATION_SALT,
    application_pepper: APPLICATION_PEPPER,
    domain: KEY_DOMAIN,
};

fn main() -> ExitCode {
    run_cli(GENERATOR_SUITE, GENERATOR_CONFIG)
}

#[cfg(test)]
#[path = "bin/support/binary_regression_tests.rs"]
mod binary_test_support;

#[cfg(test)]
mod tests {
    use super::GeneratorSuite;

    super::binary_test_support::define_binary_regression_tests!(
        expected_suite: GeneratorSuite::Argon2idAes256Ctr,
        expected_domain: b"versakey/key-file/aes256-ctr/v1",
        known_answer: [
                144, 129, 36, 143, 81, 37, 153, 95, 36, 50, 200, 67, 211, 94, 54, 137, 115, 251,
                54, 75, 215, 49, 172, 129, 143, 184, 175, 125, 104, 22, 118, 171, 211, 150, 14,
                128, 153, 149, 229, 253, 206, 101, 200, 148, 186, 69, 133, 115, 84, 171, 201, 8,
                248, 121, 144, 94, 122, 153, 112, 201, 190, 78, 55, 49,
        ],
    );
}
