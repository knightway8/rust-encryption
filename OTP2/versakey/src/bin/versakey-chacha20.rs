use std::process::ExitCode;
use versakey::cli::run_cli;
use versakey::{GeneratorConfig, GeneratorSuite};

const APPLICATION_SALT: &[u8] = b"versakey application salt 2026-08-11 v1";
const APPLICATION_PEPPER: &[u8] = b"VersaKey-build-pepper-change-me-v1";
const KEY_DOMAIN: &[u8] = b"versakey/key-file/argon2id-chacha20/v1";
const GENERATOR_SUITE: GeneratorSuite = GeneratorSuite::Argon2idChaCha20;
const GENERATOR_CONFIG: GeneratorConfig<'static> = GeneratorConfig {
    application_salt: APPLICATION_SALT,
    application_pepper: APPLICATION_PEPPER,
    domain: KEY_DOMAIN,
};

fn main() -> ExitCode {
    run_cli(GENERATOR_SUITE, GENERATOR_CONFIG)
}

#[cfg(test)]
#[path = "support/binary_regression_tests.rs"]
mod binary_test_support;

#[cfg(test)]
mod tests {
    use super::GeneratorSuite;

    super::binary_test_support::define_binary_regression_tests!(
        expected_suite: GeneratorSuite::Argon2idChaCha20,
        expected_domain: b"versakey/key-file/argon2id-chacha20/v1",
        known_answer: [
            52, 31, 122, 47, 231, 144, 90, 180, 32, 206, 106, 80, 79, 14, 19, 205, 111, 185,
            148, 89, 103, 69, 173, 128, 168, 216, 233, 145, 79, 134, 90, 48, 235, 73, 190, 233,
            10, 250, 242, 118, 158, 14, 121, 98, 152, 155, 30, 231, 207, 79, 1, 43, 83, 62, 97,
            215, 79, 94, 40, 35, 136, 95, 239, 219,
        ],
    );
}
