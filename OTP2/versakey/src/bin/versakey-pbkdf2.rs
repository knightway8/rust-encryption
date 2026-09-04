use std::process::ExitCode;
use versakey::cli::run_cli;
use versakey::{GeneratorConfig, GeneratorSuite};

const APPLICATION_SALT: &[u8] = b"versakey application salt 2026-08-11 v1";
const APPLICATION_PEPPER: &[u8] = b"VersaKey-build-pepper-change-me-v1";
const KEY_DOMAIN: &[u8] = b"versakey/key-file/pbkdf2-sha256-aes256-ctr/v1";
const GENERATOR_SUITE: GeneratorSuite = GeneratorSuite::Pbkdf2Sha256Aes256Ctr;
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
        expected_suite: GeneratorSuite::Pbkdf2Sha256Aes256Ctr,
        expected_domain: b"versakey/key-file/pbkdf2-sha256-aes256-ctr/v1",
        known_answer: [
                117, 8, 19, 69, 47, 161, 193, 120, 73, 195, 197, 166, 9, 186, 227, 239, 152, 200,
                241, 133, 54, 234, 87, 173, 197, 65, 198, 42, 24, 133, 219, 101, 192, 164, 209,
                158, 248, 28, 245, 137, 232, 38, 204, 16, 125, 187, 215, 8, 207, 167, 191, 130,
                135, 147, 80, 13, 65, 185, 99, 11, 127, 220, 93, 231,
        ],
    );
}
