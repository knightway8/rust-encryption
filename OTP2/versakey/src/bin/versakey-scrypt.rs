use std::process::ExitCode;
use versakey::cli::run_cli;
use versakey::{GeneratorConfig, GeneratorSuite};

const APPLICATION_SALT: &[u8] = b"versakey application salt 2026-08-11 v1";
const APPLICATION_PEPPER: &[u8] = b"VersaKey-build-pepper-change-me-v1";
const KEY_DOMAIN: &[u8] = b"versakey/key-file/scrypt-aes256-ctr/v1";
const GENERATOR_SUITE: GeneratorSuite = GeneratorSuite::ScryptAes256Ctr;
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
        expected_suite: GeneratorSuite::ScryptAes256Ctr,
        expected_domain: b"versakey/key-file/scrypt-aes256-ctr/v1",
        known_answer: [
                178, 180, 153, 225, 64, 190, 31, 96, 102, 35, 101, 219, 231, 53, 51, 159, 131, 229,
                223, 104, 81, 90, 75, 27, 175, 167, 224, 127, 2, 172, 241, 140, 98, 160, 189, 194,
                30, 196, 57, 218, 195, 155, 190, 158, 112, 61, 171, 104, 5, 169, 208, 90, 184, 4,
                133, 37, 156, 186, 18, 9, 131, 33, 220, 253,
        ],
    );
}
