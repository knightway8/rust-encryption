use std::process::ExitCode;
use versakey::cli::run_cli;
use versakey::{GeneratorConfig, GeneratorSuite};

const APPLICATION_SALT: &[u8] = b"versakey application salt 2026-08-11 v1";
const APPLICATION_PEPPER: &[u8] = b"VersaKey-build-pepper-change-me-v1";
const KEY_DOMAIN: &[u8] = b"versakey/key-file/argon2id-blake3-xof/v1";
const GENERATOR_SUITE: GeneratorSuite = GeneratorSuite::Argon2idBlake3Xof;
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
        expected_suite: GeneratorSuite::Argon2idBlake3Xof,
        expected_domain: b"versakey/key-file/argon2id-blake3-xof/v1",
        known_answer: [
            11, 234, 63, 217, 88, 200, 243, 144, 182, 165, 220, 57, 194, 119, 187, 186, 47, 178,
            114, 195, 234, 137, 108, 253, 112, 3, 240, 162, 169, 188, 207, 49, 17, 236, 122, 91,
            223, 207, 205, 78, 55, 112, 95, 136, 121, 159, 52, 39, 142, 90, 137, 89, 113, 224,
            108, 141, 191, 45, 183, 33, 211, 211, 237, 19,
        ],
    );
}
