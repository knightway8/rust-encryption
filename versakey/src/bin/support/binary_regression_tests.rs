//! Shared regression coverage for every shipped binary wrapper.
//!
//! This lives below `src/bin/support` so Cargo does not mistake it for another
//! executable. Each binary gets its own lazy fixture: the fixture performs the
//! minimum four production-strength derivations needed to cover all input
//! separation and file replacement properties, while the individual tests
//! remain focused and independently named.

use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;

use versakey::{GeneratorConfig, GeneratorSuite, OUTPUT_FILENAME, generate_key_file_with_suite};
use zeroize::Zeroizing;

const FIXTURE_PASSWORD: &str = "application compatibility fixture";
const DIFFERENT_PASSWORD: &str = "application compatibility fixture changed";
pub(crate) const FIXTURE_SIZE: u64 = 64;
pub(crate) const DIFFERENT_SIZE: u64 = FIXTURE_SIZE + 1;
pub(crate) const EXISTING_KEY_SIZE: usize = 4_096;
pub(crate) const EXISTING_KEY_BYTE: u8 = 0xa5;

pub(crate) struct RegressionFixture {
    pub(crate) baseline: Vec<u8>,
    pub(crate) repeated: Vec<u8>,
    pub(crate) different_password: Vec<u8>,
    pub(crate) different_size: Vec<u8>,
    pub(crate) initial_existing_size: u64,
    pub(crate) output_path: PathBuf,
    pub(crate) returned_paths: [PathBuf; 4],
    pub(crate) entry_counts: [usize; 4],
    pub(crate) final_file_name: Option<OsString>,
}

impl RegressionFixture {
    pub(crate) fn build(suite: GeneratorSuite, config: GeneratorConfig<'static>) -> Self {
        let directory = tempfile::tempdir().expect("create binary regression directory");
        let output_path = directory.path().join(OUTPUT_FILENAME);
        fs::write(&output_path, vec![EXISTING_KEY_BYTE; EXISTING_KEY_SIZE])
            .expect("create longer existing key.key");
        let initial_existing_size = fs::metadata(&output_path)
            .expect("inspect longer existing key.key")
            .len();

        let (baseline_path, baseline, baseline_entries) = generate_and_read(
            directory.path(),
            FIXTURE_PASSWORD,
            FIXTURE_SIZE,
            config,
            suite,
        );
        let (repeated_path, repeated, repeated_entries) = generate_and_read(
            directory.path(),
            FIXTURE_PASSWORD,
            FIXTURE_SIZE,
            config,
            suite,
        );
        let (different_password_path, different_password, different_password_entries) =
            generate_and_read(
                directory.path(),
                DIFFERENT_PASSWORD,
                FIXTURE_SIZE,
                config,
                suite,
            );
        let (different_size_path, different_size, different_size_entries) = generate_and_read(
            directory.path(),
            FIXTURE_PASSWORD,
            DIFFERENT_SIZE,
            config,
            suite,
        );

        let final_file_name = different_size_path.file_name().map(OsString::from);
        Self {
            baseline,
            repeated,
            different_password,
            different_size,
            initial_existing_size,
            output_path,
            returned_paths: [
                baseline_path,
                repeated_path,
                different_password_path,
                different_size_path,
            ],
            entry_counts: [
                baseline_entries,
                repeated_entries,
                different_password_entries,
                different_size_entries,
            ],
            final_file_name,
        }
    }
}

fn generate_and_read(
    directory: &std::path::Path,
    password: &str,
    size: u64,
    config: GeneratorConfig<'static>,
    suite: GeneratorSuite,
) -> (PathBuf, Vec<u8>, usize) {
    let path = generate_key_file_with_suite(
        directory,
        Zeroizing::new(password.to_owned()),
        size,
        config,
        suite,
    )
    .expect("generate binary regression key");
    let bytes = fs::read(&path).expect("read binary regression key");
    let entry_count = fs::read_dir(directory)
        .expect("inspect binary regression directory")
        .count();
    (path, bytes, entry_count)
}

macro_rules! define_binary_regression_tests {
    (
        expected_suite: $expected_suite:expr,
        expected_domain: $expected_domain:expr,
        known_answer: $known_answer:expr $(,)?
    ) => {
        const KNOWN_ANSWER: [u8; 64] = $known_answer;

        fn regression_fixture() -> &'static $crate::binary_test_support::RegressionFixture {
            static FIXTURE: std::sync::OnceLock<$crate::binary_test_support::RegressionFixture> =
                std::sync::OnceLock::new();
            FIXTURE.get_or_init(|| {
                $crate::binary_test_support::RegressionFixture::build(
                    super::GENERATOR_SUITE,
                    super::GENERATOR_CONFIG,
                )
            })
        }

        #[test]
        fn application_constants_config_and_suite_are_frozen() {
            assert_eq!(
                super::APPLICATION_SALT,
                b"versakey application salt 2026-08-11 v1"
            );
            assert_eq!(
                super::APPLICATION_PEPPER,
                b"VersaKey-build-pepper-change-me-v1"
            );
            assert_eq!(super::KEY_DOMAIN, $expected_domain);
            assert_eq!(super::GENERATOR_SUITE, $expected_suite);

            assert_eq!(
                super::GENERATOR_CONFIG.application_salt,
                super::APPLICATION_SALT
            );
            assert_eq!(
                super::GENERATOR_CONFIG.application_pepper,
                super::APPLICATION_PEPPER
            );
            assert_eq!(super::GENERATOR_CONFIG.domain, super::KEY_DOMAIN);
            assert!(!super::GENERATOR_CONFIG.application_salt.is_empty());
            assert!(!super::GENERATOR_CONFIG.application_pepper.is_empty());
            assert!(!super::GENERATOR_CONFIG.domain.is_empty());
            assert_ne!(
                super::GENERATOR_CONFIG.application_salt,
                super::GENERATOR_CONFIG.application_pepper
            );
            assert_ne!(
                super::GENERATOR_CONFIG.application_salt,
                super::GENERATOR_CONFIG.domain
            );
            assert_ne!(
                super::GENERATOR_CONFIG.application_pepper,
                super::GENERATOR_CONFIG.domain
            );
        }

        #[test]
        fn application_constants_produce_frozen_known_answer() {
            assert_eq!(regression_fixture().baseline, KNOWN_ANSWER);
        }

        #[test]
        fn repeated_generation_is_deterministic() {
            let fixture = regression_fixture();
            assert_eq!(fixture.repeated, fixture.baseline);
        }

        #[test]
        fn exact_length_atomically_replaces_a_longer_existing_key() {
            let fixture = regression_fixture();
            assert_eq!(
                fixture.initial_existing_size,
                $crate::binary_test_support::EXISTING_KEY_SIZE as u64
            );
            assert_eq!(
                fixture.baseline.len(),
                $crate::binary_test_support::FIXTURE_SIZE as usize
            );
            assert!(
                fixture
                    .baseline
                    .iter()
                    .any(|&byte| byte != $crate::binary_test_support::EXISTING_KEY_BYTE)
            );
            assert!(
                fixture
                    .returned_paths
                    .iter()
                    .all(|path| path == &fixture.output_path)
            );
            assert!(fixture.entry_counts.iter().all(|&count| count == 1));
            assert_eq!(
                fixture.final_file_name.as_deref(),
                Some(std::ffi::OsStr::new(versakey::OUTPUT_FILENAME))
            );
        }

        #[test]
        fn changing_password_changes_output() {
            let fixture = regression_fixture();
            assert_eq!(fixture.different_password.len(), fixture.baseline.len());
            assert_ne!(fixture.different_password, fixture.baseline);
        }

        #[test]
        fn changing_requested_size_changes_the_stream_prefix() {
            let fixture = regression_fixture();
            assert_eq!(
                fixture.different_size.len(),
                $crate::binary_test_support::DIFFERENT_SIZE as usize
            );
            assert_ne!(
                fixture.baseline.as_slice(),
                &fixture.different_size[..fixture.baseline.len()]
            );
            assert!(!fixture.different_size.starts_with(&fixture.baseline));
        }
    };
}

pub(crate) use define_binary_regression_tests;
