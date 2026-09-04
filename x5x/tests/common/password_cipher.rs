#![allow(dead_code)]

mod process;

use process::{assert_failure_contains, run};
use std::fs;

#[derive(Clone, Copy)]
pub struct PasswordCipherApp {
    pub command: &'static str,
    pub binary: &'static str,
}

fn expected_usage(app: PasswordCipherApp) -> String {
    format!("usage: {} [E or D] [filename] [output-file]", app.command)
}

pub fn reports_usage_without_arguments(app: PasswordCipherApp) {
    assert_failure_contains(&run(app.binary, &[]), &expected_usage(app));
}

pub fn reports_usage_with_one_argument(app: PasswordCipherApp) {
    assert_failure_contains(&run(app.binary, &["E"]), &expected_usage(app));
}

pub fn reports_usage_with_two_arguments(app: PasswordCipherApp) {
    assert_failure_contains(&run(app.binary, &["E", "input"]), &expected_usage(app));
}

pub fn reports_usage_with_extra_arguments(app: PasswordCipherApp) {
    assert_failure_contains(
        &run(app.binary, &["E", "input", "output", "extra"]),
        &expected_usage(app),
    );
}

pub fn rejects_lowercase_operations(app: PasswordCipherApp) {
    for operation in ["e", "d"] {
        assert_failure_contains(
            &run(app.binary, &[operation, "input", "output"]),
            "operation must be exactly E or D (uppercase)",
        );
    }
}

pub fn rejects_operation_words(app: PasswordCipherApp) {
    for operation in ["encrypt", "decrypt", "ENCRYPT", "DECRYPT"] {
        assert_failure_contains(
            &run(app.binary, &[operation, "input", "output"]),
            "operation must be exactly E or D (uppercase)",
        );
    }
}

pub fn rejects_empty_or_combined_operations(app: PasswordCipherApp) {
    for operation in ["", "ED", "DE", "-"] {
        assert_failure_contains(
            &run(app.binary, &[operation, "input", "output"]),
            "operation must be exactly E or D (uppercase)",
        );
    }
}

pub fn validates_operation_before_touching_files(app: PasswordCipherApp) {
    let directory = tempfile::tempdir().expect("create password CLI test directory");
    std::fs::write(directory.path().join("output"), b"preserve me").expect("write sentinel output");
    let output = process::run_in(
        app.binary,
        directory.path(),
        &["invalid", "missing", "output"],
    );
    assert_failure_contains(&output, "operation must be exactly E or D (uppercase)");
    assert_eq!(
        std::fs::read(directory.path().join("output")).expect("read sentinel output"),
        b"preserve me"
    );
}

pub fn rejects_a_missing_input_before_prompting(app: PasswordCipherApp) {
    let directory = tempfile::tempdir().expect("create password CLI test directory");
    let output = process::run_in(app.binary, directory.path(), &["D", "missing", "output"]);
    assert_failure_contains(&output, "cannot open input file");
    assert!(!directory.path().join("output").exists());
}

pub fn preserves_an_existing_output_before_prompting(app: PasswordCipherApp) {
    let directory = tempfile::tempdir().expect("create password CLI test directory");
    fs::write(directory.path().join("input"), b"ciphertext placeholder").expect("write input");
    fs::write(directory.path().join("output"), b"preserve me").expect("write sentinel output");
    let output = process::run_in(app.binary, directory.path(), &["D", "input", "output"]);
    assert_failure_contains(&output, "refusing to overwrite existing file");
    assert_eq!(
        fs::read(directory.path().join("output")).expect("read sentinel output"),
        b"preserve me"
    );
}

pub fn rejects_nonportable_filenames_before_prompting(app: PasswordCipherApp) {
    let directory = tempfile::tempdir().expect("create password CLI test directory");
    fs::write(directory.path().join("input"), b"ciphertext placeholder").expect("write input");
    for (input, output) in [
        ("folder/input", "output"),
        ("folder\\input", "output"),
        ("input", "folder/output"),
        ("input", "NUL"),
    ] {
        let result = process::run_in(app.binary, directory.path(), &["D", input, output]);
        assert_failure_contains(&result, "error:");
        assert!(!directory.path().join("output").exists());
    }
}

pub fn rejects_a_missing_encryption_input_before_prompting(app: PasswordCipherApp) {
    let directory = tempfile::tempdir().expect("create password CLI test directory");
    let output = process::run_in(app.binary, directory.path(), &["E", "missing", "output"]);
    assert_failure_contains(&output, "cannot open input file");
    assert!(!directory.path().join("output").exists());
}

pub fn preserves_an_existing_encryption_output_before_prompting(app: PasswordCipherApp) {
    let directory = tempfile::tempdir().expect("create password CLI test directory");
    fs::write(directory.path().join("input"), b"plaintext placeholder").expect("write input");
    fs::write(directory.path().join("output"), b"preserve me").expect("write sentinel output");
    let output = process::run_in(app.binary, directory.path(), &["E", "input", "output"]);
    assert_failure_contains(&output, "refusing to overwrite existing file");
    assert_eq!(
        fs::read(directory.path().join("output")).expect("read sentinel output"),
        b"preserve me"
    );
}

pub fn rejects_a_directory_input_before_prompting(app: PasswordCipherApp) {
    let directory = tempfile::tempdir().expect("create password CLI test directory");
    fs::create_dir(directory.path().join("input")).expect("create input directory");
    let output = process::run_in(app.binary, directory.path(), &["D", "input", "output"]);
    let error = process::stderr(&output);
    assert!(
        !output.status.success()
            && (error.contains("cannot open input file")
                || error.contains("is not a regular file")),
        "directory input was not rejected during preflight\nactual stderr:\n{error}"
    );
    assert!(!directory.path().join("output").exists());
}

pub fn preserves_a_directory_at_the_output_name(app: PasswordCipherApp) {
    let directory = tempfile::tempdir().expect("create password CLI test directory");
    fs::write(directory.path().join("input"), b"ciphertext placeholder").expect("write input");
    fs::create_dir(directory.path().join("output")).expect("create output directory");
    let output = process::run_in(app.binary, directory.path(), &["D", "input", "output"]);
    assert_failure_contains(&output, "refusing to overwrite existing file");
    assert!(directory.path().join("output").is_dir());
}

pub fn rejects_parent_traversal_input_before_prompting(app: PasswordCipherApp) {
    let directory = tempfile::tempdir().expect("create password CLI test directory");
    let output = process::run_in(app.binary, directory.path(), &["D", "../input", "output"]);
    assert_failure_contains(&output, "error:");
    assert!(!directory.path().join("output").exists());
}

pub fn rejects_absolute_input_before_prompting(app: PasswordCipherApp) {
    let directory = tempfile::tempdir().expect("create password CLI test directory");
    let absolute = directory.path().join("input");
    fs::write(&absolute, b"ciphertext placeholder").expect("write input");
    let output = process::run_in(
        app.binary,
        directory.path(),
        &["D", absolute.to_str().expect("UTF-8 test path"), "output"],
    );
    assert_failure_contains(&output, "error:");
    assert!(!directory.path().join("output").exists());
}

pub fn rejects_absolute_output_before_prompting(app: PasswordCipherApp) {
    let directory = tempfile::tempdir().expect("create password CLI test directory");
    fs::write(directory.path().join("input"), b"ciphertext placeholder").expect("write input");
    let absolute = directory.path().join("output");
    let output = process::run_in(
        app.binary,
        directory.path(),
        &["D", "input", absolute.to_str().expect("UTF-8 test path")],
    );
    assert_failure_contains(&output, "error:");
    assert!(!absolute.exists());
}

pub fn rejects_trailing_dot_input_before_prompting(app: PasswordCipherApp) {
    let directory = tempfile::tempdir().expect("create password CLI test directory");
    let output = process::run_in(app.binary, directory.path(), &["D", "input.", "output"]);
    assert_failure_contains(&output, "error:");
    assert!(!directory.path().join("output").exists());
}

pub fn rejects_reserved_output_names_before_prompting(app: PasswordCipherApp) {
    let directory = tempfile::tempdir().expect("create password CLI test directory");
    fs::write(directory.path().join("input"), b"ciphertext placeholder").expect("write input");
    for output_name in ["NUL", "AUX", "PRN", "COM1", "LPT9"] {
        let output = process::run_in(app.binary, directory.path(), &["D", "input", output_name]);
        assert_failure_contains(&output, "error:");
    }
}

pub fn failed_preflight_emits_no_success_output(app: PasswordCipherApp) {
    let directory = tempfile::tempdir().expect("create password CLI test directory");
    let output = process::run_in(app.binary, directory.path(), &["D", "missing", "output"]);
    assert_failure_contains(&output, "cannot open input file");
    assert!(
        process::stdout(&output).is_empty(),
        "failed preflight emitted success output"
    );
}
macro_rules! define_password_cipher_tests {
    ($binary:expr, $command:literal) => {
        const APP: $crate::common::PasswordCipherApp = $crate::common::PasswordCipherApp {
            command: $command,
            binary: $binary,
        };

        #[test]
        fn reports_usage_without_arguments() {
            $crate::common::reports_usage_without_arguments(APP);
        }

        #[test]
        fn reports_usage_with_one_argument() {
            $crate::common::reports_usage_with_one_argument(APP);
        }

        #[test]
        fn reports_usage_with_two_arguments() {
            $crate::common::reports_usage_with_two_arguments(APP);
        }

        #[test]
        fn reports_usage_with_extra_arguments() {
            $crate::common::reports_usage_with_extra_arguments(APP);
        }

        #[test]
        fn rejects_lowercase_operations() {
            $crate::common::rejects_lowercase_operations(APP);
        }

        #[test]
        fn rejects_operation_words() {
            $crate::common::rejects_operation_words(APP);
        }

        #[test]
        fn rejects_empty_or_combined_operations() {
            $crate::common::rejects_empty_or_combined_operations(APP);
        }

        #[test]
        fn validates_operation_before_touching_files() {
            $crate::common::validates_operation_before_touching_files(APP);
        }

        #[test]
        fn rejects_a_missing_input_before_prompting() {
            $crate::common::rejects_a_missing_input_before_prompting(APP);
        }

        #[test]
        fn preserves_an_existing_output_before_prompting() {
            $crate::common::preserves_an_existing_output_before_prompting(APP);
        }

        #[test]
        fn rejects_nonportable_filenames_before_prompting() {
            $crate::common::rejects_nonportable_filenames_before_prompting(APP);
        }
        #[test]
        fn rejects_a_missing_encryption_input_before_prompting() {
            $crate::common::rejects_a_missing_encryption_input_before_prompting(APP);
        }

        #[test]
        fn preserves_an_existing_encryption_output_before_prompting() {
            $crate::common::preserves_an_existing_encryption_output_before_prompting(APP);
        }

        #[test]
        fn rejects_a_directory_input_before_prompting() {
            $crate::common::rejects_a_directory_input_before_prompting(APP);
        }

        #[test]
        fn preserves_a_directory_at_the_output_name() {
            $crate::common::preserves_a_directory_at_the_output_name(APP);
        }

        #[test]
        fn rejects_parent_traversal_input_before_prompting() {
            $crate::common::rejects_parent_traversal_input_before_prompting(APP);
        }

        #[test]
        fn rejects_absolute_input_before_prompting() {
            $crate::common::rejects_absolute_input_before_prompting(APP);
        }

        #[test]
        fn rejects_absolute_output_before_prompting() {
            $crate::common::rejects_absolute_output_before_prompting(APP);
        }

        #[test]
        fn rejects_trailing_dot_input_before_prompting() {
            $crate::common::rejects_trailing_dot_input_before_prompting(APP);
        }

        #[test]
        fn rejects_reserved_output_names_before_prompting() {
            $crate::common::rejects_reserved_output_names_before_prompting(APP);
        }

        #[test]
        fn failed_preflight_emits_no_success_output() {
            $crate::common::failed_preflight_emits_no_success_output(APP);
        }
    };
}

pub(crate) use define_password_cipher_tests;
