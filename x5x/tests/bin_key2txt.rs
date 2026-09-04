#[path = "common/process.rs"]
mod process;

use process::{assert_failure_contains, assert_success, run, run_in, stdout};
use std::fs;

const BINARY: &str = env!("CARGO_BIN_EXE_key2txt");

#[test]
fn reports_usage_for_wrong_argument_counts() {
    for arguments in [Vec::<&str>::new(), vec!["input", "extra"]] {
        assert_failure_contains(&run(BINARY, &arguments), "usage: key2txt [binary key file]");
    }
}

#[test]
fn converts_a_binary_key_to_documented_decimal_text() {
    let directory = tempfile::tempdir().expect("create key2txt test directory");
    fs::write(directory.path().join("source.key"), [23_u8, 255, 53, 9, 5])
        .expect("write binary key");
    let output = run_in(BINARY, directory.path(), &["source.key"]);
    assert_success(&output);
    assert_eq!(
        fs::read(directory.path().join("key2txt.txt")).expect("read decimal text"),
        b"23,\n255,\n53,\n9,\n5\n"
    );
    assert_eq!(
        fs::read(directory.path().join("source.key")).expect("read unchanged source key"),
        [23_u8, 255, 53, 9, 5]
    );
    assert_eq!(
        fs::read_dir(directory.path())
            .expect("list key2txt test directory")
            .count(),
        2,
        "successful conversion left a temporary artifact"
    );
}

#[test]
fn converts_a_short_unicode_filename_without_panicking() {
    let directory = tempfile::tempdir().expect("create key2txt test directory");
    fs::write(directory.path().join("abé"), [1_u8, 2, 3]).expect("write Unicode-named key");

    let output = run_in(BINARY, directory.path(), &["abé"]);

    assert_success(&output);
    assert_eq!(
        fs::read(directory.path().join("key2txt.txt")).expect("read converted Unicode-named key"),
        b"1,\n2,\n3\n"
    );
}

#[test]
fn converts_every_possible_byte_value() {
    let directory = tempfile::tempdir().expect("create key2txt test directory");
    let input: Vec<u8> = (0_u8..=u8::MAX).collect();
    fs::write(directory.path().join("all.key"), input).expect("write all byte values");
    assert_success(&run_in(BINARY, directory.path(), &["all.key"]));

    let expected = (0_u16..=u16::from(u8::MAX))
        .map(|value| {
            if value == u16::from(u8::MAX) {
                format!("{value}\n")
            } else {
                format!("{value},\n")
            }
        })
        .collect::<String>();
    assert_eq!(
        fs::read_to_string(directory.path().join("key2txt.txt")).expect("read converted values"),
        expected
    );
}

#[test]
fn converts_an_empty_file_to_an_empty_file() {
    let directory = tempfile::tempdir().expect("create key2txt test directory");
    fs::write(directory.path().join("empty.key"), []).expect("write empty key");
    assert_success(&run_in(BINARY, directory.path(), &["empty.key"]));
    assert!(
        fs::read(directory.path().join("key2txt.txt"))
            .expect("read converted empty key")
            .is_empty()
    );
}

#[test]
fn streams_across_the_internal_buffer_boundary() {
    let directory = tempfile::tempdir().expect("create key2txt test directory");
    let input: Vec<u8> = (0..x3x::CHUNK_SIZE + 31)
        .map(|index| u8::try_from(index % 256).expect("test byte fits in u8"))
        .collect();
    fs::write(directory.path().join("large.key"), &input).expect("write large key");
    assert_success(&run_in(BINARY, directory.path(), &["large.key"]));
    let text =
        fs::read_to_string(directory.path().join("key2txt.txt")).expect("read large conversion");
    assert_eq!(text.lines().count(), input.len());
    assert!(text.starts_with("0,\n1,\n2,\n"));
    assert!(text.ends_with(&format!("{}\n", input[input.len() - 1])));
}

#[test]
fn reports_the_source_and_fixed_output_names() {
    let directory = tempfile::tempdir().expect("create key2txt test directory");
    fs::write(directory.path().join("named.key"), [1_u8]).expect("write source key");
    let output = run_in(BINARY, directory.path(), &["named.key"]);
    assert_success(&output);
    assert!(stdout(&output).contains("converted binary key 'named.key' to key2txt.txt"));
}

#[test]
fn rejects_a_missing_input_without_output() {
    let directory = tempfile::tempdir().expect("create key2txt test directory");
    let output = run_in(BINARY, directory.path(), &["missing.key"]);
    assert_failure_contains(&output, "cannot open input file");
    assert!(!directory.path().join("key2txt.txt").exists());
}

#[test]
fn rejects_nonlocal_and_nonportable_input_names() {
    for input in [
        "folder/key",
        "folder\\key",
        "bad:name",
        "NUL",
        "COM¹",
        "trailing.",
    ] {
        let directory = tempfile::tempdir().expect("create key2txt test directory");
        let output = run_in(BINARY, directory.path(), &[input]);
        assert_failure_contains(&output, "error:");
        assert!(!directory.path().join("key2txt.txt").exists());
    }
}

#[test]
fn refuses_to_overwrite_the_fixed_output() {
    let directory = tempfile::tempdir().expect("create key2txt test directory");
    fs::write(directory.path().join("source.key"), [1_u8, 2, 3]).expect("write source key");
    fs::write(directory.path().join("key2txt.txt"), b"preserve me").expect("write existing output");
    let output = run_in(BINARY, directory.path(), &["source.key"]);
    assert_failure_contains(&output, "refusing to overwrite existing file");
    assert_eq!(
        fs::read(directory.path().join("key2txt.txt")).expect("read preserved output"),
        b"preserve me"
    );
}

#[test]
fn converts_a_single_zero_without_a_comma() {
    let directory = tempfile::tempdir().expect("create key2txt test directory");
    fs::write(directory.path().join("zero.key"), [0_u8]).expect("write key");
    assert_success(&run_in(BINARY, directory.path(), &["zero.key"]));
    assert_eq!(
        fs::read(directory.path().join("key2txt.txt")).expect("read text"),
        b"0\n"
    );
}

#[test]
fn converts_representative_decimal_widths() {
    let directory = tempfile::tempdir().expect("create key2txt test directory");
    fs::write(
        directory.path().join("widths.key"),
        [9_u8, 10, 99, 100, 255],
    )
    .expect("write key");
    assert_success(&run_in(BINARY, directory.path(), &["widths.key"]));
    assert_eq!(
        fs::read(directory.path().join("key2txt.txt")).expect("read text"),
        b"9,\n10,\n99,\n100,\n255\n"
    );
}

#[test]
fn accepts_a_filename_beginning_with_a_hyphen() {
    let directory = tempfile::tempdir().expect("create key2txt test directory");
    fs::write(directory.path().join("-key"), [1_u8, 2]).expect("write key");
    assert_success(&run_in(BINARY, directory.path(), &["-key"]));
    assert_eq!(
        fs::read(directory.path().join("key2txt.txt")).expect("read text"),
        b"1,\n2\n"
    );
}

#[test]
fn success_emits_no_stderr() {
    let directory = tempfile::tempdir().expect("create key2txt test directory");
    fs::write(directory.path().join("key"), [1_u8]).expect("write key");
    let output = run_in(BINARY, directory.path(), &["key"]);
    assert_success(&output);
    assert!(process::stderr(&output).is_empty());
}

#[test]
fn missing_input_failure_emits_no_stdout() {
    let output = run(BINARY, &["missing"]);
    assert!(!output.status.success());
    assert!(process::stdout(&output).is_empty());
}

#[test]
fn rejects_a_directory_input_without_output() {
    let directory = tempfile::tempdir().expect("create key2txt test directory");
    fs::create_dir(directory.path().join("input")).expect("create input directory");
    let output = run_in(BINARY, directory.path(), &["input"]);
    assert_failure_contains(&output, "error:");
    assert!(!directory.path().join("key2txt.txt").exists());
}

#[test]
fn preserves_a_directory_at_the_output_name() {
    let directory = tempfile::tempdir().expect("create key2txt test directory");
    fs::write(directory.path().join("key"), [1_u8]).expect("write key");
    fs::create_dir(directory.path().join("key2txt.txt")).expect("create output directory");
    let output = run_in(BINARY, directory.path(), &["key"]);
    assert_failure_contains(&output, "refusing to overwrite existing file");
    assert!(directory.path().join("key2txt.txt").is_dir());
}

#[test]
fn refuses_a_hard_link_at_the_output_name() {
    let directory = tempfile::tempdir().expect("create key2txt hard-link test directory");
    fs::write(directory.path().join("key"), [1_u8]).expect("write key");
    fs::write(directory.path().join("sentinel"), b"preserve me").expect("write sentinel");
    fs::hard_link(
        directory.path().join("sentinel"),
        directory.path().join("key2txt.txt"),
    )
    .expect("create hard-link output");
    let output = run_in(BINARY, directory.path(), &["key"]);
    assert_failure_contains(&output, "refusing to overwrite existing file");
    assert_eq!(
        fs::read(directory.path().join("sentinel")).expect("read sentinel"),
        b"preserve me"
    );
}

#[test]
fn successful_conversion_preserves_unrelated_files() {
    let directory = tempfile::tempdir().expect("create key2txt test directory");
    fs::write(directory.path().join("key"), [1_u8]).expect("write key");
    fs::write(directory.path().join("unrelated"), b"preserve me").expect("write unrelated");
    assert_success(&run_in(BINARY, directory.path(), &["key"]));
    assert_eq!(
        fs::read(directory.path().join("unrelated")).expect("read unrelated"),
        b"preserve me"
    );
}

#[test]
fn conversion_is_deterministic() {
    let first = tempfile::tempdir().expect("create first key2txt test directory");
    let second = tempfile::tempdir().expect("create second key2txt test directory");
    let key = [0_u8, 1, 127, 128, 255];
    fs::write(first.path().join("key"), key).expect("write first key");
    fs::write(second.path().join("key"), key).expect("write second key");
    assert_success(&run_in(BINARY, first.path(), &["key"]));
    assert_success(&run_in(BINARY, second.path(), &["key"]));
    assert_eq!(
        fs::read(first.path().join("key2txt.txt")).expect("read first text"),
        fs::read(second.path().join("key2txt.txt")).expect("read second text")
    );
}

#[test]
fn source_key_is_unchanged_after_conversion() {
    let directory = tempfile::tempdir().expect("create key2txt test directory");
    let key = [0_u8, 17, 255, 42];
    fs::write(directory.path().join("key"), key).expect("write key");
    assert_success(&run_in(BINARY, directory.path(), &["key"]));
    assert_eq!(
        fs::read(directory.path().join("key")).expect("read source key"),
        key
    );
}
