#[path = "common/process.rs"]
mod process;

use process::{assert_failure_contains, assert_success, run, run_in, stdout};
use std::fmt::Write as _;
use std::fs;

const BINARY: &str = env!("CARGO_BIN_EXE_txt2key");

#[test]
fn reports_usage_for_wrong_argument_counts() {
    for arguments in [Vec::<&str>::new(), vec!["input", "extra"]] {
        assert_failure_contains(
            &run(BINARY, &arguments),
            "usage: txt2key [decimal text file]",
        );
    }
}

#[test]
fn converts_documented_decimal_text_to_binary() {
    let directory = tempfile::tempdir().expect("create txt2key test directory");
    fs::write(
        directory.path().join("source.txt"),
        b"23,\n255,\n53,\n9,\n5\n",
    )
    .expect("write decimal text");
    let output = run_in(BINARY, directory.path(), &["source.txt"]);
    assert_success(&output);
    assert_eq!(
        fs::read(directory.path().join("txt2key.key")).expect("read binary key"),
        [23_u8, 255, 53, 9, 5]
    );
    assert_eq!(
        fs::read(directory.path().join("source.txt")).expect("read unchanged decimal source"),
        b"23,\n255,\n53,\n9,\n5\n"
    );
    assert_eq!(
        fs::read_dir(directory.path())
            .expect("list txt2key test directory")
            .count(),
        2,
        "successful conversion left a temporary artifact"
    );
}

#[test]
fn accepts_plain_lines_whitespace_commas_and_crlf() {
    let directory = tempfile::tempdir().expect("create txt2key test directory");
    fs::write(
        directory.path().join("variants.txt"),
        b" 0, \r\n\t1\r\n 127 ,\n254\n255,\n",
    )
    .expect("write syntax variants");
    assert_success(&run_in(BINARY, directory.path(), &["variants.txt"]));
    assert_eq!(
        fs::read(directory.path().join("txt2key.key")).expect("read binary key"),
        [0_u8, 1, 127, 254, 255]
    );
}

#[test]
fn accepts_a_final_line_without_a_newline() {
    let directory = tempfile::tempdir().expect("create txt2key test directory");
    fs::write(directory.path().join("source.txt"), b"1,\n2,\n3")
        .expect("write unterminated final line");
    assert_success(&run_in(BINARY, directory.path(), &["source.txt"]));
    assert_eq!(
        fs::read(directory.path().join("txt2key.key")).expect("read binary key"),
        [1_u8, 2, 3]
    );
}

#[test]
fn converts_an_empty_file_to_an_empty_file() {
    let directory = tempfile::tempdir().expect("create txt2key test directory");
    fs::write(directory.path().join("empty.txt"), []).expect("write empty text");
    assert_success(&run_in(BINARY, directory.path(), &["empty.txt"]));
    assert!(
        fs::read(directory.path().join("txt2key.key"))
            .expect("read empty key")
            .is_empty()
    );
}

#[test]
fn rejects_malformed_values_without_leaving_output() {
    let invalid_inputs: [&[u8]; 11] = [
        b"256\n",
        b"-1\n",
        b"+1\n",
        b"1, 2\n",
        b"1,2\n",
        b"12 3\n",
        b"1\n\n2\n",
        b"0000\n",
        b"1\nhello\n",
        b",1\n",
        b"1,,\n",
    ];
    for (index, contents) in invalid_inputs.into_iter().enumerate() {
        let directory = tempfile::tempdir().expect("create txt2key test directory");
        fs::write(directory.path().join("invalid.txt"), contents).expect("write invalid text");
        let output = run_in(BINARY, directory.path(), &["invalid.txt"]);
        assert_failure_contains(&output, "error:");
        assert!(
            !directory.path().join("txt2key.key").exists(),
            "invalid case {index} left an output"
        );
    }
}

#[test]
fn streams_large_decimal_input() {
    let directory = tempfile::tempdir().expect("create txt2key test directory");
    let count = 300_000_usize;
    let mut text = String::with_capacity(count * 5);
    let mut expected = Vec::with_capacity(count);
    for index in 0..count {
        let value = u8::try_from(index % 256).expect("test byte fits in u8");
        expected.push(value);
        if index + 1 == count {
            writeln!(text, "{value}").expect("write test decimal line");
        } else {
            writeln!(text, "{value},").expect("write test decimal line");
        }
    }
    fs::write(directory.path().join("large.txt"), text).expect("write large decimal text");
    assert_success(&run_in(BINARY, directory.path(), &["large.txt"]));
    assert_eq!(
        fs::read(directory.path().join("txt2key.key")).expect("read large key"),
        expected
    );
}

#[test]
fn reports_the_source_and_fixed_output_names() {
    let directory = tempfile::tempdir().expect("create txt2key test directory");
    fs::write(directory.path().join("named.txt"), b"7\n").expect("write decimal text");
    let output = run_in(BINARY, directory.path(), &["named.txt"]);
    assert_success(&output);
    assert!(stdout(&output).contains("restored decimal key text 'named.txt' to txt2key.key"));
}

#[test]
fn rejects_a_missing_input_without_output() {
    let directory = tempfile::tempdir().expect("create txt2key test directory");
    let output = run_in(BINARY, directory.path(), &["missing.txt"]);
    assert_failure_contains(&output, "cannot open input file");
    assert!(!directory.path().join("txt2key.key").exists());
}

#[test]
fn rejects_nonlocal_and_nonportable_input_names() {
    for input in ["folder/key", "folder\\key", "bad:name", "NUL", "trailing."] {
        let directory = tempfile::tempdir().expect("create txt2key test directory");
        let output = run_in(BINARY, directory.path(), &[input]);
        assert_failure_contains(&output, "error:");
        assert!(!directory.path().join("txt2key.key").exists());
    }
}

#[test]
fn refuses_to_overwrite_the_fixed_output() {
    let directory = tempfile::tempdir().expect("create txt2key test directory");
    fs::write(directory.path().join("source.txt"), b"1\n2\n3\n").expect("write decimal text");
    fs::write(directory.path().join("txt2key.key"), b"preserve me").expect("write existing output");
    let output = run_in(BINARY, directory.path(), &["source.txt"]);
    assert_failure_contains(&output, "refusing to overwrite existing file");
    assert_eq!(
        fs::read(directory.path().join("txt2key.key")).expect("read preserved output"),
        b"preserve me"
    );
}
#[test]
fn malformed_data_after_a_written_chunk_leaves_no_output_or_temporary_file() {
    let directory = tempfile::tempdir().expect("create late-malformed txt2key test directory");
    let mut text = "1\n".repeat(x3x::CHUNK_SIZE + 1);
    text.push_str("999\n");
    fs::write(directory.path().join("late-invalid.txt"), text)
        .expect("write late-malformed decimal text");

    let output = run_in(BINARY, directory.path(), &["late-invalid.txt"]);
    assert_failure_contains(&output, "greater than 255");
    assert!(!directory.path().join("txt2key.key").exists());
    assert_eq!(
        fs::read_dir(directory.path())
            .expect("list late-malformed txt2key directory")
            .count(),
        1,
        "failed conversion left a temporary artifact"
    );
}

#[test]
fn accepts_three_digit_zero_padded_values() {
    let directory = tempfile::tempdir().expect("create txt2key test directory");
    fs::write(
        directory.path().join("source.txt"),
        b"000,\n001,\n009,\n255\n",
    )
    .expect("write text");
    assert_success(&run_in(BINARY, directory.path(), &["source.txt"]));
    assert_eq!(
        fs::read(directory.path().join("txt2key.key")).expect("read key"),
        [0_u8, 1, 9, 255]
    );
}

#[test]
fn accepts_tabs_around_values_and_commas() {
    let directory = tempfile::tempdir().expect("create txt2key test directory");
    fs::write(directory.path().join("source.txt"), b"\t1\t,\t\n\t2\t\n").expect("write text");
    assert_success(&run_in(BINARY, directory.path(), &["source.txt"]));
    assert_eq!(
        fs::read(directory.path().join("txt2key.key")).expect("read key"),
        [1_u8, 2]
    );
}

#[test]
fn rejects_a_blank_first_line() {
    let directory = tempfile::tempdir().expect("create txt2key test directory");
    fs::write(directory.path().join("source.txt"), b"\n1\n").expect("write text");
    let output = run_in(BINARY, directory.path(), &["source.txt"]);
    assert_failure_contains(&output, "blank lines are not allowed");
    assert!(!directory.path().join("txt2key.key").exists());
}

#[test]
fn rejects_a_whitespace_only_final_line() {
    let directory = tempfile::tempdir().expect("create txt2key test directory");
    fs::write(directory.path().join("source.txt"), b"1\n   ").expect("write text");
    let output = run_in(BINARY, directory.path(), &["source.txt"]);
    assert_failure_contains(&output, "does not contain a decimal byte");
    assert!(!directory.path().join("txt2key.key").exists());
}

#[test]
fn rejects_non_ascii_digits() {
    let directory = tempfile::tempdir().expect("create txt2key test directory");
    fs::write(directory.path().join("source.txt"), "１２\n".as_bytes()).expect("write text");
    let output = run_in(BINARY, directory.path(), &["source.txt"]);
    assert_failure_contains(&output, "expected one unsigned decimal byte");
    assert!(!directory.path().join("txt2key.key").exists());
}

#[test]
fn rejects_a_directory_input_without_output() {
    let directory = tempfile::tempdir().expect("create txt2key test directory");
    fs::create_dir(directory.path().join("input")).expect("create input directory");
    let output = run_in(BINARY, directory.path(), &["input"]);
    assert_failure_contains(&output, "error:");
    assert!(!directory.path().join("txt2key.key").exists());
}

#[test]
fn preserves_a_directory_at_the_output_name() {
    let directory = tempfile::tempdir().expect("create txt2key test directory");
    fs::write(directory.path().join("source.txt"), b"1\n").expect("write text");
    fs::create_dir(directory.path().join("txt2key.key")).expect("create output directory");
    let output = run_in(BINARY, directory.path(), &["source.txt"]);
    assert_failure_contains(&output, "refusing to overwrite existing file");
    assert!(directory.path().join("txt2key.key").is_dir());
}

#[test]
fn refuses_a_hard_link_at_the_output_name() {
    let directory = tempfile::tempdir().expect("create txt2key hard-link test directory");
    fs::write(directory.path().join("source.txt"), b"1\n").expect("write text");
    fs::write(directory.path().join("sentinel"), b"preserve me").expect("write sentinel");
    fs::hard_link(
        directory.path().join("sentinel"),
        directory.path().join("txt2key.key"),
    )
    .expect("create hard-link output");
    let output = run_in(BINARY, directory.path(), &["source.txt"]);
    assert_failure_contains(&output, "refusing to overwrite existing file");
    assert_eq!(
        fs::read(directory.path().join("sentinel")).expect("read sentinel"),
        b"preserve me"
    );
}

#[test]
fn success_emits_no_stderr() {
    let directory = tempfile::tempdir().expect("create txt2key test directory");
    fs::write(directory.path().join("source.txt"), b"1\n").expect("write text");
    let output = run_in(BINARY, directory.path(), &["source.txt"]);
    assert_success(&output);
    assert!(process::stderr(&output).is_empty());
}
