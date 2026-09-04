#![allow(dead_code)]

mod process;

use process::{run, run_in, stderr, stdout};
use std::fs;

#[derive(Clone, Copy)]
pub enum DeepCliKind {
    Cipher {
        key_filename: Option<&'static str>,
        key_len: usize,
    },
    Size,
    SingleInput,
    Otp,
}

#[derive(Clone, Copy)]
pub struct DeepCliApp {
    pub binary: &'static str,
    pub kind: DeepCliKind,
}

fn assert_robust_failure(output: &std::process::Output, case: usize) {
    assert_eq!(
        output.status.code(),
        Some(1),
        "deep CLI case {case} returned an unexpected status; stdout: {:?}; stderr: {:?}",
        stdout(output),
        stderr(output)
    );
    assert!(
        stdout(output).is_empty(),
        "deep CLI case {case} emitted stdout on failure: {:?}",
        stdout(output)
    );
    let error = stderr(output);
    assert!(
        error.starts_with("error: "),
        "deep CLI case {case} did not use the normal error channel: {error:?}"
    );
    assert!(
        !error.contains("panicked at") && !error.contains("stack backtrace"),
        "deep CLI case {case} panicked: {error}"
    );
}

fn wrong_arity(app: DeepCliApp, case: usize, valid_arity: usize) {
    let count = if case == valid_arity { case + 16 } else { case };
    let owned = (0..count)
        .map(|index| format!("unexpected-{case}-{index}"))
        .collect::<Vec<_>>();
    let arguments = owned.iter().map(String::as_str).collect::<Vec<_>>();
    assert_robust_failure(&run(app.binary, &arguments), case);
}

fn invalid_operation(case: usize) -> String {
    const SPECIAL: [&str; 16] = [
        "e", "d", "encrypt", "decrypt", "ENCRYPT", "DECRYPT", "ED", "DE", "E ", " D", "+E", "-D",
        "0", "1", "?", "É",
    ];
    SPECIAL.get(case).map_or_else(
        || format!("invalid-operation-{case}"),
        |value| (*value).into(),
    )
}

fn invalid_size(case: usize) -> String {
    let serial = case + 1;
    match case % 10 {
        0 => format!("-{serial}"),
        1 => format!("+{serial}+"),
        2 => format!("{serial}x"),
        3 => format!("0x{serial:x}"),
        4 => format!("{serial}e1"),
        5 => format!("{serial}_{serial}"),
        6 => format!(" {serial}"),
        7 => format!("{serial} "),
        8 => format!("{serial}.0"),
        _ => (u128::from(u64::MAX) + serial as u128).to_string(),
    }
}

fn invalid_filename(case: usize) -> String {
    match case % 12 {
        0 => format!("folder/case-{case}"),
        1 => format!("folder\\case-{case}"),
        2 => format!("case:{case}"),
        3 => format!("case*{case}"),
        4 => format!("case?{case}"),
        5 => format!("case\"{case}"),
        6 => format!("case<{case}"),
        7 => format!("case>{case}"),
        8 => format!("case|{case}"),
        9 => format!("case-{case}."),
        10 => format!("case-{case} "),
        _ => format!("NUL.case-{case}"),
    }
}

fn cipher_case(app: DeepCliApp, case: usize, key_filename: Option<&str>, key_len: usize) {
    if case < 16 {
        wrong_arity(app, case, 3);
        return;
    }

    let corpus_case = case - 16;
    if corpus_case < 48 {
        let operation = invalid_operation(corpus_case);
        let output = run(app.binary, &[&operation, "input", "output"]);
        assert_robust_failure(&output, case);
        return;
    }

    let directory = tempfile::tempdir().expect("create deep cipher CLI test directory");
    fs::write(directory.path().join("input"), b"preserve this input")
        .expect("write deep cipher input");
    if let Some(filename) = key_filename {
        fs::write(directory.path().join(filename), vec![0x5a; key_len])
            .expect("write deep cipher key");
    }

    let path_case = corpus_case - 48;
    let bad_name = invalid_filename(path_case);
    let arguments = if path_case < 31 {
        ["E", bad_name.as_str(), "output"]
    } else {
        ["E", "input", bad_name.as_str()]
    };
    let output = run_in(app.binary, directory.path(), &arguments);
    assert_robust_failure(&output, case);
    assert_eq!(
        fs::read(directory.path().join("input")).expect("read preserved deep cipher input"),
        b"preserve this input"
    );
    assert!(!directory.path().join("output").exists());
}

fn size_case(app: DeepCliApp, case: usize) {
    if case < 16 {
        wrong_arity(app, case, 1);
        return;
    }
    let size = invalid_size(case - 16);
    let directory = tempfile::tempdir().expect("create deep size CLI test directory");
    let output = run_in(app.binary, directory.path(), &[&size]);
    assert_robust_failure(&output, case);
    assert_eq!(
        fs::read_dir(directory.path())
            .expect("list deep size CLI test directory")
            .count(),
        0,
        "deep size case {case} left an output or temporary file"
    );
}

fn single_input_case(app: DeepCliApp, case: usize) {
    if case < 16 {
        wrong_arity(app, case, 1);
        return;
    }
    let input = invalid_filename(case - 16);
    let directory = tempfile::tempdir().expect("create deep converter CLI test directory");
    let output = run_in(app.binary, directory.path(), &[&input]);
    assert_robust_failure(&output, case);
    assert_eq!(
        fs::read_dir(directory.path())
            .expect("list deep converter CLI test directory")
            .count(),
        0,
        "deep converter case {case} left an output or temporary file"
    );
}

fn otp_case(app: DeepCliApp, case: usize) {
    if case < 16 {
        wrong_arity(app, case, 2);
        return;
    }
    let directory = tempfile::tempdir().expect("create deep OTP CLI test directory");
    fs::write(directory.path().join("input"), b"preserve this input")
        .expect("write deep OTP input");
    fs::write(directory.path().join("key"), b"a sufficiently long key")
        .expect("write deep OTP key");
    let bad_name = invalid_filename(case - 16);
    let arguments = if case.is_multiple_of(2) {
        [bad_name.as_str(), "key"]
    } else {
        ["input", bad_name.as_str()]
    };
    let output = run_in(app.binary, directory.path(), &arguments);
    assert_robust_failure(&output, case);
    assert_eq!(
        fs::read(directory.path().join("input")).expect("read preserved deep OTP input"),
        b"preserve this input"
    );
    assert_eq!(
        fs::read(directory.path().join("key")).expect("read preserved deep OTP key"),
        b"a sufficiently long key"
    );
}

pub fn run_case(app: DeepCliApp, case: usize) {
    assert!(case < 126, "deep CLI case index is outside the corpus");
    match app.kind {
        DeepCliKind::Cipher {
            key_filename,
            key_len,
        } => cipher_case(app, case, key_filename, key_len),
        DeepCliKind::Size => size_case(app, case),
        DeepCliKind::SingleInput => single_input_case(app, case),
        DeepCliKind::Otp => otp_case(app, case),
    }
}

macro_rules! define_deep_cli_tests {
    ($runner:path, $app:expr) => {
        macro_rules! deep_cli_case {
            ($name:ident, $case:expr) => {
                #[test]
                fn $name() {
                    $runner($app, $case);
                }
            };
        }

        deep_cli_case!(deep_cli_case_000, 0);
        deep_cli_case!(deep_cli_case_001, 1);
        deep_cli_case!(deep_cli_case_002, 2);
        deep_cli_case!(deep_cli_case_003, 3);
        deep_cli_case!(deep_cli_case_004, 4);
        deep_cli_case!(deep_cli_case_005, 5);
        deep_cli_case!(deep_cli_case_006, 6);
        deep_cli_case!(deep_cli_case_007, 7);
        deep_cli_case!(deep_cli_case_008, 8);
        deep_cli_case!(deep_cli_case_009, 9);
        deep_cli_case!(deep_cli_case_010, 10);
        deep_cli_case!(deep_cli_case_011, 11);
        deep_cli_case!(deep_cli_case_012, 12);
        deep_cli_case!(deep_cli_case_013, 13);
        deep_cli_case!(deep_cli_case_014, 14);
        deep_cli_case!(deep_cli_case_015, 15);
        deep_cli_case!(deep_cli_case_016, 16);
        deep_cli_case!(deep_cli_case_017, 17);
        deep_cli_case!(deep_cli_case_018, 18);
        deep_cli_case!(deep_cli_case_019, 19);
        deep_cli_case!(deep_cli_case_020, 20);
        deep_cli_case!(deep_cli_case_021, 21);
        deep_cli_case!(deep_cli_case_022, 22);
        deep_cli_case!(deep_cli_case_023, 23);
        deep_cli_case!(deep_cli_case_024, 24);
        deep_cli_case!(deep_cli_case_025, 25);
        deep_cli_case!(deep_cli_case_026, 26);
        deep_cli_case!(deep_cli_case_027, 27);
        deep_cli_case!(deep_cli_case_028, 28);
        deep_cli_case!(deep_cli_case_029, 29);
        deep_cli_case!(deep_cli_case_030, 30);
        deep_cli_case!(deep_cli_case_031, 31);
        deep_cli_case!(deep_cli_case_032, 32);
        deep_cli_case!(deep_cli_case_033, 33);
        deep_cli_case!(deep_cli_case_034, 34);
        deep_cli_case!(deep_cli_case_035, 35);
        deep_cli_case!(deep_cli_case_036, 36);
        deep_cli_case!(deep_cli_case_037, 37);
        deep_cli_case!(deep_cli_case_038, 38);
        deep_cli_case!(deep_cli_case_039, 39);
        deep_cli_case!(deep_cli_case_040, 40);
        deep_cli_case!(deep_cli_case_041, 41);
        deep_cli_case!(deep_cli_case_042, 42);
        deep_cli_case!(deep_cli_case_043, 43);
        deep_cli_case!(deep_cli_case_044, 44);
        deep_cli_case!(deep_cli_case_045, 45);
        deep_cli_case!(deep_cli_case_046, 46);
        deep_cli_case!(deep_cli_case_047, 47);
        deep_cli_case!(deep_cli_case_048, 48);
        deep_cli_case!(deep_cli_case_049, 49);
        deep_cli_case!(deep_cli_case_050, 50);
        deep_cli_case!(deep_cli_case_051, 51);
        deep_cli_case!(deep_cli_case_052, 52);
        deep_cli_case!(deep_cli_case_053, 53);
        deep_cli_case!(deep_cli_case_054, 54);
        deep_cli_case!(deep_cli_case_055, 55);
        deep_cli_case!(deep_cli_case_056, 56);
        deep_cli_case!(deep_cli_case_057, 57);
        deep_cli_case!(deep_cli_case_058, 58);
        deep_cli_case!(deep_cli_case_059, 59);
        deep_cli_case!(deep_cli_case_060, 60);
        deep_cli_case!(deep_cli_case_061, 61);
        deep_cli_case!(deep_cli_case_062, 62);
        deep_cli_case!(deep_cli_case_063, 63);
        deep_cli_case!(deep_cli_case_064, 64);
        deep_cli_case!(deep_cli_case_065, 65);
        deep_cli_case!(deep_cli_case_066, 66);
        deep_cli_case!(deep_cli_case_067, 67);
        deep_cli_case!(deep_cli_case_068, 68);
        deep_cli_case!(deep_cli_case_069, 69);
        deep_cli_case!(deep_cli_case_070, 70);
        deep_cli_case!(deep_cli_case_071, 71);
        deep_cli_case!(deep_cli_case_072, 72);
        deep_cli_case!(deep_cli_case_073, 73);
        deep_cli_case!(deep_cli_case_074, 74);
        deep_cli_case!(deep_cli_case_075, 75);
        deep_cli_case!(deep_cli_case_076, 76);
        deep_cli_case!(deep_cli_case_077, 77);
        deep_cli_case!(deep_cli_case_078, 78);
        deep_cli_case!(deep_cli_case_079, 79);
        deep_cli_case!(deep_cli_case_080, 80);
        deep_cli_case!(deep_cli_case_081, 81);
        deep_cli_case!(deep_cli_case_082, 82);
        deep_cli_case!(deep_cli_case_083, 83);
        deep_cli_case!(deep_cli_case_084, 84);
        deep_cli_case!(deep_cli_case_085, 85);
        deep_cli_case!(deep_cli_case_086, 86);
        deep_cli_case!(deep_cli_case_087, 87);
        deep_cli_case!(deep_cli_case_088, 88);
        deep_cli_case!(deep_cli_case_089, 89);
        deep_cli_case!(deep_cli_case_090, 90);
        deep_cli_case!(deep_cli_case_091, 91);
        deep_cli_case!(deep_cli_case_092, 92);
        deep_cli_case!(deep_cli_case_093, 93);
        deep_cli_case!(deep_cli_case_094, 94);
        deep_cli_case!(deep_cli_case_095, 95);
        deep_cli_case!(deep_cli_case_096, 96);
        deep_cli_case!(deep_cli_case_097, 97);
        deep_cli_case!(deep_cli_case_098, 98);
        deep_cli_case!(deep_cli_case_099, 99);
        deep_cli_case!(deep_cli_case_100, 100);
        deep_cli_case!(deep_cli_case_101, 101);
        deep_cli_case!(deep_cli_case_102, 102);
        deep_cli_case!(deep_cli_case_103, 103);
        deep_cli_case!(deep_cli_case_104, 104);
        deep_cli_case!(deep_cli_case_105, 105);
        deep_cli_case!(deep_cli_case_106, 106);
        deep_cli_case!(deep_cli_case_107, 107);
        deep_cli_case!(deep_cli_case_108, 108);
        deep_cli_case!(deep_cli_case_109, 109);
        deep_cli_case!(deep_cli_case_110, 110);
        deep_cli_case!(deep_cli_case_111, 111);
        deep_cli_case!(deep_cli_case_112, 112);
        deep_cli_case!(deep_cli_case_113, 113);
        deep_cli_case!(deep_cli_case_114, 114);
        deep_cli_case!(deep_cli_case_115, 115);
        deep_cli_case!(deep_cli_case_116, 116);
        deep_cli_case!(deep_cli_case_117, 117);
        deep_cli_case!(deep_cli_case_118, 118);
        deep_cli_case!(deep_cli_case_119, 119);
        deep_cli_case!(deep_cli_case_120, 120);
        deep_cli_case!(deep_cli_case_121, 121);
        deep_cli_case!(deep_cli_case_122, 122);
        deep_cli_case!(deep_cli_case_123, 123);
        deep_cli_case!(deep_cli_case_124, 124);
        deep_cli_case!(deep_cli_case_125, 125);
    };
}

pub(crate) use define_deep_cli_tests;
