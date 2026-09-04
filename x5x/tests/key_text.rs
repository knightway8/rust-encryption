use std::ffi::OsStr;
use std::fs;
use std::process::Command;
use x3x::{CHUNK_SIZE, binary_key_to_text_in, text_to_binary_key_in};

#[test]
fn converter_binaries_round_trip_and_emit_documented_format() {
    let directory = tempfile::tempdir().unwrap();
    let original = [23_u8, 255, 53, 9, 5];
    fs::write(directory.path().join("original.key"), original).unwrap();

    let key2txt = Command::new(env!("CARGO_BIN_EXE_key2txt"))
        .current_dir(directory.path())
        .arg("original.key")
        .output()
        .unwrap();
    assert!(
        key2txt.status.success(),
        "key2txt failed: {}",
        String::from_utf8_lossy(&key2txt.stderr)
    );
    assert_eq!(
        fs::read(directory.path().join("key2txt.txt")).unwrap(),
        b"23,\n255,\n53,\n9,\n5\n"
    );

    let txt2key = Command::new(env!("CARGO_BIN_EXE_txt2key"))
        .current_dir(directory.path())
        .arg("key2txt.txt")
        .output()
        .unwrap();
    assert!(
        txt2key.status.success(),
        "txt2key failed: {}",
        String::from_utf8_lossy(&txt2key.stderr)
    );
    assert_eq!(
        fs::read(directory.path().join("txt2key.key")).unwrap(),
        original
    );
}

#[test]
fn converters_stream_across_internal_buffer_boundaries() {
    let directory = tempfile::tempdir().unwrap();
    let original: Vec<u8> = (0..CHUNK_SIZE + 137)
        .map(|index| u8::try_from(index % 256).expect("test byte fits in u8"))
        .collect();
    fs::write(directory.path().join("large.key"), &original).unwrap();

    binary_key_to_text_in(directory.path(), OsStr::new("large.key")).unwrap();
    text_to_binary_key_in(directory.path(), OsStr::new("key2txt.txt")).unwrap();

    assert_eq!(
        fs::read(directory.path().join("txt2key.key")).unwrap(),
        original
    );
}

#[test]
fn txt2key_accepts_plain_lines_commas_spaces_and_crlf() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(
        directory.path().join("values.txt"),
        b" 23, \r\n255\r\n\t53,\n9\n5,\n",
    )
    .unwrap();

    text_to_binary_key_in(directory.path(), OsStr::new("values.txt")).unwrap();
    assert_eq!(
        fs::read(directory.path().join("txt2key.key")).unwrap(),
        [23_u8, 255, 53, 9, 5]
    );
}

#[test]
fn txt2key_rejects_malformed_lines_without_creating_output() {
    let invalid_inputs: [&[u8]; 8] = [
        b"256\n",
        b"-1\n",
        b"1, 2\n",
        b"1,2\n",
        b"12 3\n",
        b"1\n\n2\n",
        b"0000\n",
        b"1\nhello\n",
    ];

    for (index, contents) in invalid_inputs.into_iter().enumerate() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("invalid.txt"), contents).unwrap();
        let result = text_to_binary_key_in(directory.path(), OsStr::new("invalid.txt"));
        assert!(result.is_err(), "invalid case {index} was accepted");
        assert!(
            !directory.path().join("txt2key.key").exists(),
            "invalid case {index} left an output"
        );
    }
}

#[test]
fn converters_refuse_to_overwrite_fixed_outputs() {
    let key2txt_directory = tempfile::tempdir().unwrap();
    fs::write(key2txt_directory.path().join("source.key"), [1_u8, 2, 3]).unwrap();
    fs::write(
        key2txt_directory.path().join("key2txt.txt"),
        b"preserve text",
    )
    .unwrap();
    assert!(binary_key_to_text_in(key2txt_directory.path(), OsStr::new("source.key")).is_err());
    assert_eq!(
        fs::read(key2txt_directory.path().join("key2txt.txt")).unwrap(),
        b"preserve text"
    );

    let txt2key_directory = tempfile::tempdir().unwrap();
    fs::write(txt2key_directory.path().join("source.txt"), b"1\n2\n3\n").unwrap();
    fs::write(
        txt2key_directory.path().join("txt2key.key"),
        b"preserve binary",
    )
    .unwrap();
    assert!(text_to_binary_key_in(txt2key_directory.path(), OsStr::new("source.txt")).is_err());
    assert_eq!(
        fs::read(txt2key_directory.path().join("txt2key.key")).unwrap(),
        b"preserve binary"
    );
}

#[test]
fn empty_key_round_trips_as_empty_files() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(directory.path().join("empty.key"), []).unwrap();

    binary_key_to_text_in(directory.path(), OsStr::new("empty.key")).unwrap();
    assert!(
        fs::read(directory.path().join("key2txt.txt"))
            .unwrap()
            .is_empty()
    );

    text_to_binary_key_in(directory.path(), OsStr::new("key2txt.txt")).unwrap();
    assert!(
        fs::read(directory.path().join("txt2key.key"))
            .unwrap()
            .is_empty()
    );
}
