use std::process::Command;

#[test]
fn every_password_binary_has_the_expected_standalone_command() {
    let binaries = [
        ("aesp", env!("CARGO_BIN_EXE_aesp")),
        ("chap", env!("CARGO_BIN_EXE_chap")),
        ("serp", env!("CARGO_BIN_EXE_serp")),
        ("thfp", env!("CARGO_BIN_EXE_thfp")),
        ("ascp", env!("CARGO_BIN_EXE_ascp")),
        ("rabbitp", env!("CARGO_BIN_EXE_rabbitp")),
        ("aegis256p", env!("CARGO_BIN_EXE_aegis256p")),
        ("aegis128lp", env!("CARGO_BIN_EXE_aegis128lp")),
    ];

    for (name, binary) in binaries {
        let result = Command::new(binary).output().unwrap();
        assert!(
            !result.status.success(),
            "{name} accepted missing arguments"
        );
        let error = String::from_utf8_lossy(&result.stderr);
        assert!(
            error.contains(&format!("usage: {name} [E or D] [filename] [output-file]")),
            "{name} emitted unexpected usage text: {error}"
        );
    }
}
