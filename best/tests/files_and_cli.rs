use age::secrecy::{ExposeSecret, SecretString};
use best::{Decryption, Encryption, Operation};
use rstest::rstest;
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::Ordering,
};

fn cli(args: &[&str], cwd: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_best"))
        .args(args)
        .current_dir(cwd)
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap()
}

fn seal(data: &[u8]) -> (tempfile::TempDir, age::x25519::Identity, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input");
    let cipher = dir.path().join("cipher.age");
    fs::write(&input, data).unwrap();
    let key = age::x25519::Identity::generate();
    best::encrypt_file(
        &input,
        &cipher,
        Encryption::Recipients(vec![key.to_public()]),
        &Operation::default(),
    )
    .unwrap();
    (dir, key, cipher)
}

fn no_temps(dir: &Path) {
    for item in fs::read_dir(dir).unwrap() {
        assert!(
            !item
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".best-tmp-")
        );
    }
}

#[rstest]
fn file_roundtrip_and_verify(
    #[values(
        0, 1, 15, 16, 17, 255, 4096, 65535, 65536, 65537, 131071, 131072, 131073, 1048576
    )]
    size: usize,
    #[values("restored", "space in name.txt", "日本語 🔒.bin")] name: &str,
) {
    let data: Vec<u8> = (0..size).map(|n| n as u8).collect();
    let (dir, key, cipher) = seal(&data);
    let count_before = fs::read_dir(dir.path()).unwrap().count();
    assert_eq!(
        best::verify_file(
            &cipher,
            Decryption::Identities(vec![key.clone()]),
            &Operation::default()
        )
        .unwrap(),
        size as u64
    );
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), count_before);
    let output = dir.path().join(name);
    assert_eq!(
        best::decrypt_file(
            &cipher,
            &output,
            Decryption::Identities(vec![key]),
            &Operation::default()
        )
        .unwrap(),
        size as u64
    );
    assert_eq!(fs::read(output).unwrap(), data);
    assert_eq!(fs::read(dir.path().join("input")).unwrap(), data);
    assert!(cipher.exists());
    no_temps(dir.path());
}

#[rstest]
fn failed_authentication_never_publishes_plaintext(
    #[values(0, 1, 65535, 65536, 65537, 131073)] size: usize,
    #[values("wrong-key", "last-bit", "truncate", "append", "malformed")] attack: &str,
) {
    let (dir, mut key, cipher) = seal(&vec![99; size]);
    let mut bytes = fs::read(&cipher).unwrap();
    match attack {
        "wrong-key" => key = age::x25519::Identity::generate(),
        "last-bit" => *bytes.last_mut().unwrap() ^= 1,
        "truncate" => {
            bytes.pop();
        }
        "append" => bytes.push(0),
        "malformed" => bytes[0] ^= 1,
        _ => unreachable!(),
    }
    fs::write(&cipher, &bytes).unwrap();
    let output = dir.path().join("result");
    assert!(
        best::decrypt_file(
            &cipher,
            &output,
            Decryption::Identities(vec![key.clone()]),
            &Operation::default()
        )
        .is_err()
    );
    assert!(!output.exists());
    assert!(
        best::verify_file(
            &cipher,
            Decryption::Identities(vec![key]),
            &Operation::default()
        )
        .is_err()
    );
    assert_eq!(fs::read(cipher).unwrap(), bytes);
    no_temps(dir.path());
}

#[rstest]
fn no_overwrites(
    #[values("encrypt", "decrypt", "keygen")] operation: &str,
    #[values("file", "directory", "same-input", "hardlink")] kind: &str,
) {
    let (dir, key, cipher) = seal(b"input remains safe");
    let output = if kind == "same-input" {
        cipher.clone()
    } else {
        dir.path().join("existing")
    };
    match kind {
        "file" => fs::write(&output, b"precious original").unwrap(),
        "directory" => fs::create_dir(&output).unwrap(),
        "hardlink" => fs::hard_link(&cipher, &output).unwrap(),
        _ => {}
    }
    let before = fs::read(&cipher).unwrap();
    let result = match operation {
        "encrypt" => best::encrypt_file(
            &cipher,
            &output,
            Encryption::Recipients(vec![key.to_public()]),
            &Operation::default(),
        )
        .map(|_| ()),
        "decrypt" => best::decrypt_file(
            &cipher,
            &output,
            Decryption::Identities(vec![key]),
            &Operation::default(),
        )
        .map(|_| ()),
        _ => best::keygen(&output).map(|_| ()),
    };
    assert!(result.is_err());
    assert_eq!(fs::read(&cipher).unwrap(), before);
    if kind == "file" {
        assert_eq!(fs::read(output).unwrap(), b"precious original");
    }
    no_temps(dir.path());
}

#[rstest]
fn invalid_inputs_do_not_create_output(#[values("missing", "directory")] kind: &str) {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input");
    if kind == "directory" {
        fs::create_dir(&input).unwrap();
    }
    let output = dir.path().join("out");
    let key = age::x25519::Identity::generate();
    assert!(
        best::encrypt_file(
            &input,
            &output,
            Encryption::Recipients(vec![key.to_public()]),
            &Operation::default()
        )
        .is_err()
    );
    assert!(!output.exists());
    no_temps(dir.path());
}

#[rstest]
fn limits_and_cancellation_cleanup(
    #[values(false, true)] decrypt: bool,
    #[values(false, true)] cancel: bool,
) {
    let (dir, key, cipher) = seal(&vec![42; 100000]);
    let output = dir.path().join("result");
    let op = Operation {
        max_bytes: Some(65536),
        ..Operation::default()
    };
    if cancel {
        op.cancelled.store(true, Ordering::Relaxed);
    }
    let result = if decrypt {
        best::decrypt_file(&cipher, &output, Decryption::Identities(vec![key]), &op)
    } else {
        best::encrypt_file(
            &cipher,
            &output,
            Encryption::Recipients(vec![key.to_public()]),
            &op,
        )
    };
    assert!(result.is_err());
    assert!(!output.exists());
    no_temps(dir.path());
}

#[test]
fn missing_output_directory_is_not_created() {
    let (dir, key, cipher) = seal(b"hello");
    let output = dir.path().join("missing/out");
    assert!(
        best::decrypt_file(
            &cipher,
            &output,
            Decryption::Identities(vec![key]),
            &Operation::default()
        )
        .is_err()
    );
    assert!(!dir.path().join("missing").exists());
    no_temps(dir.path());
}

#[rstest]
#[case("twelve chars!", true)]
#[case("twelve chars!\n", true)]
#[case("twelve chars!\r\n", true)]
#[case("  spaces are preserved  \n", true)]
#[case("🔒日本語long password\n", true)]
#[case("", false)]
#[case("\n", false)]
#[case("short", false)]
#[case("first password\nsecond", false)]
#[case("password\r", false)]
#[case("a password\0here", false)]
fn password_file_policy(#[case] content: &str, #[case] valid: bool) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pw");
    fs::write(&path, content).unwrap();
    let result = best::secret::password_file(&path, true);
    assert_eq!(result.is_ok(), valid);
    if let Ok(value) = result {
        assert_eq!(
            value.expose_secret(),
            content.trim_end_matches(['\r', '\n'])
        );
    }
}

#[rstest]
fn password_size_boundaries(
    #[values(1, 11, 12, 4095, 4096, 4097, 8192)] length: usize,
    #[values("", "\n", "\r\n")] ending: &str,
) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pw");
    fs::write(&path, format!("{}{ending}", "x".repeat(length))).unwrap();
    assert_eq!(
        best::secret::password_file(&path, true).is_ok(),
        (12..=4096).contains(&length)
    );
    assert_eq!(
        best::secret::password_file(&path, false).is_ok(),
        (1..=4096).contains(&length)
    );
}

#[test]
fn passwords_require_valid_utf8() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pw");
    fs::write(&path, [255; 20]).unwrap();
    assert!(best::secret::password_file(&path, true).is_err());
}

#[test]
fn generated_identity_roundtrips_and_only_public_key_reaches_stdout() {
    let dir = tempfile::tempdir().unwrap();
    let result = cli(&["keygen", "-o", "personal.key"], dir.path());
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let public = String::from_utf8(result.stdout).unwrap();
    assert!(public.starts_with("age1"));
    assert!(!String::from_utf8_lossy(&result.stderr).contains("AGE-SECRET-KEY-"));
    let result = cli(&["recipients", "-i", "personal.key"], dir.path());
    assert!(result.status.success());
    assert_eq!(result.stdout, public.as_bytes());
    let keys = best::secret::identities_file(&dir.path().join("personal.key")).unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].to_public().to_string(), public.trim());
}

#[rstest]
fn identity_file_limits(#[values(0, 1, 2, 32, 33)] count: usize) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("keys");
    let key = age::x25519::Identity::generate();
    let value = key.to_string();
    let body = format!(
        "# comment\r\n\r\n{}",
        format!("{}\r\n", value.expose_secret()).repeat(count)
    );
    fs::write(&path, body).unwrap();
    let result = best::secret::identities_file(&path);
    assert_eq!(result.is_ok(), (1..=32).contains(&count));
}

#[test]
fn malformed_identity_error_does_not_echo_secret_material() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("key"), "DO_NOT_LEAK_THIS_PRIVATE_MATERIAL").unwrap();
    let result = cli(&["recipients", "-i", "key"], dir.path());
    assert_eq!(result.status.code(), Some(1));
    assert!(result.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&result.stderr).contains("DO_NOT_LEAK"));
}

#[test]
fn oversized_identity_file_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("key");
    fs::write(&path, vec![b'#'; 65537]).unwrap();
    assert!(best::secret::identities_file(&path).is_err());
}

#[rstest]
fn recipient_count_limits(#[values(0, 1, 2, 64, 65)] count: usize) {
    let keys: Vec<_> = (0..count)
        .map(|_| age::x25519::Identity::generate().to_public().to_string())
        .collect();
    assert_eq!(best::recipients(&keys).is_ok(), (1..=64).contains(&count));
}

#[test]
fn duplicate_and_invalid_recipients_are_rejected() {
    let key = age::x25519::Identity::generate().to_public().to_string();
    assert!(best::recipients(&[key.clone(), key]).is_err());
    for key in [
        "",
        "age1wrong",
        "ssh-rsa unsupported",
        "AGE-SECRET-KEY-invalid",
    ] {
        assert!(best::recipients(&[key.to_owned()]).is_err());
    }
}

#[rstest]
fn cli_recipient_workflow(
    #[values(false, true)] quiet: bool,
    #[values("report.txt", "a b.txt", "日本語.bin")] name: &str,
) {
    let dir = tempfile::tempdir().unwrap();
    let public = best::keygen(&dir.path().join("key")).unwrap();
    fs::write(dir.path().join(name), b"binary\0\xff\nplaintext").unwrap();
    let mut args = vec!["encrypt", name, "-r", &public];
    if quiet {
        args.push("--quiet");
    }
    let result = cli(&args, dir.path());
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(result.stdout.is_empty());
    assert_eq!(result.stderr.is_empty(), quiet);
    let encrypted = format!("{name}.age");
    assert!(
        cli(&["verify", &encrypted, "-i", "key"], dir.path())
            .status
            .success()
    );
    assert_eq!(
        cli(&["decrypt", &encrypted, "-i", "key"], dir.path())
            .status
            .code(),
        Some(1)
    );
    assert!(
        cli(
            &["decrypt", &encrypted, "-i", "key", "-o", "restored"],
            dir.path()
        )
        .status
        .success()
    );
    assert_eq!(
        fs::read(dir.path().join("restored")).unwrap(),
        b"binary\0\xff\nplaintext"
    );
    no_temps(dir.path());
}

#[rstest]
#[case(vec!["--help"], 0)]
#[case(vec!["--version"], 0)]
#[case(vec!["encrypt", "--help"], 0)]
#[case(vec!["decrypt", "--help"], 0)]
#[case(vec!["verify", "--help"], 0)]
#[case(vec!["keygen", "--help"], 0)]
#[case(vec!["recipients", "--help"], 0)]
#[case(vec![], 2)]
#[case(vec!["bad-command"], 2)]
#[case(vec!["encrypt"], 2)]
#[case(vec!["keygen"], 2)]
#[case(vec!["verify", "f", "--max-work-factor", "21"], 2)]
fn cli_exit_codes(#[case] args: Vec<&str>, #[case] code: i32) {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(cli(&args, dir.path()).status.code(), Some(code));
}

#[test]
fn real_production_password_workflow() {
    // No reduced KDF parameters or ignored test: exercises the actual shipped
    // N=2^18 password encryption path, with a real subprocess on each command.
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("input"), b"password protected\0data").unwrap();
    fs::write(dir.path().join("pw"), "a long test passphrase only\r\n").unwrap();
    fs::write(
        dir.path().join("wrong"),
        "a different long test passphrase\n",
    )
    .unwrap();
    let result = cli(&["encrypt", "input", "--password-file", "pw"], dir.path());
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let bytes = fs::read(dir.path().join("input.age")).unwrap();
    assert!(String::from_utf8_lossy(&bytes[..140.min(bytes.len())]).contains(" 18\n"));
    let result = cli(
        &[
            "decrypt",
            "input.age",
            "--password-file",
            "pw",
            "-o",
            "restored",
        ],
        dir.path(),
    );
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        fs::read(dir.path().join("restored")).unwrap(),
        b"password protected\0data"
    );
    assert!(
        cli(
            &["verify", "input.age", "--password-file", "pw"],
            dir.path()
        )
        .status
        .success()
    );
    let result = cli(
        &[
            "decrypt",
            "input.age",
            "--password-file",
            "wrong",
            "-o",
            "must-not-exist",
        ],
        dir.path(),
    );
    assert_eq!(
        result.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(!dir.path().join("must-not-exist").exists());
    assert!(!String::from_utf8_lossy(&result.stderr).contains("a different long"));
    // A lower policy cap must reject before attempting the expensive KDF.
    let capped = cli(
        &[
            "verify",
            "input.age",
            "--password-file",
            "pw",
            "--max-work-factor",
            "17",
        ],
        dir.path(),
    );
    assert_eq!(
        capped.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&capped.stderr)
    );
    no_temps(dir.path());
}

#[test]
fn wrong_credential_kind_is_rejected() {
    let (_dir, _key, path) = seal(b"hello");
    let method = Decryption::Password {
        password: SecretString::from("long password here".to_owned()),
        max_work_factor: 18,
    };
    assert!(best::verify_file(&path, method, &Operation::default()).is_err());
}

#[cfg(unix)]
#[test]
fn unix_outputs_and_keys_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let (dir, key, cipher) = seal(b"secret");
    let output = dir.path().join("result");
    best::decrypt_file(
        &cipher,
        &output,
        Decryption::Identities(vec![key]),
        &Operation::default(),
    )
    .unwrap();
    let identity = dir.path().join("key");
    best::keygen(&identity).unwrap();
    for path in [&cipher, &output, &identity] {
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[cfg(windows)]
#[test]
fn windows_outputs_and_keys_have_protected_owner_system_acl() {
    let (dir, key, cipher) = seal(b"secret");
    let output = dir.path().join("result");
    best::decrypt_file(
        &cipher,
        &output,
        Decryption::Identities(vec![key]),
        &Operation::default(),
    )
    .unwrap();
    best::keygen(&dir.path().join("key")).unwrap();
    let script = "$ErrorActionPreference='Stop'; foreach ($n in @('cipher.age','result','key')) { $a=Get-Acl -LiteralPath $n; if (-not $a.AreAccessRulesProtected) { throw 'inherited ACL' }; $rules=$a.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier]); if ($rules.Count -ne 2) { throw 'unexpected rule count' }; foreach ($r in $rules) { if ($r.IsInherited -or $r.IdentityReference.Value -notin @('S-1-3-4','S-1-5-18')) { throw 'unexpected access' } } }";
    let result = Command::new("powershell.exe")
        .env_remove("PSModulePath")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[cfg(unix)]
#[rstest]
fn symlinks_are_refused(#[values(false, true)] dangling: bool) {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target");
    if !dangling {
        fs::write(&target, b"precious").unwrap();
    }
    let link = dir.path().join("link");
    symlink(&target, &link).unwrap();
    let key = age::x25519::Identity::generate();
    assert!(
        best::encrypt_file(
            &link,
            &dir.path().join("out"),
            Encryption::Recipients(vec![key.to_public()]),
            &Operation::default()
        )
        .is_err()
    );
    assert!(best::keygen(&link).is_err());
    assert!(!dir.path().join("out").exists());
    no_temps(dir.path());
}
