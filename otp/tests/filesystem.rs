use std::fs;

use otp::{
    OtpError, PadRole, create_pad_pair, destroy_pad, encrypt_file_with_state, inspect_pad,
    is_reserved_in,
};
use tempfile::tempdir;

#[cfg(unix)]
use otp::decrypt_file_with_state;

#[test]
fn a_non_directory_ledger_path_fails_closed_without_consuming_the_pad() {
    let temp = tempdir().unwrap();
    let plaintext = temp.path().join("plain.bin");
    let sender = temp.path().join("sender.pad");
    let receiver = temp.path().join("receiver.pad");
    let encrypted = temp.path().join("encrypted.otp");
    let invalid_state = temp.path().join("state-is-a-file");
    fs::write(&plaintext, b"ledger path").unwrap();
    fs::write(&invalid_state, b"not a directory").unwrap();
    create_pad_pair(11, &sender, &receiver).unwrap();
    let information = inspect_pad(&sender).unwrap();

    assert!(matches!(
        is_reserved_in(&invalid_state, &information.id, PadRole::Sender),
        Err(OtpError::Io { .. })
    ));
    assert!(matches!(
        encrypt_file_with_state(&plaintext, &sender, &encrypted, &invalid_state),
        Err(OtpError::Io { .. })
    ));
    assert!(!encrypted.exists());
    assert!(!inspect_pad(&sender).unwrap().consumed);
}

#[cfg(any(unix, windows))]
#[test]
fn symbolic_link_pad_aliases_are_rejected_without_touching_the_target() {
    let temp = tempdir().unwrap();
    let sender = temp.path().join("sender.pad");
    let receiver = temp.path().join("receiver.pad");
    let link = temp.path().join("receiver-link.pad");
    create_pad_pair(9, &sender, &receiver).unwrap();
    let original = fs::read(&receiver).unwrap();

    #[cfg(unix)]
    let link_result = std::os::unix::fs::symlink(&receiver, &link);
    #[cfg(windows)]
    let link_result = std::os::windows::fs::symlink_file(&receiver, &link);
    if let Err(error) = link_result {
        eprintln!("symbolic links unavailable; skipping alias assertions: {error}");
        return;
    }

    assert!(matches!(inspect_pad(&link), Err(OtpError::InvalidPad(_))));
    assert!(matches!(destroy_pad(&link), Err(OtpError::InvalidPad(_))));
    assert_eq!(fs::read(&receiver).unwrap(), original);
}

#[cfg(unix)]
#[test]
fn unix_pad_permissions_must_be_owner_only_and_outputs_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempdir().unwrap();
    let plaintext = temp.path().join("plain.bin");
    let sender = temp.path().join("sender.pad");
    let receiver = temp.path().join("receiver.pad");
    let encrypted = temp.path().join("encrypted.otp");
    let recovered = temp.path().join("recovered.bin");
    let state = temp.path().join("state");
    fs::write(&plaintext, b"private permissions").unwrap();
    create_pad_pair(19, &sender, &receiver).unwrap();

    assert_eq!(
        fs::metadata(&sender).unwrap().permissions().mode() & 0o777,
        0o600
    );
    fs::set_permissions(&sender, fs::Permissions::from_mode(0o640)).unwrap();
    assert!(matches!(inspect_pad(&sender), Err(OtpError::InvalidPad(_))));
    fs::set_permissions(&sender, fs::Permissions::from_mode(0o600)).unwrap();

    encrypt_file_with_state(&plaintext, &sender, &encrypted, &state).unwrap();
    decrypt_file_with_state(&encrypted, &receiver, &recovered, &state).unwrap();
    assert_eq!(
        fs::metadata(&encrypted).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(&recovered).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(&state).unwrap().permissions().mode() & 0o777,
        0o700
    );
}
