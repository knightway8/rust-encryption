#![cfg(target_os = "linux")]

use otp2_auth::{AUTH_KEY_LENGTH, AuthError, AuthOutcome, create_tag, verify_file};
use std::fs::{self, File, FileTimes, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

const KEY: [u8; AUTH_KEY_LENGTH] = [0x83; AUTH_KEY_LENGTH];
static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

struct CloudFixture {
    root: PathBuf,
    source: PathBuf,
    store: PathBuf,
    download: PathBuf,
    key: PathBuf,
}

impl CloudFixture {
    fn new(label: &str) -> Self {
        let root = loop {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let candidate = std::env::temp_dir().join(format!(
                "otp2-auth-cloud-{label}-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&candidate) {
                Ok(()) => break candidate,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("create cloud fixture: {error}"),
            }
        };
        let source = root.join("source");
        let store = root.join("object store");
        let download = root.join("download");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&store).unwrap();
        fs::create_dir(&download).unwrap();
        let key = root.join("auth.key");
        fs::write(&key, KEY).unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        Self {
            root,
            source,
            store,
            download,
            key,
        }
    }

    fn tag(&self, file: &Path, tag: &Path) {
        match create_tag(file, tag, &self.key, false).unwrap() {
            AuthOutcome::Committed => {}
            AuthOutcome::CommittedButDurabilityUncertain(error) => {
                panic!("test filesystem did not durably publish sidecar: {error}")
            }
        }
    }
}

impl Drop for CloudFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn deterministic_bytes(length: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    let mut result = Vec::with_capacity(length);
    for _ in 0..length {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        result.push((state >> 32) as u8);
    }
    result
}

fn change_metadata(path: &Path, mode: u32, seconds_ago: u64) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    let timestamp = SystemTime::now() - Duration::from_secs(seconds_ago);
    File::options()
        .read(true)
        .open(path)
        .unwrap()
        .set_times(FileTimes::new().set_modified(timestamp))
        .unwrap();
}

#[test]
fn renamed_and_copied_file_tag_pairs_verify_independent_of_paths_and_metadata() {
    let fixture = CloudFixture::new("portable-pair");
    let bytes = deterministic_bytes(3 * 65_536 + 29, 0x1234_abcd);
    let source_file = fixture.source.join("original object λ.bin");
    let source_tag = fixture.source.join("unexpected tag name");
    fs::write(&source_file, &bytes).unwrap();
    fixture.tag(&source_file, &source_tag);

    let renamed_file = fixture.source.join("renamed object.bin");
    let renamed_tag = fixture.source.join("renamed metadata.otp2auth");
    fs::rename(&source_file, &renamed_file).unwrap();
    fs::rename(&source_tag, &renamed_tag).unwrap();
    verify_file(&renamed_file, &renamed_tag, &fixture.key).unwrap();

    let stored_file = fixture.store.join("provider-generated-object-id");
    let stored_tag = fixture.store.join("provider-generated-sidecar-id");
    fs::copy(&renamed_file, &stored_file).unwrap();
    fs::copy(&renamed_tag, &stored_tag).unwrap();
    change_metadata(&stored_file, 0o444, 3_600);
    change_metadata(&stored_tag, 0o400, 7_200);
    verify_file(&stored_file, &stored_tag, &fixture.key).unwrap();
    assert_eq!(fs::read(stored_file).unwrap(), bytes);
}

#[test]
fn sidecars_can_follow_identical_content_but_cannot_be_swapped_between_different_objects() {
    let fixture = CloudFixture::new("sidecar-swap");
    let first = fixture.source.join("first");
    let second = fixture.source.join("second");
    let identical_copy = fixture.source.join("identical under a new name");
    let first_tag = fixture.source.join("first.tag");
    let second_tag = fixture.source.join("second.tag");
    let first_bytes = deterministic_bytes(65_537, 0x1111_2222);
    let second_bytes = deterministic_bytes(first_bytes.len(), 0x3333_4444);
    fs::write(&first, &first_bytes).unwrap();
    fs::write(&second, &second_bytes).unwrap();
    fs::write(&identical_copy, &first_bytes).unwrap();
    fixture.tag(&first, &first_tag);
    fixture.tag(&second, &second_tag);

    verify_file(&identical_copy, &first_tag, &fixture.key).unwrap();
    for (file, wrong_tag) in [(&first, &second_tag), (&second, &first_tag)] {
        let error = verify_file(file, wrong_tag, &fixture.key).unwrap_err();
        assert!(error.is_authentication_failure());
        assert!(matches!(error, AuthError::AuthenticationFailed { .. }));
    }
}

#[test]
fn independent_cloud_arrival_never_falls_back_to_unsigned_data() {
    let fixture = CloudFixture::new("arrival-order");
    let source_file = fixture.source.join("object");
    let source_tag = fixture.source.join("object.tag");
    fs::write(&source_file, b"authenticated object").unwrap();
    fixture.tag(&source_file, &source_tag);

    let downloaded_file = fixture.download.join("object");
    let downloaded_tag = fixture.download.join("object.tag");
    fs::copy(&source_file, &downloaded_file).unwrap();
    let missing_tag_error =
        verify_file(&downloaded_file, &downloaded_tag, &fixture.key).unwrap_err();
    assert!(!missing_tag_error.is_authentication_failure());

    fs::copy(&source_tag, &downloaded_tag).unwrap();
    verify_file(&downloaded_file, &downloaded_tag, &fixture.key).unwrap();

    fs::remove_file(&downloaded_file).unwrap();
    let missing_file_error =
        verify_file(&downloaded_file, &downloaded_tag, &fixture.key).unwrap_err();
    assert!(!missing_file_error.is_authentication_failure());
    fs::copy(&source_file, &downloaded_file).unwrap();
    verify_file(&downloaded_file, &downloaded_tag, &fixture.key).unwrap();
}

#[test]
fn downloaded_payload_and_sidecar_corruption_are_detected_without_mutation() {
    let fixture = CloudFixture::new("download-corruption");
    let source_file = fixture.source.join("object");
    let source_tag = fixture.source.join("object.tag");
    let original = deterministic_bytes(2 * 65_536 + 7, 0x55aa_7788);
    fs::write(&source_file, &original).unwrap();
    fixture.tag(&source_file, &source_tag);
    let valid_tag = fs::read(&source_tag).unwrap();

    let file = fixture.download.join("object");
    let tag = fixture.download.join("object.tag");
    fs::copy(&source_file, &file).unwrap();
    fs::copy(&source_tag, &tag).unwrap();
    let file_identity = fs::metadata(&file).unwrap().ino();
    let tag_identity = fs::metadata(&tag).unwrap().ino();

    let mut changed = original.clone();
    changed[65_536] ^= 0x40;
    fs::write(&file, &changed).unwrap();
    assert!(
        verify_file(&file, &tag, &fixture.key)
            .unwrap_err()
            .is_authentication_failure()
    );
    assert_eq!(fs::read(&file).unwrap(), changed);
    assert_eq!(fs::read(&tag).unwrap(), valid_tag);
    assert_eq!(fs::metadata(&file).unwrap().ino(), file_identity);
    assert_eq!(fs::metadata(&tag).unwrap().ino(), tag_identity);

    fs::write(&file, &original).unwrap();
    let mut bad_tag = valid_tag.clone();
    bad_tag[0] ^= 1;
    fs::write(&tag, &bad_tag).unwrap();
    assert!(
        verify_file(&file, &tag, &fixture.key)
            .unwrap_err()
            .is_authentication_failure()
    );
    assert_eq!(fs::read(&file).unwrap(), original);
    assert_eq!(fs::read(&tag).unwrap(), bad_tag);
}

#[test]
fn sparse_and_empty_objects_survive_byte_for_byte_store_round_trips() {
    let fixture = CloudFixture::new("sparse-empty");
    let sparse = fixture.source.join("sparse object");
    let sparse_tag = fixture.source.join("sparse tag");
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&sparse)
        .unwrap();
    const LENGTH: u64 = 64 * 1024 * 1024 + 17;
    file.set_len(LENGTH).unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();
    file.write_all(b"prefix").unwrap();
    file.seek(SeekFrom::Start(32 * 1024 * 1024 + 3)).unwrap();
    file.write_all(b"middle island").unwrap();
    file.seek(SeekFrom::Start(LENGTH - 6)).unwrap();
    file.write_all(b"suffix").unwrap();
    file.sync_all().unwrap();
    let sparse_blocks = file.metadata().unwrap().blocks();
    drop(file);
    assert!(sparse_blocks * 512 < LENGTH / 4, "fixture was not sparse");
    fixture.tag(&sparse, &sparse_tag);

    let stored_sparse = fixture.store.join("sparse bytes");
    let stored_tag = fixture.store.join("sparse sidecar");
    fs::copy(&sparse, &stored_sparse).unwrap();
    fs::copy(&sparse_tag, &stored_tag).unwrap();
    verify_file(&stored_sparse, &stored_tag, &fixture.key).unwrap();
    assert_eq!(fs::metadata(&stored_sparse).unwrap().len(), LENGTH);
    let mut reader = File::open(&stored_sparse).unwrap();
    let mut sample = [0_u8; 13];
    reader.seek(SeekFrom::Start(32 * 1024 * 1024 + 3)).unwrap();
    reader.read_exact(&mut sample).unwrap();
    assert_eq!(&sample, b"middle island");

    let empty = fixture.source.join("empty object");
    let empty_tag = fixture.source.join("empty tag");
    fs::write(&empty, b"").unwrap();
    fixture.tag(&empty, &empty_tag);
    fs::copy(&empty, fixture.download.join("empty")).unwrap();
    fs::copy(&empty_tag, fixture.download.join("empty.tag")).unwrap();
    verify_file(
        fixture.download.join("empty"),
        fixture.download.join("empty.tag"),
        &fixture.key,
    )
    .unwrap();
}
