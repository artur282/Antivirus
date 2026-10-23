mod common;

use std::fs;
use std::path::Path;

use antivirus_core::{CoreError, DeleteReport, QuarantineReport};

fn setup() -> (tempfile::TempDir, antivirus_core::Core) {
    let dir = common::temp_dir();
    let core = common::make_core(&dir.path().join("app-data"), None);
    (dir, core)
}

#[test]
fn quarantine_moves_files_with_metadata_and_unique_names() {
    let (dir, core) = setup();
    let first_dir = dir.path().join("one");
    let second_dir = dir.path().join("two");
    let first = common::write_file(&first_dir.join("same.txt"), b"hello");
    let second = common::write_file(&second_dir.join("same.txt"), b"world");

    let report: QuarantineReport = core
        .quarantine_files(&[first.clone(), second.clone()])
        .expect("quarantine");

    assert!(report.failed.is_empty());
    assert_eq!(report.moved.len(), 2);
    assert!(!first.exists());
    assert!(!second.exists());

    let quarantine_dir = dir.path().join("app-data/quarantine");
    let first_entry = &report.moved[0];
    let second_entry = &report.moved[1];

    assert_eq!(first_entry.original_path, common::path_string(&first));
    assert_eq!(first_entry.sha256, common::HELLO_SHA256);
    assert!(first_entry.created_at.len() >= 19);
    assert!(first_entry.restored_at.is_none());
    assert!(Path::new(&first_entry.stored_path).starts_with(&quarantine_dir));
    assert_eq!(
        fs::read(&first_entry.stored_path).expect("stored content"),
        b"hello"
    );

    assert_eq!(second_entry.sha256, common::WORLD_SHA256);
    assert_ne!(first_entry.stored_path, second_entry.stored_path);
    assert!(Path::new(&second_entry.stored_path)
        .file_name()
        .expect("stored file name")
        .to_string_lossy()
        .contains("same.txt"));

    let listed = core.list_quarantine().expect("list");
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0].id, second_entry.id, "newest entry first");
    assert_eq!(listed[1].id, first_entry.id);
    assert!(listed.iter().all(|entry| entry.restored_at.is_none()));
}

#[test]
fn quarantine_reports_per_file_failures() {
    let (dir, core) = setup();
    let missing = dir.path().join("missing.bin");
    let report = core
        .quarantine_files(&[missing.clone()])
        .expect("quarantine report");

    assert!(report.moved.is_empty());
    assert_eq!(report.failed.len(), 1);
    assert_eq!(report.failed[0].path, common::path_string(&missing));
    assert!(!report.failed[0].message.is_empty());
    assert!(core.list_quarantine().expect("list").is_empty());
}

#[test]
fn restore_returns_updated_entry_and_recreates_parents() {
    let (dir, core) = setup();
    let original = common::write_file(&dir.path().join("deep/nested/file.txt"), b"hello");
    let report = core
        .quarantine_files(&[original.clone()])
        .expect("quarantine");
    let entry = report.moved[0].clone();

    fs::remove_dir_all(dir.path().join("deep")).expect("remove original tree");
    assert!(!original.exists());

    let restored = core.restore_quarantined(entry.id).expect("restore");
    assert_eq!(restored.id, entry.id);
    assert_eq!(restored.original_path, common::path_string(&original));
    assert!(restored.restored_at.is_some());
    assert_eq!(fs::read(&original).expect("restored content"), b"hello");
    assert!(!Path::new(&restored.stored_path).exists());

    let listed = core.list_quarantine().expect("list");
    assert_eq!(listed.len(), 1);
    assert!(listed[0].restored_at.is_some());
}

#[test]
fn restore_refuses_to_overwrite_an_existing_file() {
    let (dir, core) = setup();
    let original = common::write_file(&dir.path().join("important.txt"), b"hello");
    let report = core
        .quarantine_files(&[original.clone()])
        .expect("quarantine");
    let entry = report.moved[0].clone();

    fs::write(&original, b"new content").expect("recreate original");
    let error = core
        .restore_quarantined(entry.id)
        .expect_err("must refuse overwrite");
    assert!(matches!(error, CoreError::InvalidPath(_)));
    assert_eq!(fs::read(&original).expect("original kept"), b"new content");

    let listed = core.list_quarantine().expect("list");
    assert!(listed[0].restored_at.is_none());
    assert!(Path::new(&entry.stored_path).exists());
}

#[test]
fn restore_reports_missing_quarantine_entries_and_files() {
    let (dir, core) = setup();
    let error = core.restore_quarantined(999).expect_err("unknown id");
    assert!(matches!(error, CoreError::NotFound(_)));

    let original = common::write_file(&dir.path().join("gone.txt"), b"hello");
    let report = core
        .quarantine_files(&[original.clone()])
        .expect("quarantine");
    let entry = report.moved[0].clone();
    fs::remove_file(&entry.stored_path).expect("delete stored file");

    let error = core
        .restore_quarantined(entry.id)
        .expect_err("missing stored");
    assert!(matches!(error, CoreError::NotFound(_)));
}

#[test]
fn delete_files_returns_deleted_paths_and_per_file_failures() {
    let (dir, core) = setup();
    let kept = common::write_file(&dir.path().join("kept.txt"), b"hello");
    let removed = common::write_file(&dir.path().join("removed.txt"), b"world");
    let missing = dir.path().join("missing.txt");
    let directory = dir.path().join("folder");
    fs::create_dir_all(&directory).expect("create directory");

    let report: DeleteReport = core
        .delete_files(&[removed.clone(), missing.clone(), directory.clone()])
        .expect("delete");

    assert_eq!(report.deleted, vec![common::path_string(&removed)]);
    assert_eq!(report.failed.len(), 2);
    assert!(!removed.exists());
    assert!(kept.exists());
    assert!(directory.exists());
    assert!(report
        .failed
        .iter()
        .any(|failure| failure.path == common::path_string(&missing)));
}
