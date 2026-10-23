mod common;

use std::fs;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use antivirus_core::{CoreError, HistoryQuery, ScanKind, ScanPhase, ScanProgress, ScanRequest};
use rusqlite::Connection;

fn file_scan(paths: Vec<String>) -> ScanRequest {
    ScanRequest {
        kind: ScanKind::File,
        paths,
    }
}

#[test]
fn detects_infected_file_and_reports_all_hashes() {
    let dir = common::temp_dir();
    let signatures = common::create_signatures(
        &dir.path().join("virus_data.db"),
        &[],
        &[],
        &[common::HELLO_SHA256],
    );
    let core = common::make_core(&dir.path().join("app-data"), Some(&signatures));

    let clean = common::write_file(&dir.path().join("clean.txt"), b"world");
    let infected = common::write_file(&dir.path().join("infected.bin"), b"hello");

    let request = file_scan(vec![
        common::path_string(&clean),
        common::path_string(&infected),
    ]);
    let cancel = AtomicBool::new(false);
    let result = core.scan(request, &cancel, &|_| {}).expect("scan");

    assert_eq!(result.total_files, 2);
    assert_eq!(result.scanned_files, 2);
    assert_eq!(result.infected_files, 1);
    assert_eq!(result.safe_files, 1);
    assert!(!result.cancelled);
    assert!(result.errors.is_empty());
    assert_eq!(result.threats.len(), 1);

    let threat = &result.threats[0];
    assert_eq!(threat.path, common::path_string(&infected));
    assert_eq!(threat.md5, common::HELLO_MD5);
    assert_eq!(threat.sha1, common::HELLO_SHA1);
    assert_eq!(threat.sha256, common::HELLO_SHA256);
    assert_eq!(threat.size, 5);
    assert_eq!(threat.matched, vec!["sha256".to_string()]);

    let page = core.history(HistoryQuery::default()).expect("history");
    assert_eq!(page.total, 2);
    let infected_entries = page
        .entries
        .iter()
        .filter(|entry| entry.is_infected)
        .count();
    assert_eq!(infected_entries, 1);
}

#[test]
fn file_scan_skips_duplicates_and_reports_missing_paths() {
    let dir = common::temp_dir();
    let signatures = common::create_signatures(
        &dir.path().join("virus_data.db"),
        &[],
        &[],
        &[common::HELLO_SHA256],
    );
    let core = common::make_core(&dir.path().join("app-data"), Some(&signatures));

    let clean = common::write_file(&dir.path().join("clean.txt"), b"world");
    let missing = dir.path().join("does-not-exist.txt");
    let request = file_scan(vec![
        common::path_string(&clean),
        common::path_string(&clean),
        common::path_string(&missing),
    ]);

    let cancel = AtomicBool::new(false);
    let result = core.scan(request, &cancel, &|_| {}).expect("scan");

    assert_eq!(result.total_files, 1);
    assert_eq!(result.scanned_files, 1);
    assert_eq!(result.infected_files, 0);
    assert_eq!(result.safe_files, 1);
    assert_eq!(result.errors.len(), 1);
    assert_eq!(result.errors[0].path, common::path_string(&missing));
}

#[test]
fn directory_scan_walks_recursively_and_skips_symlinks() {
    let dir = common::temp_dir();
    let signatures = common::create_signatures(
        &dir.path().join("virus_data.db"),
        &[],
        &[],
        &[common::HELLO_SHA256],
    );
    let core = common::make_core(&dir.path().join("app-data"), Some(&signatures));

    let root = dir.path().join("tree");
    let first = common::write_file(&root.join("first.txt"), b"world");
    let nested = common::write_file(&root.join("nested/second.txt"), b"hello");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&nested, root.join("link.txt")).expect("create symlink");

    let request = ScanRequest {
        kind: ScanKind::Directory,
        paths: vec![common::path_string(&root)],
    };
    let cancel = AtomicBool::new(false);
    let result = core.scan(request, &cancel, &|_| {}).expect("scan");

    assert_eq!(result.total_files, 2);
    assert_eq!(result.scanned_files, 2);
    assert_eq!(result.infected_files, 1);
    assert_eq!(result.threats[0].path, common::path_string(&nested));
    let _ = first;
}

#[cfg(unix)]
#[test]
fn unreadable_file_becomes_scan_failure_instead_of_aborting() {
    use std::os::unix::fs::PermissionsExt;

    let dir = common::temp_dir();
    let signatures = common::create_signatures(
        &dir.path().join("virus_data.db"),
        &[],
        &[],
        &[common::HELLO_SHA256],
    );
    let core = common::make_core(&dir.path().join("app-data"), Some(&signatures));

    let readable = common::write_file(&dir.path().join("readable.txt"), b"world");
    let blocked = common::write_file(&dir.path().join("blocked.txt"), b"hello");
    fs::set_permissions(&blocked, fs::Permissions::from_mode(0o000)).expect("chmod");
    if fs::read(&blocked).is_ok() {
        // Privileged test runners can read mode-000 files; nothing to assert.
        return;
    }

    let request = file_scan(vec![
        common::path_string(&readable),
        common::path_string(&blocked),
    ]);
    let cancel = AtomicBool::new(false);
    let result = core.scan(request, &cancel, &|_| {}).expect("scan");

    assert_eq!(result.scanned_files, 1);
    assert_eq!(result.infected_files, 0);
    assert_eq!(result.errors.len(), 1);
    assert_eq!(result.errors[0].path, common::path_string(&blocked));

    fs::remove_file(&blocked).expect("remove blocked file");
}

#[test]
fn emits_progress_phases_and_a_scan_id() {
    let dir = common::temp_dir();
    let signatures = common::create_signatures(
        &dir.path().join("virus_data.db"),
        &[],
        &[],
        &[common::HELLO_SHA256],
    );
    let core = common::make_core(&dir.path().join("app-data"), Some(&signatures));
    let file = common::write_file(&dir.path().join("hello.txt"), b"hello");

    let events = Arc::new(Mutex::new(Vec::<ScanProgress>::new()));
    let sink = events.clone();
    let cancel = AtomicBool::new(false);
    let result = core
        .scan(
            file_scan(vec![common::path_string(&file)]),
            &cancel,
            &move |progress| sink.lock().expect("events lock").push(progress),
        )
        .expect("scan");

    let events = events.lock().expect("events lock");
    let phases: Vec<ScanPhase> = events.iter().map(|event| event.phase).collect();
    assert_eq!(phases.first(), Some(&ScanPhase::Preparing));
    assert!(phases.contains(&ScanPhase::Collecting));
    assert!(phases.contains(&ScanPhase::Scanning));
    assert_eq!(phases.last(), Some(&ScanPhase::Finished));
    assert!(events.iter().all(|event| event.scan_id == result.scan_id));
    assert!(!result.scan_id.is_empty());
}

#[test]
fn cancellation_between_hash_chunks_returns_partial_counts() {
    let dir = common::temp_dir();
    let signatures = common::create_signatures(
        &dir.path().join("virus_data.db"),
        &[],
        &[],
        &[common::HELLO_SHA256],
    );
    let core = common::make_core(&dir.path().join("app-data"), Some(&signatures));

    let root = dir.path().join("many");
    let mut paths = Vec::new();
    for index in 0..600 {
        let path = common::write_file(&root.join(format!("file-{index:04}.bin")), b"world");
        paths.push(common::path_string(&path));
    }

    let cancel = Arc::new(AtomicBool::new(false));
    let cancel_from_progress = cancel.clone();
    let phases = Arc::new(Mutex::new(Vec::<ScanPhase>::new()));
    let phases_sink = phases.clone();
    let result = core
        .scan(
            ScanRequest {
                kind: ScanKind::Directory,
                paths: vec![common::path_string(&root)],
            },
            cancel.as_ref(),
            &move |progress| {
                phases_sink
                    .lock()
                    .expect("phases lock")
                    .push(progress.phase);
                if progress.phase == ScanPhase::Scanning && progress.scanned >= 256 {
                    cancel_from_progress.store(true, Ordering::SeqCst);
                }
            },
        )
        .expect("scan");

    assert!(result.cancelled);
    assert!(result.scanned_files > 0);
    assert!(result.scanned_files < result.total_files);
    let phases = phases.lock().expect("phases lock");
    assert_eq!(phases.last(), Some(&ScanPhase::Cancelled));
    assert!(!phases.contains(&ScanPhase::Finished));

    let history = core.history(HistoryQuery::default()).expect("history");
    assert_eq!(history.total as usize, result.scanned_files);
}

#[test]
fn core_creates_app_database_and_quarantine_directory() {
    let dir = common::temp_dir();
    let app_data = dir.path().join("app-data");
    let _core = common::make_core(&app_data, None);

    assert!(app_data.is_dir());
    assert!(app_data.join("antivirus.db").is_file());
    assert!(app_data.join("quarantine").is_dir());
}

#[test]
fn core_is_clone_send_and_sync() {
    fn assert_traits<T: Clone + Send + Sync>() {}
    assert_traits::<antivirus_core::Core>();
}

#[test]
fn file_scan_skips_directories_and_other_non_regular_paths() {
    let dir = common::temp_dir();
    let signatures = common::create_signatures(
        &dir.path().join("virus_data.db"),
        &[],
        &[],
        &[common::HELLO_SHA256],
    );
    let core = common::make_core(&dir.path().join("app-data"), Some(&signatures));
    let folder = dir.path().join("folder");
    fs::create_dir_all(&folder).expect("create folder");

    let cancel = AtomicBool::new(false);
    let result = core
        .scan(
            file_scan(vec![common::path_string(&folder)]),
            &cancel,
            &|_| {},
        )
        .expect("scan");

    assert_eq!(result.total_files, 0);
    assert_eq!(result.scanned_files, 0);
    assert!(result.errors.is_empty());
}

#[test]
fn scan_persists_hashes_and_one_run_summary() {
    let dir = common::temp_dir();
    let signatures = common::create_signatures(
        &dir.path().join("virus_data.db"),
        &[],
        &[],
        &[common::HELLO_SHA256],
    );
    let core = common::make_core(&dir.path().join("app-data"), Some(&signatures));
    let clean = common::write_file(&dir.path().join("clean.txt"), b"world");
    let infected = common::write_file(&dir.path().join("infected.bin"), b"hello");

    let cancel = AtomicBool::new(false);
    core.scan(
        file_scan(vec![
            common::path_string(&clean),
            common::path_string(&infected),
        ]),
        &cancel,
        &|_| {},
    )
    .expect("scan");

    let connection =
        Connection::open(dir.path().join("app-data/antivirus.db")).expect("open app database");
    let (md5, sha1, sha256, size): (String, String, String, i64) = connection
        .query_row(
            "SELECT md5, sha1, sha256, file_size FROM scan_history WHERE file_path = ?1",
            [common::path_string(&infected)],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .expect("persisted hashes");
    assert_eq!(md5, common::HELLO_MD5);
    assert_eq!(sha1, common::HELLO_SHA1);
    assert_eq!(sha256, common::HELLO_SHA256);
    assert_eq!(size, 5);

    let (runs, scanned, infected_count, safe, cancelled): (i64, i64, i64, i64, i64) = connection
        .query_row(
            "SELECT COUNT(*), COALESCE(SUM(scanned_files), 0),
                    COALESCE(SUM(infected_files), 0), COALESCE(SUM(safe_files), 0),
                    COALESCE(SUM(cancelled), 0)
             FROM scan_runs",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .expect("scan run summary");
    assert_eq!(
        (runs, scanned, infected_count, safe, cancelled),
        (1, 2, 1, 1, 0)
    );
}

#[test]
fn missing_signatures_is_not_a_construction_error_and_blocks_scan() {
    let dir = common::temp_dir();
    let core = common::make_core(&dir.path().join("app-data"), None);
    let file = common::write_file(&dir.path().join("hello.txt"), b"hello");

    let info = core.app_info().expect("app info");
    assert!(!info.signatures_ready);
    assert!(info.signatures_db_path.is_none());
    assert!(info.signature_counts.is_none());
    assert_eq!(info.history_count, 0);
    assert!(!info.version.is_empty());
    assert_eq!(
        info.app_data_dir,
        common::path_string(&dir.path().join("app-data"))
    );

    let cancel = AtomicBool::new(false);
    let error = core
        .scan(
            file_scan(vec![common::path_string(&file)]),
            &cancel,
            &|_| {},
        )
        .expect_err("scan without signatures");
    assert!(matches!(error, CoreError::SignaturesMissing));
}

#[test]
fn invalid_signatures_database_is_reported() {
    let dir = common::temp_dir();
    let signatures = dir.path().join("broken.db");
    fs::write(&signatures, b"this is not a sqlite database").expect("write broken db");
    let core = common::make_core(&dir.path().join("app-data"), Some(&signatures));
    let file = common::write_file(&dir.path().join("hello.txt"), b"hello");

    let info = core.app_info().expect("app info");
    assert!(!info.signatures_ready);
    assert!(info.signature_counts.is_none());

    let cancel = AtomicBool::new(false);
    let error = core
        .scan(
            file_scan(vec![common::path_string(&file)]),
            &cancel,
            &|_| {},
        )
        .expect_err("scan with broken signatures");
    assert!(matches!(error, CoreError::InvalidSignatures(_)));
}

#[test]
fn candidate_order_and_stored_setting_resolution() {
    let dir = common::temp_dir();
    let first = common::create_signatures(
        &dir.path().join("first.db"),
        &[],
        &[],
        &[common::HELLO_SHA256],
    );
    let second = common::create_signatures(
        &dir.path().join("second.db"),
        &[],
        &[],
        &[common::WORLD_SHA256],
    );
    let app_data = dir.path().join("app-data");
    let hello = common::write_file(&dir.path().join("hello.txt"), b"hello");
    let world = common::write_file(&dir.path().join("world.txt"), b"world");

    let core = antivirus_core::Core::new(&app_data, vec![first.clone(), second.clone()])
        .expect("core with candidates");
    let info = core.app_info().expect("app info");
    assert_eq!(
        info.signatures_db_path.as_deref(),
        Some(common::path_string(&first).as_str())
    );
    assert!(info.signatures_ready);
    assert_eq!(
        info.signature_counts.expect("counts").sha256,
        1,
        "candidate counts are read from the first existing database"
    );

    let cancel = AtomicBool::new(false);
    let hello_scan = core
        .scan(
            file_scan(vec![common::path_string(&hello)]),
            &cancel,
            &|_| {},
        )
        .expect("scan hello");
    assert_eq!(hello_scan.infected_files, 1);

    let info = core.set_signatures_db(&second).expect("set signatures");
    assert_eq!(
        info.signatures_db_path.as_deref(),
        Some(common::path_string(&second).as_str())
    );

    let hello_scan = core
        .scan(
            file_scan(vec![common::path_string(&hello)]),
            &cancel,
            &|_| {},
        )
        .expect("scan hello again");
    assert_eq!(hello_scan.infected_files, 0);
    let world_scan = core
        .scan(
            file_scan(vec![common::path_string(&world)]),
            &cancel,
            &|_| {},
        )
        .expect("scan world");
    assert_eq!(world_scan.infected_files, 1);

    drop(core);
    let reopened = antivirus_core::Core::new(&app_data, vec![first]).expect("reopen core");
    assert_eq!(
        reopened
            .app_info()
            .expect("info")
            .signatures_db_path
            .as_deref(),
        Some(common::path_string(&second).as_str()),
        "stored path wins over candidates"
    );
}

#[test]
fn creates_indexes_on_signature_hash_columns() {
    let dir = common::temp_dir();
    let signatures = common::create_signatures(
        &dir.path().join("virus_data.db"),
        &[common::HELLO_MD5],
        &[common::WORLD_SHA1],
        &[common::HELLO_SHA256],
    );
    let _core = common::make_core(&dir.path().join("app-data"), Some(&signatures));

    let connection = Connection::open(&signatures).expect("open signatures");
    assert!(has_index_on(&connection, "virus_md5", "md5_hash"));
    assert!(has_index_on(&connection, "virus_sha1", "sha1_hash"));
    assert!(has_index_on(&connection, "virus_sha256", "sha256_hash"));
}

#[cfg(unix)]
#[test]
fn scanning_works_when_signatures_database_is_read_only() {
    use std::os::unix::fs::PermissionsExt;

    let dir = common::temp_dir();
    let signatures = common::create_signatures(
        &dir.path().join("virus_data.db"),
        &[],
        &[],
        &[common::HELLO_SHA256],
    );
    fs::set_permissions(&signatures, fs::Permissions::from_mode(0o444)).expect("chmod");
    let core = common::make_core(&dir.path().join("app-data"), Some(&signatures));
    let hello = common::write_file(&dir.path().join("hello.txt"), b"hello");

    assert!(core.app_info().expect("info").signatures_ready);
    let cancel = AtomicBool::new(false);
    let result = core
        .scan(
            file_scan(vec![common::path_string(&hello)]),
            &cancel,
            &|_| {},
        )
        .expect("scan read-only signatures");
    assert_eq!(result.infected_files, 1);
}

#[test]
fn set_signatures_db_rejects_missing_paths() {
    let dir = common::temp_dir();
    let core = common::make_core(&dir.path().join("app-data"), None);
    let error = core
        .set_signatures_db(dir.path().join("missing.db"))
        .expect_err("missing signatures path");
    assert!(matches!(error, CoreError::SignaturesMissing));
}

fn has_index_on(connection: &Connection, table: &str, column: &str) -> bool {
    let mut list = connection
        .prepare(&format!("PRAGMA index_list({table})"))
        .expect("index list");
    let names: Vec<String> = list
        .query_map([], |row| row.get::<_, String>(1))
        .expect("index names")
        .collect::<rusqlite::Result<Vec<_>>>()
        .expect("collect index names");
    for name in names {
        let mut info = connection
            .prepare(&format!("PRAGMA index_info({name})"))
            .expect("index info");
        let columns: Vec<String> = info
            .query_map([], |row| row.get::<_, String>(2))
            .expect("index columns")
            .collect::<rusqlite::Result<Vec<_>>>()
            .expect("collect index columns");
        if columns.iter().any(|value| value == column) {
            return true;
        }
    }
    false
}
