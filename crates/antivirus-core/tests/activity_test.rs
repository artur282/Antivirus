mod common;

use std::sync::atomic::AtomicBool;

use antivirus_core::{ScanKind, ScanRequest};
use rusqlite::Connection;

#[test]
fn activity_records_scan_quarantine_delete_clear_and_exports() {
    let dir = common::temp_dir();
    let signatures = common::create_signatures(
        &dir.path().join("virus_data.db"),
        &[],
        &[],
        &[common::HELLO_SHA256],
    );
    let app_data = dir.path().join("app-data");
    let core = common::make_core(&app_data, Some(&signatures));

    let infected = common::write_file(&dir.path().join("infected.bin"), b"hello");
    let doomed = common::write_file(&dir.path().join("doomed.txt"), b"world");

    let cancel = AtomicBool::new(false);
    core.scan(
        ScanRequest {
            kind: ScanKind::File,
            paths: vec![common::path_string(&infected)],
        },
        &cancel,
        &|_| {},
    )
    .expect("scan");
    core.quarantine_files(&[infected]).expect("quarantine");
    core.delete_files(&[doomed]).expect("delete");
    core.export_csv(&dir.path().join("report.csv"))
        .expect("export csv");
    core.export_pdf(&dir.path().join("report.pdf"))
        .expect("export pdf");
    core.clear_history().expect("clear history");
    core.log_activity("custom_marker", "detail");

    let connection = Connection::open(app_data.join("antivirus.db")).expect("open app database");
    for event in [
        "scan_start",
        "scan_finish",
        "quarantine",
        "delete",
        "export_csv",
        "export_pdf",
        "history_clear",
        "custom_marker",
    ] {
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM activity WHERE event = ?1",
                [event],
                |row| row.get(0),
            )
            .expect("activity count");
        assert_eq!(count, 1, "expected one {event} activity row");
    }
}
