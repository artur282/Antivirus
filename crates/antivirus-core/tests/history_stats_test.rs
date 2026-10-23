mod common;

use std::sync::atomic::AtomicBool;

use antivirus_core::{HistoryFilter, HistoryQuery, ScanKind, ScanRequest, Stats};
use chrono::Utc;

const DAY_MS: i64 = 24 * 60 * 60 * 1000;

fn scan_paths(core: &antivirus_core::Core, paths: &[std::path::PathBuf]) {
    let request = ScanRequest {
        kind: ScanKind::File,
        paths: paths
            .iter()
            .map(|path| path.to_string_lossy().into_owned())
            .collect(),
    };
    let cancel = AtomicBool::new(false);
    core.scan(request, &cancel, &|_| {}).expect("scan");
}

fn populated_core() -> (tempfile::TempDir, antivirus_core::Core) {
    let dir = common::temp_dir();
    let signatures = common::create_signatures(
        &dir.path().join("virus_data.db"),
        &[],
        &[],
        &[common::HELLO_SHA256],
    );
    let core = common::make_core(&dir.path().join("app-data"), Some(&signatures));
    let a = common::write_file(&dir.path().join("a_infected.bin"), b"hello");
    let b = common::write_file(&dir.path().join("b_safe.bin"), b"world");
    let c = common::write_file(&dir.path().join("c_safe.bin"), b"otro contenido");
    scan_paths(&core, &[a, b, c]);
    (dir, core)
}

#[test]
fn history_filters_by_status_and_paginates_deterministically() {
    let (_dir, core) = populated_core();

    let all = core
        .history(HistoryQuery {
            limit: 100,
            offset: 0,
            filter: HistoryFilter::All,
        })
        .expect("all history");
    assert_eq!(all.total, 3);
    assert_eq!(all.entries.len(), 3);
    assert!(all.entries[0].file_path.ends_with("c_safe.bin"));
    assert!(all.entries[1].file_path.ends_with("b_safe.bin"));
    assert!(all.entries[2].file_path.ends_with("a_infected.bin"));
    assert!(all.entries[0].id > all.entries[1].id);
    assert!(all.entries[1].id > all.entries[2].id);
    assert!(all.entries.iter().all(|entry| entry.scan_id.is_some()));

    let page = core
        .history(HistoryQuery {
            limit: 2,
            offset: 1,
            filter: HistoryFilter::All,
        })
        .expect("page");
    assert_eq!(page.total, 3);
    assert_eq!(page.entries.len(), 2);
    assert!(page.entries[0].file_path.ends_with("b_safe.bin"));
    assert!(page.entries[1].file_path.ends_with("a_infected.bin"));

    let infected = core
        .history(HistoryQuery {
            limit: 100,
            offset: 0,
            filter: HistoryFilter::Infected,
        })
        .expect("infected");
    assert_eq!(infected.total, 1);
    assert_eq!(infected.entries.len(), 1);
    assert!(infected.entries[0].is_infected);
    assert!(infected.entries[0].file_path.ends_with("a_infected.bin"));

    let safe = core
        .history(HistoryQuery {
            limit: 100,
            offset: 0,
            filter: HistoryFilter::Safe,
        })
        .expect("safe");
    assert_eq!(safe.total, 2);
    assert!(safe.entries.iter().all(|entry| !entry.is_infected));

    let empty_page = core
        .history(HistoryQuery {
            limit: 2,
            offset: 99,
            filter: HistoryFilter::All,
        })
        .expect("empty page");
    assert_eq!(empty_page.total, 3);
    assert!(empty_page.entries.is_empty());
}

#[test]
fn stats_cover_totals_rate_last_scan_and_fourteen_days() {
    let (_dir, core) = populated_core();
    let stats = core.stats().expect("stats");

    assert_eq!(stats.total_scanned, 3);
    assert_eq!(stats.total_infected, 1);
    assert_eq!(stats.total_safe, 2);
    assert!((stats.infection_rate - (100.0 / 3.0)).abs() < 1e-9);
    assert!(stats.last_scan_at.is_some());

    assert_eq!(stats.daily.len(), 14);
    let today = Utc::now().format("%Y-%m-%d").to_string();
    assert_eq!(stats.daily.last().expect("today").date, today);
    assert_eq!(stats.daily.last().expect("today").total, 3);
    assert_eq!(stats.daily.last().expect("today").infected, 1);
    for day in &stats.daily[..13] {
        assert_eq!(day.total, 0);
        assert_eq!(day.infected, 0);
    }
    for window in stats.daily.windows(2) {
        assert!(window[0].date < window[1].date);
    }

    let oldest = (Utc::now() - chrono::Duration::milliseconds(13 * DAY_MS))
        .format("%Y-%m-%d")
        .to_string();
    assert_eq!(stats.daily.first().expect("oldest").date, oldest);
}

#[test]
fn empty_stats_report_zero_rate_and_fourteen_empty_days() {
    let dir = common::temp_dir();
    let core = common::make_core(&dir.path().join("app-data"), None);
    let stats: Stats = core.stats().expect("stats");

    assert_eq!(stats.total_scanned, 0);
    assert_eq!(stats.total_infected, 0);
    assert_eq!(stats.total_safe, 0);
    assert_eq!(stats.infection_rate, 0.0);
    assert_eq!(stats.last_scan_at, None);
    assert_eq!(stats.daily.len(), 14);
    assert!(stats
        .daily
        .iter()
        .all(|day| day.total == 0 && day.infected == 0));
}

#[test]
fn history_survives_reopening_the_core() {
    let (dir, core) = populated_core();
    drop(core);

    let reopened =
        antivirus_core::Core::new(dir.path().join("app-data"), Vec::new()).expect("reopen");
    let page = reopened.history(HistoryQuery::default()).expect("history");
    assert_eq!(page.total, 3);
    let stats = reopened.stats().expect("stats");
    assert_eq!(stats.total_scanned, 3);
    assert!(reopened.app_info().expect("info").history_count >= 3);
}

#[test]
fn clear_history_removes_rows_and_resets_stats() {
    let (_dir, core) = populated_core();
    assert_eq!(core.clear_history().expect("clear"), 3);

    let page = core.history(HistoryQuery::default()).expect("history");
    assert_eq!(page.total, 0);
    assert!(page.entries.is_empty());

    let stats = core.stats().expect("stats");
    assert_eq!(stats.total_scanned, 0);
    assert_eq!(stats.infection_rate, 0.0);
    assert_eq!(stats.last_scan_at, None);
    assert_eq!(stats.daily.len(), 14);

    assert_eq!(core.clear_history().expect("clear again"), 0);
}

#[test]
fn failed_scan_files_are_not_persisted_as_history() {
    let dir = common::temp_dir();
    let signatures = common::create_signatures(
        &dir.path().join("virus_data.db"),
        &[],
        &[],
        &[common::HELLO_SHA256],
    );
    let core = common::make_core(&dir.path().join("app-data"), Some(&signatures));
    let missing = dir.path().join("missing.txt");

    let request = ScanRequest {
        kind: ScanKind::File,
        paths: vec![common::path_string(&missing)],
    };
    let cancel = AtomicBool::new(false);
    let result = core.scan(request, &cancel, &|_| {}).expect("scan");
    assert_eq!(result.errors.len(), 1);
    assert_eq!(result.scanned_files, 0);
    assert_eq!(
        core.history(HistoryQuery::default())
            .expect("history")
            .total,
        0
    );
}
