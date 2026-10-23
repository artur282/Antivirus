use std::path::Path;
use std::time::Duration;

use rusqlite::{params, Connection, OpenFlags, OptionalExtension};

use crate::{CoreError, Result, SignatureCounts};

pub(crate) const SIGNATURES_SETTING: &str = "signatures_db";

const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

const APP_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS scan_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    total_files INTEGER NOT NULL,
    scanned_files INTEGER NOT NULL,
    infected_files INTEGER NOT NULL,
    safe_files INTEGER NOT NULL,
    cancelled INTEGER NOT NULL,
    duration_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT,
    file_path TEXT NOT NULL,
    is_infected INTEGER NOT NULL,
    scan_date TEXT NOT NULL,
    md5 TEXT,
    sha1 TEXT,
    sha256 TEXT,
    file_size INTEGER
);
CREATE INDEX IF NOT EXISTS idx_scan_history_date ON scan_history(scan_date DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_scan_history_infected ON scan_history(is_infected);
CREATE TABLE IF NOT EXISTS quarantine (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    original_path TEXT NOT NULL,
    stored_path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    created_at TEXT NOT NULL,
    restored_at TEXT
);
CREATE TABLE IF NOT EXISTS activity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event TEXT NOT NULL,
    detail TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
";

pub(crate) fn now_string() -> String {
    chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

pub(crate) fn open(path: &Path) -> Result<Connection> {
    let connection = Connection::open(path)?;
    connection.busy_timeout(BUSY_TIMEOUT)?;
    Ok(connection)
}

pub(crate) fn open_read_only(path: &Path) -> Result<Connection> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    connection.busy_timeout(BUSY_TIMEOUT)?;
    Ok(connection)
}

pub(crate) fn init(path: &Path) -> Result<()> {
    let connection = open(path)?;
    connection.execute_batch(APP_SCHEMA)?;
    Ok(())
}

pub(crate) fn get_setting(connection: &Connection, key: &str) -> Result<Option<String>> {
    let value = connection
        .query_row("SELECT value FROM settings WHERE key = ?1", [key], |row| {
            row.get::<_, String>(0)
        })
        .optional()?;
    Ok(value)
}

pub(crate) fn set_setting(connection: &Connection, key: &str, value: &str) -> Result<()> {
    connection.execute(
        "INSERT INTO settings (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}

/// Inserts one audit event. Callers that must never break a user action
/// ignore the returned error.
pub(crate) fn insert_activity(path: &Path, event: &str, detail: &str) -> Result<()> {
    let connection = open(path)?;
    connection.execute(
        "INSERT INTO activity (event, detail, created_at) VALUES (?1, ?2, ?3)",
        params![event, detail, now_string()],
    )?;
    Ok(())
}

/// Validates the three signature tables and returns their row counts.
/// Index creation happens afterwards and is best-effort so a read-only
/// signature database still scans fine.
pub(crate) fn validate_signatures(path: &Path) -> Result<SignatureCounts> {
    let connection = open_read_only(path)
        .map_err(|error| CoreError::InvalidSignatures(format!("{}: {error}", path.display())))?;

    let counts = read_signature_counts(&connection)
        .map_err(|error| CoreError::InvalidSignatures(error.to_string()))?;
    drop(connection);
    ensure_signature_indexes(path);
    Ok(counts)
}

/// Creates the lookup indexes once. Any failure (read-only database, locked
/// file, older SQLite) is intentionally ignored: scanning still works without
/// indexes, and signature rows are never modified.
pub(crate) fn ensure_signature_indexes(path: &Path) {
    let Ok(connection) = Connection::open(path) else {
        return;
    };
    let _ = connection.busy_timeout(BUSY_TIMEOUT);
    let _ = connection.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_virus_md5_hash ON virus_md5(md5_hash);
         CREATE INDEX IF NOT EXISTS idx_virus_sha1_hash ON virus_sha1(sha1_hash);
         CREATE INDEX IF NOT EXISTS idx_virus_sha256_hash ON virus_sha256(sha256_hash);",
    );
}

fn read_signature_counts(connection: &Connection) -> rusqlite::Result<SignatureCounts> {
    for (table, column) in SIGNATURE_TABLES {
        if !table_has_column(connection, table, column)? {
            return Err(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_ERROR),
                Some(format!(
                    "missing signature table or column: {table}.{column}"
                )),
            ));
        }
    }

    Ok(SignatureCounts {
        md5: count_rows(connection, "virus_md5")?,
        sha1: count_rows(connection, "virus_sha1")?,
        sha256: count_rows(connection, "virus_sha256")?,
    })
}

const SIGNATURE_TABLES: [(&str, &str); 3] = [
    ("virus_md5", "md5_hash"),
    ("virus_sha1", "sha1_hash"),
    ("virus_sha256", "sha256_hash"),
];

fn table_has_column(connection: &Connection, table: &str, column: &str) -> rusqlite::Result<bool> {
    let exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
        [table],
        |row| row.get(0),
    )?;
    if !exists {
        return Ok(false);
    }
    let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
    let columns: Vec<String> = statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(columns.iter().any(|name| name == column))
}

fn count_rows(connection: &Connection, table: &str) -> rusqlite::Result<u64> {
    let count: i64 = connection.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
        row.get(0)
    })?;
    Ok(count.max(0) as u64)
}
