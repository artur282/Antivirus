//! Pure Rust core for the antivirus desktop app.
//!
//! This crate deliberately has no Tauri dependency so that scanning, signature
//! lookup, history, reports and quarantine can be unit-tested on machines where
//! the GUI system libraries are not installed.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, RwLock};

pub mod db;
pub mod hashing;
pub mod quarantine;
pub mod report;
pub mod scanner;
pub mod stats;
pub mod types;

pub use types::*;

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("file system error: {0}")]
    Io(#[from] std::io::Error),
    #[error("signature database not found; extract virus_data.db.7z or choose the database file")]
    SignaturesMissing,
    #[error("signature database is invalid: {0}")]
    InvalidSignatures(String),
    #[error("invalid path: {0}")]
    InvalidPath(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("report error: {0}")]
    Report(String),
}

pub type Result<T> = std::result::Result<T, CoreError>;

#[derive(Debug)]
struct AppPaths {
    app_data_dir: PathBuf,
    history_db: PathBuf,
    signatures_db: RwLock<Option<PathBuf>>,
}

/// Entry point used by the Tauri shell. Cheap to clone and safe to share.
#[derive(Debug, Clone)]
pub struct Core {
    paths: Arc<AppPaths>,
}

impl Core {
    /// Creates the app data directory and history database. The signature
    /// database is resolved from a previously stored setting or the provided
    /// candidate paths (first existing file wins).
    pub fn new(
        app_data_dir: impl Into<PathBuf>,
        signature_candidates: Vec<PathBuf>,
    ) -> Result<Self> {
        let app_data_dir = app_data_dir.into();
        fs::create_dir_all(&app_data_dir)?;
        fs::create_dir_all(app_data_dir.join("quarantine"))?;

        let history_db = app_data_dir.join("antivirus.db");
        db::init(&history_db)?;

        let connection = db::open(&history_db)?;
        let stored = db::get_setting(&connection, db::SIGNATURES_SETTING)?;
        drop(connection);

        let signatures_db = match stored {
            Some(path) => Some(PathBuf::from(path)),
            None => signature_candidates
                .into_iter()
                .find(|candidate| candidate.is_file()),
        };

        if let Some(path) = &signatures_db {
            if !path.is_file() {
                let _ =
                    db::insert_activity(&history_db, "signatures_missing", &path.to_string_lossy());
            } else {
                db::ensure_signature_indexes(path);
                if let Ok(connection) = db::open(&history_db) {
                    // A read-only/hostile app database must not prevent startup.
                    let _ = db::set_setting(
                        &connection,
                        db::SIGNATURES_SETTING,
                        &path.to_string_lossy(),
                    );
                }
            }
        }

        Ok(Self {
            paths: Arc::new(AppPaths {
                app_data_dir,
                history_db,
                signatures_db: RwLock::new(signatures_db),
            }),
        })
    }

    /// Returns metadata used by the dashboard header and the onboarding state.
    pub fn app_info(&self) -> Result<AppInfo> {
        let signatures_path = self.signatures_path();
        let (signatures_ready, signature_counts) = match signatures_path.as_deref() {
            Some(path) if path.is_file() => match db::validate_signatures(path) {
                Ok(counts) => (true, Some(counts)),
                Err(_) => (false, None),
            },
            _ => (false, None),
        };

        let history_count = {
            let connection = db::open(&self.paths.history_db)?;
            let count: i64 =
                connection.query_row("SELECT COUNT(*) FROM scan_history", [], |row| row.get(0))?;
            count.max(0) as u64
        };

        Ok(AppInfo {
            version: env!("CARGO_PKG_VERSION").to_string(),
            signatures_db_path: signatures_path.map(|path| path.to_string_lossy().into_owned()),
            signatures_ready,
            signature_counts,
            history_count,
            app_data_dir: self.paths.app_data_dir.to_string_lossy().into_owned(),
        })
    }

    /// Validates and stores a user-selected signature database path.
    pub fn set_signatures_db(&self, path: impl Into<PathBuf>) -> Result<AppInfo> {
        let path = path.into();
        if !path.is_file() {
            return Err(CoreError::SignaturesMissing);
        }
        db::validate_signatures(&path)?;

        let connection = db::open(&self.paths.history_db)?;
        db::set_setting(&connection, db::SIGNATURES_SETTING, &path.to_string_lossy())?;
        drop(connection);

        let mut stored = self
            .paths
            .signatures_db
            .write()
            .expect("signature path lock");
        *stored = Some(path);
        drop(stored);

        self.app_info()
    }

    /// Scans the requested paths. `progress` is invoked from worker threads and
    /// must be thread-safe; the shell forwards it as a Tauri event.
    pub fn scan(
        &self,
        request: ScanRequest,
        cancel: &AtomicBool,
        progress: &(dyn Fn(ScanProgress) + Send + Sync),
    ) -> Result<ScanResult> {
        let detail = format!("{:?}: {} ruta(s)", request.kind, request.paths.len());
        self.log_activity("scan_start", &detail);

        let signatures_path = self.signatures_path();
        let result = scanner::run(
            &self.paths.history_db,
            signatures_path.as_deref(),
            request,
            cancel,
            progress,
        );

        match &result {
            Ok(scan) if scan.cancelled => self.log_activity(
                "scan_cancelled",
                &format!(
                    "{}: {} archivos, {} infectados",
                    scan.scan_id, scan.scanned_files, scan.infected_files
                ),
            ),
            Ok(scan) => self.log_activity(
                "scan_finish",
                &format!(
                    "{}: {} archivos, {} infectados",
                    scan.scan_id, scan.scanned_files, scan.infected_files
                ),
            ),
            Err(error) => self.log_activity("scan_error", &error.to_string()),
        }

        result
    }

    pub fn history(&self, query: HistoryQuery) -> Result<HistoryPage> {
        let connection = db::open(&self.paths.history_db)?;
        let filter_clause = match query.filter {
            HistoryFilter::All => "",
            HistoryFilter::Infected => " WHERE is_infected = 1",
            HistoryFilter::Safe => " WHERE is_infected = 0",
        };

        let total: i64 = connection.query_row(
            &format!("SELECT COUNT(*) FROM scan_history{filter_clause}"),
            [],
            |row| row.get(0),
        )?;

        let limit = i64::try_from(query.limit).unwrap_or(i64::MAX);
        let offset = i64::try_from(query.offset).unwrap_or(i64::MAX);
        let mut statement = connection.prepare(&format!(
            "SELECT id, scan_id, file_path, is_infected, scan_date
             FROM scan_history{filter_clause}
             ORDER BY scan_date DESC, id DESC
             LIMIT ?1 OFFSET ?2"
        ))?;
        let entries = statement
            .query_map([limit, offset], |row| {
                Ok(HistoryEntry {
                    id: row.get(0)?,
                    scan_id: row.get(1)?,
                    file_path: row.get(2)?,
                    is_infected: row.get::<_, i64>(3)? != 0,
                    scan_date: row.get(4)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        Ok(HistoryPage {
            total: total.max(0) as u64,
            entries,
        })
    }

    pub fn stats(&self) -> Result<Stats> {
        stats::compute(&self.paths.history_db)
    }

    /// Deletes all history rows and returns how many were removed.
    pub fn clear_history(&self) -> Result<u64> {
        let connection = db::open(&self.paths.history_db)?;
        let removed = connection.execute("DELETE FROM scan_history", [])?;
        drop(connection);
        self.log_activity("history_clear", &format!("{removed} registro(s)"));
        Ok(removed as u64)
    }

    pub fn quarantine_files(&self, paths: &[PathBuf]) -> Result<QuarantineReport> {
        let report =
            quarantine::quarantine_files(&self.paths.app_data_dir, &self.paths.history_db, paths)?;
        self.log_activity(
            "quarantine",
            &format!(
                "{} movido(s), {} fallo(s)",
                report.moved.len(),
                report.failed.len()
            ),
        );
        Ok(report)
    }

    pub fn list_quarantine(&self) -> Result<Vec<QuarantineEntry>> {
        quarantine::list_quarantine(&self.paths.history_db)
    }

    pub fn restore_quarantined(&self, id: i64) -> Result<QuarantineEntry> {
        let entry = quarantine::restore_quarantined(&self.paths.history_db, id)?;
        self.log_activity("quarantine_restore", &entry.original_path);
        Ok(entry)
    }

    pub fn delete_files(&self, paths: &[PathBuf]) -> Result<DeleteReport> {
        let report = quarantine::delete_files(paths)?;
        self.log_activity(
            "delete",
            &format!(
                "{} eliminado(s), {} fallo(s)",
                report.deleted.len(),
                report.failed.len()
            ),
        );
        Ok(report)
    }

    pub fn export_csv(&self, path: &Path) -> Result<()> {
        report::export_csv(&self.paths.history_db, path)?;
        self.log_activity("export_csv", &path.to_string_lossy());
        Ok(())
    }

    pub fn export_pdf(&self, path: &Path) -> Result<()> {
        report::export_pdf(&self.paths.history_db, path)?;
        self.log_activity("export_pdf", &path.to_string_lossy());
        Ok(())
    }

    /// Best-effort audit trail; failures never break a user action.
    pub fn log_activity(&self, event: &str, detail: &str) {
        let _ = db::insert_activity(&self.paths.history_db, event, detail);
    }

    fn signatures_path(&self) -> Option<PathBuf> {
        self.paths
            .signatures_db
            .read()
            .expect("signature path lock")
            .clone()
    }
}
