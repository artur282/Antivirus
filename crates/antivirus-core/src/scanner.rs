use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use rayon::prelude::*;
use rusqlite::{params, Connection, Statement};
use uuid::Uuid;
use walkdir::WalkDir;

use crate::db;
use crate::hashing::{self, HashError, HashedFile};
use crate::types::{
    ScanFailure, ScanKind, ScanPhase, ScanProgress, ScanRequest, ScanResult, Threat,
};
use crate::{CoreError, Result};

const HASH_CHUNK_SIZE: usize = 256;
const PROGRESS_FILE_INTERVAL: usize = 25;
const PROGRESS_TIME_INTERVAL: Duration = Duration::from_millis(100);

/// Runs a whole scan: collection, hashing, signature lookup, history and the
/// terminal progress event. Fatal problems are reported as `Error` progress
/// events and returned as errors; per-file problems only become `ScanFailure`
/// entries.
pub(crate) fn run(
    history_db: &Path,
    signatures_db: Option<&Path>,
    request: ScanRequest,
    cancel: &AtomicBool,
    progress: &(dyn Fn(ScanProgress) + Send + Sync),
) -> Result<ScanResult> {
    let scan_id = Uuid::new_v4().to_string();
    let started = Instant::now();
    let started_at = db::now_string();
    let mut emitter = ProgressEmitter::new(&scan_id, progress);

    emitter.force(
        ScanPhase::Preparing,
        0,
        0,
        0,
        "",
        Some("Preparando escaneo"),
    );

    let Some(signatures_db) = signatures_db else {
        return fail_without_signatures(&mut emitter);
    };
    if !signatures_db.is_file() {
        return fail_without_signatures(&mut emitter);
    }
    if let Err(error) = db::validate_signatures(signatures_db) {
        emitter.force(ScanPhase::Error, 0, 0, 0, "", Some(&error.to_string()));
        return Err(error);
    }

    emitter.force(
        ScanPhase::Collecting,
        0,
        0,
        0,
        "",
        Some("Recopilando archivos"),
    );
    let collection = collect(&request, cancel);
    let files = collection.files;
    let total = files.len();
    emitter.force(
        ScanPhase::Collecting,
        0,
        total,
        0,
        "",
        Some("Recopilando archivos"),
    );

    if collection.cancelled {
        let summary = RunSummary {
            scan_id: &scan_id,
            kind: kind_name(request.kind),
            started_at: &started_at,
            total,
            scanned: 0,
            infected: 0,
            safe: 0,
            cancelled: true,
            duration_ms: elapsed_ms(started),
        };
        if let Err(error) = record_run(history_db, &summary) {
            emitter.force(ScanPhase::Error, 0, total, 0, "", Some(&error.to_string()));
            return Err(error);
        }
        emitter.force(ScanPhase::Cancelled, 0, total, 0, "", None);
        return Ok(ScanResult {
            scan_id,
            kind: request.kind,
            total_files: total,
            scanned_files: 0,
            infected_files: 0,
            safe_files: 0,
            cancelled: true,
            duration_ms: elapsed_ms(started),
            threats: Vec::new(),
            errors: collection.errors,
        });
    }

    let outcome = scan_files(
        history_db,
        signatures_db,
        &scan_id,
        &started_at,
        &files,
        collection.errors,
        cancel,
        &mut emitter,
    );

    match outcome {
        Ok(outcome) => {
            let safe_files = outcome.scanned.saturating_sub(outcome.infected);
            let duration_ms = elapsed_ms(started);
            let summary = RunSummary {
                scan_id: &scan_id,
                kind: kind_name(request.kind),
                started_at: &started_at,
                total,
                scanned: outcome.scanned,
                infected: outcome.infected,
                safe: safe_files,
                cancelled: outcome.cancelled,
                duration_ms,
            };
            if let Err(error) = record_run(history_db, &summary) {
                emitter.force(ScanPhase::Error, 0, total, 0, "", Some(&error.to_string()));
                return Err(error);
            }

            let phase = if outcome.cancelled {
                ScanPhase::Cancelled
            } else {
                ScanPhase::Finished
            };
            emitter.force(phase, outcome.scanned, total, outcome.infected, "", None);

            Ok(ScanResult {
                scan_id,
                kind: request.kind,
                total_files: total,
                scanned_files: outcome.scanned,
                infected_files: outcome.infected,
                safe_files,
                cancelled: outcome.cancelled,
                duration_ms,
                threats: outcome.threats,
                errors: outcome.errors,
            })
        }
        Err(error) => {
            emitter.force(ScanPhase::Error, 0, total, 0, "", Some(&error.to_string()));
            Err(error)
        }
    }
}

fn fail_without_signatures(emitter: &mut ProgressEmitter<'_>) -> Result<ScanResult> {
    emitter.force(
        ScanPhase::Error,
        0,
        0,
        0,
        "",
        Some("No se encontró la base de firmas; elija virus_data.db para escanear"),
    );
    Err(CoreError::SignaturesMissing)
}

struct ScanOutcome {
    scanned: usize,
    infected: usize,
    threats: Vec<Threat>,
    errors: Vec<ScanFailure>,
    cancelled: bool,
}

#[allow(clippy::too_many_arguments)]
fn scan_files(
    history_db: &Path,
    signatures_db: &Path,
    scan_id: &str,
    scan_date: &str,
    files: &[PathBuf],
    mut errors: Vec<ScanFailure>,
    cancel: &AtomicBool,
    emitter: &mut ProgressEmitter<'_>,
) -> Result<ScanOutcome> {
    let mut history_connection = db::open(history_db)?;
    let signature_connection = db::open_read_only(signatures_db)?;
    let mut md5_statement =
        signature_connection.prepare("SELECT 1 FROM virus_md5 WHERE md5_hash = ?1 LIMIT 1")?;
    let mut sha1_statement =
        signature_connection.prepare("SELECT 1 FROM virus_sha1 WHERE sha1_hash = ?1 LIMIT 1")?;
    let mut sha256_statement = signature_connection
        .prepare("SELECT 1 FROM virus_sha256 WHERE sha256_hash = ?1 LIMIT 1")?;

    let total = files.len();
    let mut scanned = 0_usize;
    let mut infected = 0_usize;
    let mut threats = Vec::new();
    let mut cancelled = false;

    emitter.force(
        ScanPhase::Scanning,
        0,
        total,
        0,
        "",
        Some("Escaneando archivos"),
    );

    for chunk in files.chunks(HASH_CHUNK_SIZE) {
        if cancel.load(Ordering::Relaxed) {
            cancelled = true;
            break;
        }

        let hashed: Vec<(PathBuf, std::result::Result<HashedFile, HashError>)> = chunk
            .par_iter()
            .map(|path| (path.clone(), hashing::hash_file(path)))
            .collect();

        let transaction = history_connection.transaction()?;
        {
            let mut insert = transaction.prepare(
                "INSERT INTO scan_history
                 (scan_id, file_path, is_infected, scan_date, md5, sha1, sha256, file_size)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )?;
            for (path, hashed_file) in hashed {
                let hashed_file = match hashed_file {
                    Ok(file) => file,
                    Err(HashError::Skipped) => continue,
                    Err(HashError::Failed(message)) => {
                        errors.push(ScanFailure {
                            path: path_string(&path),
                            message,
                        });
                        continue;
                    }
                };

                let matched = matched_hashes(
                    &mut md5_statement,
                    &mut sha1_statement,
                    &mut sha256_statement,
                    &hashed_file,
                )?;
                let is_infected = !matched.is_empty();
                insert.execute(params![
                    scan_id,
                    path_string(&path),
                    is_infected as i64,
                    scan_date,
                    hashed_file.md5,
                    hashed_file.sha1,
                    hashed_file.sha256,
                    hashed_file.size as i64,
                ])?;

                scanned += 1;
                if is_infected {
                    infected += 1;
                    threats.push(Threat {
                        path: path_string(&path),
                        md5: hashed_file.md5,
                        sha1: hashed_file.sha1,
                        sha256: hashed_file.sha256,
                        size: hashed_file.size,
                        matched,
                    });
                }

                if emitter.is_due(scanned) {
                    emitter.force(
                        ScanPhase::Scanning,
                        scanned,
                        total,
                        infected,
                        &path_string(&path),
                        None,
                    );
                }
            }
        }
        transaction.commit()?;

        emitter.force(ScanPhase::Scanning, scanned, total, infected, "", None);
    }

    Ok(ScanOutcome {
        scanned,
        infected,
        threats,
        errors,
        cancelled,
    })
}

fn matched_hashes(
    md5: &mut Statement<'_>,
    sha1: &mut Statement<'_>,
    sha256: &mut Statement<'_>,
    file: &HashedFile,
) -> Result<Vec<String>> {
    let mut matched = Vec::new();
    if md5.exists([file.md5.as_str()])? {
        matched.push("md5".to_string());
    }
    if sha1.exists([file.sha1.as_str()])? {
        matched.push("sha1".to_string());
    }
    if sha256.exists([file.sha256.as_str()])? {
        matched.push("sha256".to_string());
    }
    Ok(matched)
}

struct RunSummary<'a> {
    scan_id: &'a str,
    kind: &'a str,
    started_at: &'a str,
    total: usize,
    scanned: usize,
    infected: usize,
    safe: usize,
    cancelled: bool,
    duration_ms: u64,
}

fn record_run(history_db: &Path, summary: &RunSummary<'_>) -> Result<()> {
    let connection = db::open(history_db)?;
    record_scan_run(&connection, summary)
}

fn record_scan_run(connection: &Connection, summary: &RunSummary<'_>) -> Result<()> {
    connection.execute(
        "INSERT INTO scan_runs
         (scan_id, kind, started_at, finished_at, total_files, scanned_files,
          infected_files, safe_files, cancelled, duration_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            summary.scan_id,
            summary.kind,
            summary.started_at,
            db::now_string(),
            summary.total as i64,
            summary.scanned as i64,
            summary.infected as i64,
            summary.safe as i64,
            summary.cancelled as i64,
            summary.duration_ms as i64,
        ],
    )?;
    Ok(())
}

fn kind_name(kind: ScanKind) -> &'static str {
    match kind {
        ScanKind::File => "file",
        ScanKind::Directory => "directory",
        ScanKind::Quick => "quick",
        ScanKind::Full => "full",
    }
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

struct Collection {
    files: Vec<PathBuf>,
    errors: Vec<ScanFailure>,
    cancelled: bool,
}

fn collect(request: &ScanRequest, cancel: &AtomicBool) -> Collection {
    let mut files = BTreeSet::new();
    let mut errors = Vec::new();
    let mut cancelled = false;

    match request.kind {
        ScanKind::File => {
            for raw in &request.paths {
                if cancel.load(Ordering::Relaxed) {
                    cancelled = true;
                    break;
                }
                collect_explicit_file(Path::new(raw), &mut files, &mut errors);
            }
        }
        ScanKind::Directory => {
            for raw in &request.paths {
                if cancelled {
                    break;
                }
                let root = PathBuf::from(raw);
                if !root.exists() {
                    errors.push(ScanFailure {
                        path: path_string(&root),
                        message: "la ruta no existe".to_string(),
                    });
                    continue;
                }
                cancelled |= walk_into(
                    &root,
                    &mut files,
                    &mut errors,
                    cancel,
                    WalkRules {
                        apply_full_exclusions: false,
                        extensions: None,
                        skip_missing_root: false,
                    },
                );
            }
        }
        ScanKind::Quick => {
            for root in quick_roots() {
                if cancelled {
                    break;
                }
                if !Path::new(root).exists() {
                    continue;
                }
                cancelled |= walk_into(
                    Path::new(root),
                    &mut files,
                    &mut errors,
                    cancel,
                    WalkRules {
                        apply_full_exclusions: false,
                        extensions: Some(quick_extensions()),
                        skip_missing_root: true,
                    },
                );
            }
        }
        ScanKind::Full => {
            for root in full_roots() {
                if cancelled {
                    break;
                }
                if !Path::new(root).exists() {
                    continue;
                }
                cancelled |= walk_into(
                    Path::new(root),
                    &mut files,
                    &mut errors,
                    cancel,
                    WalkRules {
                        apply_full_exclusions: true,
                        extensions: None,
                        skip_missing_root: true,
                    },
                );
            }
        }
    }

    Collection {
        files: files.into_iter().collect(),
        errors,
        cancelled,
    }
}

fn collect_explicit_file(
    path: &Path,
    files: &mut BTreeSet<PathBuf>,
    errors: &mut Vec<ScanFailure>,
) {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            files.insert(path.to_path_buf());
        }
        Ok(_) => {}
        Err(error) => errors.push(ScanFailure {
            path: path_string(path),
            message: error.to_string(),
        }),
    }
}

struct WalkRules {
    apply_full_exclusions: bool,
    /// `None` accepts every regular file; `Some(&[])` also accepts every file.
    extensions: Option<&'static [&'static str]>,
    skip_missing_root: bool,
}

/// Walks a root recursively and returns `true` when cancellation was observed.
fn walk_into(
    root: &Path,
    files: &mut BTreeSet<PathBuf>,
    errors: &mut Vec<ScanFailure>,
    cancel: &AtomicBool,
    rules: WalkRules,
) -> bool {
    if !root.exists() {
        if !rules.skip_missing_root {
            errors.push(ScanFailure {
                path: path_string(root),
                message: "la ruta no existe".to_string(),
            });
        }
        return false;
    }

    let walker = WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| !rules.apply_full_exclusions || !full_scan_excluded(entry.path()));

    for entry in walker {
        if cancel.load(Ordering::Relaxed) {
            return true;
        }
        match entry {
            Ok(entry) => {
                if !entry.file_type().is_file() {
                    continue;
                }
                if !matches_extensions(entry.path(), rules.extensions) {
                    continue;
                }
                files.insert(entry.into_path());
            }
            Err(error) => {
                let path = error
                    .path()
                    .map(path_string)
                    .unwrap_or_else(|| path_string(root));
                errors.push(ScanFailure {
                    path,
                    message: error.to_string(),
                });
            }
        }
    }
    false
}

fn matches_extensions(path: &Path, extensions: Option<&'static [&'static str]>) -> bool {
    let Some(extensions) = extensions else {
        return true;
    };
    if extensions.is_empty() {
        return true;
    }
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::to_lowercase)
        .unwrap_or_default();
    extensions.iter().any(|extension| name.ends_with(extension))
}

fn full_scan_excluded(path: &Path) -> bool {
    if full_excluded_roots()
        .iter()
        .any(|excluded| path.starts_with(excluded))
    {
        return true;
    }
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    name.starts_with('.')
        || has_hidden_attribute(path)
        || name.ends_with(".tmp")
        || name.ends_with(".cache")
        || name.ends_with(".log")
        || name.ends_with('~')
}

#[cfg(target_os = "windows")]
fn has_hidden_attribute(path: &Path) -> bool {
    const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
    use std::os::windows::fs::MetadataExt;
    fs::symlink_metadata(path)
        .map(|metadata| metadata.file_attributes() & FILE_ATTRIBUTE_HIDDEN != 0)
        .unwrap_or(false)
}

#[cfg(not(target_os = "windows"))]
fn has_hidden_attribute(_path: &Path) -> bool {
    false
}

#[cfg(target_os = "linux")]
fn full_excluded_roots() -> &'static [&'static str] {
    &[
        "/proc",
        "/sys",
        "/dev",
        "/run",
        "/tmp",
        "/var/cache",
        "/var/tmp",
    ]
}

#[cfg(target_os = "windows")]
fn full_excluded_roots() -> &'static [&'static str] {
    &["C:\\Windows\\WinSxS"]
}

#[cfg(target_os = "macos")]
fn full_excluded_roots() -> &'static [&'static str] {
    &[]
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
fn full_excluded_roots() -> &'static [&'static str] {
    &[]
}

#[cfg(target_os = "linux")]
fn quick_roots() -> &'static [&'static str] {
    &["/usr/bin", "/usr/local/bin"]
}

#[cfg(target_os = "windows")]
fn quick_roots() -> &'static [&'static str] {
    &[
        "C:\\Windows\\System32",
        "C:\\Program Files",
        "C:\\Program Files (x86)",
    ]
}

#[cfg(target_os = "macos")]
fn quick_roots() -> &'static [&'static str] {
    &[
        "/Applications",
        "/System/Library/CoreServices",
        "/usr/local/bin",
    ]
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
fn quick_roots() -> &'static [&'static str] {
    &["/usr/bin"]
}

#[cfg(target_os = "linux")]
fn quick_extensions() -> &'static [&'static str] {
    &[".sh", ".bin"]
}

#[cfg(target_os = "windows")]
fn quick_extensions() -> &'static [&'static str] {
    &[".exe", ".dll", ".bat", ".com", ".scr", ".msi"]
}

#[cfg(target_os = "macos")]
fn quick_extensions() -> &'static [&'static str] {
    &[]
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
fn quick_extensions() -> &'static [&'static str] {
    &[]
}

#[cfg(target_os = "linux")]
fn full_roots() -> &'static [&'static str] {
    &["/"]
}

#[cfg(target_os = "windows")]
fn full_roots() -> &'static [&'static str] {
    &["C:\\"]
}

#[cfg(target_os = "macos")]
fn full_roots() -> &'static [&'static str] {
    &["/Applications", "/Library", "/System", "/usr", "/Users"]
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
fn full_roots() -> &'static [&'static str] {
    &["/"]
}

struct ProgressEmitter<'a> {
    scan_id: &'a str,
    callback: &'a (dyn Fn(ScanProgress) + Send + Sync),
    last_emit: Instant,
    last_scanned: usize,
}

impl<'a> ProgressEmitter<'a> {
    fn new(
        scan_id: &'a str,
        callback: &'a (dyn Fn(ScanProgress) + Send + Sync),
    ) -> ProgressEmitter<'a> {
        ProgressEmitter {
            scan_id,
            callback,
            last_emit: Instant::now(),
            last_scanned: 0,
        }
    }

    fn force(
        &mut self,
        phase: ScanPhase,
        scanned: usize,
        total: usize,
        infected: usize,
        current_path: &str,
        message: Option<&str>,
    ) {
        self.last_emit = Instant::now();
        self.last_scanned = scanned;
        (self.callback)(ScanProgress {
            scan_id: self.scan_id.to_string(),
            phase,
            scanned,
            total,
            infected,
            current_path: current_path.to_string(),
            message: message.map(str::to_string),
        });
    }

    fn is_due(&self, scanned: usize) -> bool {
        scanned.saturating_sub(self.last_scanned) >= PROGRESS_FILE_INTERVAL
            || self.last_emit.elapsed() >= PROGRESS_TIME_INTERVAL
    }
}
