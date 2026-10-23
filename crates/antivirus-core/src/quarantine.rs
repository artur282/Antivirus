use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use chrono::Utc;
use rusqlite::{params, OptionalExtension};

use crate::db;
use crate::hashing::{self, HashError};
use crate::types::{DeleteReport, FailedItem, QuarantineEntry, QuarantineReport};
use crate::{CoreError, Result};

const QUARANTINE_DIR: &str = "quarantine";

pub(crate) fn quarantine_files(
    app_data_dir: &Path,
    history_db: &Path,
    paths: &[PathBuf],
) -> Result<QuarantineReport> {
    let quarantine_dir = app_data_dir.join(QUARANTINE_DIR);
    fs::create_dir_all(&quarantine_dir)?;
    let connection = db::open(history_db)?;

    let mut moved = Vec::new();
    let mut failed = Vec::new();
    for path in paths {
        match quarantine_one(&connection, &quarantine_dir, path) {
            Ok(entry) => moved.push(entry),
            Err(error) => failed.push(FailedItem {
                path: display(path),
                message: error.to_string(),
            }),
        }
    }

    Ok(QuarantineReport { moved, failed })
}

pub(crate) fn list_quarantine(history_db: &Path) -> Result<Vec<QuarantineEntry>> {
    let connection = db::open(history_db)?;
    let mut statement = connection.prepare(
        "SELECT id, original_path, stored_path, sha256, created_at, restored_at
         FROM quarantine
         ORDER BY created_at DESC, id DESC",
    )?;
    let entries = statement
        .query_map([], entry_from_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(entries)
}

pub(crate) fn restore_quarantined(history_db: &Path, id: i64) -> Result<QuarantineEntry> {
    let connection = db::open(history_db)?;
    let mut entry = connection
        .query_row(
            "SELECT id, original_path, stored_path, sha256, created_at, restored_at
             FROM quarantine WHERE id = ?1",
            [id],
            entry_from_row,
        )
        .optional()?
        .ok_or_else(|| CoreError::NotFound(format!("entrada de cuarentena {id}")))?;

    if entry.restored_at.is_some() {
        return Err(CoreError::NotFound(format!(
            "la entrada de cuarentena {id} ya fue restaurada"
        )));
    }

    let stored_path = PathBuf::from(&entry.stored_path);
    if !stored_path.is_file() {
        return Err(CoreError::NotFound(format!(
            "el archivo en cuarentena {} ya no existe",
            entry.stored_path
        )));
    }

    let original_path = PathBuf::from(&entry.original_path);
    if original_path.symlink_metadata().is_ok() {
        return Err(CoreError::InvalidPath(format!(
            "se niega a sobrescribir el archivo existente {}",
            entry.original_path
        )));
    }
    if let Some(parent) = original_path.parent() {
        fs::create_dir_all(parent)?;
    }

    move_file(&stored_path, &original_path)?;

    let restored_at = db::now_string();
    if let Err(error) = connection.execute(
        "UPDATE quarantine SET restored_at = ?1 WHERE id = ?2",
        params![restored_at, id],
    ) {
        let _ = move_file(&original_path, &stored_path);
        return Err(error.into());
    }
    entry.restored_at = Some(restored_at);
    Ok(entry)
}

pub(crate) fn delete_files(paths: &[PathBuf]) -> Result<DeleteReport> {
    let mut deleted = Vec::new();
    let mut failed = Vec::new();
    for path in paths {
        match fs::remove_file(path) {
            Ok(()) => deleted.push(display(path)),
            Err(error) => failed.push(FailedItem {
                path: display(path),
                message: error.to_string(),
            }),
        }
    }
    Ok(DeleteReport { deleted, failed })
}

fn quarantine_one(
    connection: &rusqlite::Connection,
    quarantine_dir: &Path,
    path: &Path,
) -> Result<QuarantineEntry> {
    let hashed = hashing::hash_file(path).map_err(|error| match error {
        HashError::Skipped => {
            CoreError::InvalidPath(format!("{} no es un archivo regular", display(path)))
        }
        HashError::Failed(message) => {
            CoreError::InvalidPath(format!("no se pudo leer {}: {message}", display(path)))
        }
    })?;

    let stored_path = unique_stored_path(quarantine_dir, path, &hashed.sha256);
    move_file(path, &stored_path)?;

    let created_at = db::now_string();
    let insert = connection.execute(
        "INSERT INTO quarantine (original_path, stored_path, sha256, created_at)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            display(path),
            display(&stored_path),
            hashed.sha256,
            created_at
        ],
    );
    if let Err(error) = insert {
        let _ = move_file(&stored_path, path);
        return Err(error.into());
    }

    Ok(QuarantineEntry {
        id: connection.last_insert_rowid(),
        original_path: display(path),
        stored_path: display(&stored_path),
        sha256: hashed.sha256,
        created_at,
        restored_at: None,
    })
}

fn unique_stored_path(quarantine_dir: &Path, original: &Path, sha256: &str) -> PathBuf {
    let basename = original
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("archivo");
    let short_hash = &sha256[..sha256.len().min(8)];
    let stamp = Utc::now()
        .format("%Y%m%dT%H%M%S%.3fZ")
        .to_string()
        .replace('.', "");

    let mut candidate = quarantine_dir.join(format!("{stamp}_{short_hash}_{basename}"));
    let mut attempt = 0_u32;
    while candidate.exists() {
        attempt += 1;
        candidate = quarantine_dir.join(format!("{stamp}_{short_hash}_{attempt}_{basename}"));
    }
    candidate
}

/// Renames a file, falling back to copy + remove when source and destination
/// live on different devices.
fn move_file(from: &Path, to: &Path) -> std::io::Result<()> {
    match fs::rename(from, to) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::CrossesDevices => {
            fs::copy(from, to)?;
            fs::remove_file(from)?;
            Ok(())
        }
        Err(error) => Err(error),
    }
}

fn entry_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<QuarantineEntry> {
    Ok(QuarantineEntry {
        id: row.get(0)?,
        original_path: row.get(1)?,
        stored_path: row.get(2)?,
        sha256: row.get(3)?,
        created_at: row.get(4)?,
        restored_at: row.get(5)?,
    })
}

fn display(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}
