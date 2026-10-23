mod commands;
mod state;

use std::path::{Path, PathBuf};

use antivirus_core::Core;
use tauri::Manager;

use crate::state::AppState;

const SIGNATURES_FILE_NAME: &str = "virus_data.db";
const SIGNATURES_ENV_VAR: &str = "ANTIVIRUS_SIGNATURES_DB";
const FALLBACK_APP_DATA_DIR: &str = ".antivirus-data";

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let app_data_dir = resolve_app_data_dir(app.handle());
            let core = Core::new(app_data_dir.clone(), signature_candidates(&app_data_dir))
                .map_err(|error| {
                    format!(
                        "No se pudo inicializar el almacenamiento en {}: {error}",
                        app_data_dir.display()
                    )
                })?;
            app.manage(AppState::new(core));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::app_info,
            commands::set_signatures_db,
            commands::start_scan,
            commands::cancel_scan,
            commands::get_history,
            commands::get_stats,
            commands::clear_history,
            commands::quarantine_files,
            commands::delete_files,
            commands::list_quarantine,
            commands::restore_quarantined,
            commands::export_csv,
            commands::export_pdf,
        ])
        .run(tauri::generate_context!())
        .expect("failed to run the Tauri application");
}

fn resolve_app_data_dir(app: &tauri::AppHandle) -> PathBuf {
    match app.path().app_data_dir() {
        Ok(dir) => dir,
        Err(_) => fallback_app_data_dir(),
    }
}

fn fallback_app_data_dir() -> PathBuf {
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(FALLBACK_APP_DATA_DIR)
}

fn signature_candidates(app_data_dir: &Path) -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    if let Some(from_env) = signatures_from_env() {
        push_candidate(&mut candidates, from_env);
    }
    if let Ok(cwd) = std::env::current_dir() {
        push_candidate(&mut candidates, cwd.join(SIGNATURES_FILE_NAME));
        push_candidate(&mut candidates, cwd.join("..").join(SIGNATURES_FILE_NAME));
    }
    if let Some(exe_dir) = executable_dir() {
        push_candidate(&mut candidates, exe_dir.join(SIGNATURES_FILE_NAME));
    }
    push_candidate(&mut candidates, app_data_dir.join(SIGNATURES_FILE_NAME));

    candidates
}

fn signatures_from_env() -> Option<PathBuf> {
    std::env::var_os(SIGNATURES_ENV_VAR)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn executable_dir() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf))
}

fn push_candidate(candidates: &mut Vec<PathBuf>, candidate: PathBuf) {
    if !candidates.contains(&candidate) {
        candidates.push(candidate);
    }
}
