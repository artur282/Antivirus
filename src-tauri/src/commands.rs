use std::path::PathBuf;
use std::sync::Arc;

use antivirus_core::{
    AppInfo, CoreError, DeleteReport, HistoryPage, HistoryQuery, QuarantineEntry, QuarantineReport,
    ScanProgress, ScanRequest, ScanResult, Stats,
};
use tauri::{AppHandle, Emitter, State};

use crate::state::{AppState, ScanActivity};

const SCAN_PROGRESS_EVENT: &str = "scan-progress";

fn describe(action: &str, error: CoreError) -> String {
    format!("{action}: {error}")
}

fn to_paths(paths: Vec<String>) -> Vec<PathBuf> {
    paths.into_iter().map(PathBuf::from).collect()
}

#[tauri::command]
pub fn app_info(state: State<'_, AppState>) -> Result<AppInfo, String> {
    state
        .core
        .app_info()
        .map_err(|error| describe("No se pudo leer la información de la aplicación", error))
}

#[tauri::command]
pub fn set_signatures_db(state: State<'_, AppState>, path: String) -> Result<AppInfo, String> {
    state
        .core
        .set_signatures_db(PathBuf::from(&path))
        .map_err(|error| describe("No se pudo usar la base de datos de firmas", error))
}

#[tauri::command]
pub async fn start_scan(
    app: AppHandle,
    state: State<'_, AppState>,
    request: ScanRequest,
) -> Result<ScanResult, String> {
    let core = state.core.clone();
    let cancel = Arc::clone(&state.cancel);
    let _activity = ScanActivity::begin(&cancel, &state.running);

    let progress_app = app.clone();
    let emit_progress = move |progress: ScanProgress| {
        if let Err(error) = progress_app.emit(SCAN_PROGRESS_EVENT, progress) {
            eprintln!("failed to emit scan-progress event: {error}");
        }
    };

    let scan = tauri::async_runtime::spawn_blocking(move || {
        core.scan(
            request,
            cancel.as_ref(),
            &emit_progress as &(dyn Fn(ScanProgress) + Send + Sync),
        )
    });

    match scan.await {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(error)) => Err(describe("El escaneo falló", error)),
        Err(error) => Err(format!(
            "El escaneo se interrumpió de forma inesperada: {error}"
        )),
    }
}

#[tauri::command]
pub fn cancel_scan(scan_id: String, state: State<'_, AppState>) -> Result<bool, String> {
    if scan_id.trim().is_empty() {
        return Err("El identificador del escaneo no puede estar vacío".to_string());
    }
    Ok(state.request_cancel())
}

#[tauri::command]
pub fn get_history(state: State<'_, AppState>, query: HistoryQuery) -> Result<HistoryPage, String> {
    state
        .core
        .history(query)
        .map_err(|error| describe("No se pudo cargar el historial", error))
}

#[tauri::command]
pub fn get_stats(state: State<'_, AppState>) -> Result<Stats, String> {
    state
        .core
        .stats()
        .map_err(|error| describe("No se pudieron calcular las estadísticas", error))
}

#[tauri::command]
pub fn clear_history(state: State<'_, AppState>) -> Result<u64, String> {
    state
        .core
        .clear_history()
        .map_err(|error| describe("No se pudo borrar el historial", error))
}

#[tauri::command]
pub fn quarantine_files(
    state: State<'_, AppState>,
    paths: Vec<String>,
) -> Result<QuarantineReport, String> {
    state
        .core
        .quarantine_files(&to_paths(paths))
        .map_err(|error| describe("No se pudo mover los archivos a la cuarentena", error))
}

#[tauri::command]
pub fn delete_files(
    state: State<'_, AppState>,
    paths: Vec<String>,
) -> Result<DeleteReport, String> {
    state
        .core
        .delete_files(&to_paths(paths))
        .map_err(|error| describe("No se pudieron eliminar los archivos", error))
}

#[tauri::command]
pub fn list_quarantine(state: State<'_, AppState>) -> Result<Vec<QuarantineEntry>, String> {
    state
        .core
        .list_quarantine()
        .map_err(|error| describe("No se pudo listar la cuarentena", error))
}

#[tauri::command]
pub fn restore_quarantined(state: State<'_, AppState>, id: i64) -> Result<QuarantineEntry, String> {
    state
        .core
        .restore_quarantined(id)
        .map_err(|error| describe("No se pudo restaurar el archivo en cuarentena", error))
}

#[tauri::command]
pub fn export_csv(state: State<'_, AppState>, path: String) -> Result<String, String> {
    state
        .core
        .export_csv(&PathBuf::from(&path))
        .map_err(|error| describe("No se pudo exportar el reporte CSV", error))?;
    Ok(path)
}

#[tauri::command]
pub fn export_pdf(state: State<'_, AppState>, path: String) -> Result<String, String> {
    state
        .core
        .export_pdf(&PathBuf::from(&path))
        .map_err(|error| describe("No se pudo exportar el reporte PDF", error))?;
    Ok(path)
}
