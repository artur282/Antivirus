# Integration contracts (frozen)

All UI types live in `src/types.ts`; all frontend calls live in `src/api.ts`. Do not change either file unless the parent asks. The Rust core public API is frozen in `crates/antivirus-core/src/lib.rs`.

## Tauri commands

| Command | Argument | Return |
| --- | --- | --- |
| `app_info` | — | `AppInfo` |
| `set_signatures_db` | `path: String` | `AppInfo` |
| `start_scan` | `request: ScanRequest` | `ScanResult` |
| `cancel_scan` | `scanId: String` | `bool` |
| `get_history` | `query: HistoryQuery` | `HistoryPage` |
| `get_stats` | — | `Stats` |
| `clear_history` | — | `u64` |
| `quarantine_files` | `paths: Vec<String>` | `QuarantineReport` |
| `delete_files` | `paths: Vec<String>` | `DeleteReport` |
| `list_quarantine` | — | `Vec<QuarantineEntry>` |
| `restore_quarantined` | `id: i64` | `QuarantineEntry` |
| `export_csv` | `path: String` | `String` (saved path) |
| `export_pdf` | `path: String` | `String` (saved path) |

Event name: `scan-progress`. Payload: `ScanProgress` (serialized camelCase by the core types).

## Core crate

`Core::new(app_data_dir, signature_candidates)` creates the app data directory and the app database; it never fails because signatures are missing. `Core::app_info`, `set_signatures_db`, `scan`, `history`, `stats`, `clear_history`, `quarantine_files`, `list_quarantine`, `restore_quarantined`, `delete_files`, `export_csv`, `export_pdf`, `log_activity` follow `lib.rs` exactly. `Core` is `Clone + Send + Sync`. The scanner must be cancellable through `&AtomicBool` and must call the progress callback from worker threads.

## Signatures database

`virus_data.db` contains `virus_md5(md5_hash)`, `virus_sha1(sha1_hash)`, `virus_sha256(sha256_hash)` and a legacy `scan_history` table that the new app does not use. The core creates indexes once (writable DB) and must not delete or rewrite signature rows. The app database lives at `<app_data_dir>/antivirus.db`.

## File ownership

- Parent: `odd/`, `package.json`, `tsconfig.json`, `vite.config.ts`, `index.html`, `.gitignore`, `Cargo.toml`, `src/main.tsx`, `src/App.tsx`, `src/types.ts`, `src/api.ts`, `src/lib/**`, `src/ui/**`, `src/styles/base.css`, `src/styles/app.css`, `src-tauri/tauri.conf.json`, `src-tauri/capabilities/**`, `src-tauri/Cargo.toml`, `src-tauri/icons/**`, `README.md`.
- Core worker: `crates/antivirus-core/**`.
- Tauri shell worker: `src-tauri/src/**`, `src-tauri/build.rs`. Cargo.toml may be edited only to add a dependency already required by the design.
- Scan UI worker: `src/features/scan/**`, `src/styles/scan.css`.
- Data views worker: `src/features/history/**`, `src/features/dashboard/**`, `src/features/reports/**`, `src/styles/views.css`.

No worker runs `git commit`, `git push`, `git checkout`, or modifies files outside its surface.
