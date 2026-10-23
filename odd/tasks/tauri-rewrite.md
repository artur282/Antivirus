# Antivirus Rust + Tauri rewrite

Objective: replace the legacy Python/Tkinter antivirus with a Tauri v2 desktop app (Rust backend, React + TypeScript frontend) that preserves file/directory/quick/full scanning, hash detection, history, dashboard, reports, quarantine and themes, with a modern Spanish UI.
Branch: worktree `glowing-river` (detached HEAD). Delivery: user-owned commits only; agents must not commit, push or tag.
Checks: `cargo test -p antivirus-core`, `cargo fmt --check`, `npm run build`, `npm run tauri build` (requires webkit2gtk dev packages; unavailable in this sandbox).

## Specs

- **S1 — Stack.** The application is a Tauri v2 desktop app. The backend is Rust; the UI is React 19 + TypeScript + Vite. The legacy Python app is preserved on the `legacy-python` branch.
- **S2 — Scans.** The app supports: single file, directory, quick scan (critical system dirs) and full scan (platform system roots). File/directory scans use paths selected by the user. Quick/full choose their own paths. Scans report progress and can be cancelled.
- **S3 — Detection.** For every scanned regular file compute MD5, SHA1 and SHA256 in one read pass. A file is infected when any hash matches `virus_md5.md5_hash`, `virus_sha1.sha1_hash` or `virus_sha256.sha256_hash` in `virus_data.db`. Report which hashes matched, file size and path.
- **S4 — History.** Persist every scanned file result with path, infected flag, timestamp and scan id in the app database. The history view shows total/safe/infected counters, a filterable table, and allows clearing the history after confirmation.
- **S5 — Dashboard.** Show total scanned, safe, infected and infection rate, plus daily activity for the last 14 days. Offer three visualizations: stat cards, donut chart and 14-day heatmap. Handle the empty state.
- **S6 — Reports.** Export a CSV report with columns `Archivo,Estado,Fecha` and a PDF summary report (title, generation date, total scanned, safe, infected, infection rate) to a user-selected path.
- **S7 — Quarantine and deletion.** After a scan with threats the user can move infected files to the app quarantine (with metadata and unique stored name) or permanently delete them only after an explicit second confirmation. Quarantine entries can be listed and restored. Failures are reported per file, never silently ignored.
- **S8 — UI and theme.** Spanish UI matching the original feature set, with a modern responsive layout, logo, light/dark theme persisted locally, accessible focus states, and clear empty/loading/error states.
- **S9 — Database onboarding.** The app works without `virus_data.db` for history/dashboard, but scanning requires signatures. The UI must show a clear "signatures missing" state and let the user pick the database file. The selected path is stored in the app database. In-place indexes are created once on the signatures DB to make lookups fast; if the DB is not writable, scanning still works but reports the degraded state.
- **S10 — Verification and docs.** Core behavior is covered by Rust tests (hashing, detection, history, stats, quarantine/restore, reports, missing DB). The frontend must type-check and build. README documents setup, DB extraction, development, build and the verification limitations.

## Tasks

| ID | Specs | Route | Status |
| --- | --- | --- | --- |
| T1 | S1, S8, S9, S10 | inline (parent) — scaffold, contracts, shared UI | done |
| T2 | S2, S3, S4, S5, S6, S7, S9 | delegated — `antivirus-core` worker (test-first) | done — 33 tests |
| T3 | S1, S9 | delegated — Tauri shell worker | done — rustfmt/metadata; fake-pkg-config check/build |
| T4 | S2, S8 | delegated — scan UI worker | done — strict tsc |
| T5 | S4, S5, S6, S8 | delegated — history/dashboard/reports worker | done — strict tsc |
| T6 | all | inline (parent) — integrate, type-check, test, fix | done — `npm run build`, `cargo test` |
| T7 | S10 | inline (parent) — README and final report | done — README rewritten for Rust/Tauri |

## Log

- **L1 — user request (verbatim):**
  > este es un proyecto viejo necesito que lo actualices  rescribiendo todo el proyecto usando rust+tauri
  > despliega varios agente para hacer esto mas rapido
- **L2 — decisions:** Tauri v2 + React 19 + TypeScript + Vite; plain CSS design system (no Tailwind); core logic in a pure Rust crate `antivirus-core` so it can be unit-tested without GUI system libraries; separate app database (`antivirus.db`) from read-only signatures (`virus_data.db`); in-place signature indexes; minimal dependency-free PDF writer; the original Python app is preserved on the `legacy-python` branch; no agent commits.
- **L3 — environment:** `cargo 1.99.1`, `node v24.22.1`, `npm 11.19.1`. `webkit2gtk-4.1` runtime exists but dev headers/`pkg-config` files are absent, so the Tauri shell cannot be compiled in this sandbox. Core tests and frontend build are the executable proof here; the README records the full build requirement.
- **L4 — user correction (verbatim):**
  > usa la skill /home/arthur/Documentos/Desarrollo/personal/Antivirus/.agents/skills/design-taste-frontend para mejorar el diseño ya qeu el que esta actualmente es muy generico
- **L5 — design decision:** replaced the generic navy/gradient dashboard with the skill's `framed-sheet` app style (seed 1965551630): tinted L-frame with a white sheet inset 8px, 228px sidebar, 48px topbar, flat surfaces, IBM Plex Sans/Mono self-hosted in `public/fonts/`, 22px title, KPI strips instead of icon cards, colour reserved for data/status, and one product-specific element: the three hash-lane signature strip (MD5/SHA1/SHA256) in the scan status panel. Added a six-row recent-scans panel to the dashboard to close the empty first-screen band.
- **L6 — design verification:** tasteskill `lint.mjs --app src` → 0 FAIL; `inspect.mjs --app` at 1440/768/390 → 0 FAIL, 0 WARN on scan, dashboard, history and reports after the final type/table adjustments. `npm run build` passes (TypeScript strict + Vite). Browser demo verified scan, threat modal, results, dashboard, history navigation, reports and dark theme. Tauri shell build still requires real WebKitGTK dev headers; it was previously check/built with the sandbox fake pkg-config workaround. No agent commits.
