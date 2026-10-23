use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanKind {
    File,
    Directory,
    Quick,
    Full,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanRequest {
    pub kind: ScanKind,
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanPhase {
    Preparing,
    Collecting,
    Scanning,
    Finished,
    Cancelled,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanProgress {
    pub scan_id: String,
    pub phase: ScanPhase,
    pub scanned: usize,
    pub total: usize,
    pub infected: usize,
    pub current_path: String,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureCounts {
    pub md5: u64,
    pub sha1: u64,
    pub sha256: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppInfo {
    pub version: String,
    pub signatures_db_path: Option<String>,
    pub signatures_ready: bool,
    pub signature_counts: Option<SignatureCounts>,
    pub history_count: u64,
    pub app_data_dir: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Threat {
    pub path: String,
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub size: u64,
    pub matched: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanFailure {
    pub path: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanResult {
    pub scan_id: String,
    pub kind: ScanKind,
    pub total_files: usize,
    pub scanned_files: usize,
    pub infected_files: usize,
    pub safe_files: usize,
    pub cancelled: bool,
    pub duration_ms: u64,
    pub threats: Vec<Threat>,
    pub errors: Vec<ScanFailure>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryFilter {
    All,
    Infected,
    Safe,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryQuery {
    pub limit: u64,
    pub offset: u64,
    pub filter: HistoryFilter,
}

impl Default for HistoryQuery {
    fn default() -> Self {
        Self {
            limit: 100,
            offset: 0,
            filter: HistoryFilter::All,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryEntry {
    pub id: i64,
    pub scan_id: Option<String>,
    pub file_path: String,
    pub is_infected: bool,
    pub scan_date: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryPage {
    pub total: u64,
    pub entries: Vec<HistoryEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DailyStat {
    pub date: String,
    pub total: u64,
    pub infected: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Stats {
    pub total_scanned: u64,
    pub total_infected: u64,
    pub total_safe: u64,
    pub infection_rate: f64,
    pub last_scan_at: Option<String>,
    pub daily: Vec<DailyStat>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuarantineEntry {
    pub id: i64,
    pub original_path: String,
    pub stored_path: String,
    pub sha256: String,
    pub created_at: String,
    pub restored_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FailedItem {
    pub path: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuarantineReport {
    pub moved: Vec<QuarantineEntry>,
    pub failed: Vec<FailedItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteReport {
    pub deleted: Vec<String>,
    pub failed: Vec<FailedItem>,
}
