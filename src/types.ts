export type ScanKind = "file" | "directory" | "quick" | "full";

export type ScanPhase =
  | "preparing"
  | "collecting"
  | "scanning"
  | "finished"
  | "cancelled"
  | "error";

export type HistoryFilter = "all" | "infected" | "safe";

export interface SignatureCounts {
  md5: number;
  sha1: number;
  sha256: number;
}

export interface AppInfo {
  version: string;
  signaturesDbPath: string | null;
  signaturesReady: boolean;
  signatureCounts: SignatureCounts | null;
  historyCount: number;
  appDataDir: string;
}

export interface ScanRequest {
  kind: ScanKind;
  paths: string[];
}

export interface ScanProgress {
  scanId: string;
  phase: ScanPhase;
  scanned: number;
  total: number;
  infected: number;
  currentPath: string;
  message: string | null;
}

export interface Threat {
  path: string;
  md5: string;
  sha1: string;
  sha256: string;
  size: number;
  matched: string[];
}

export interface ScanFailure {
  path: string;
  message: string;
}

export interface ScanResult {
  scanId: string;
  kind: ScanKind;
  totalFiles: number;
  scannedFiles: number;
  infectedFiles: number;
  safeFiles: number;
  cancelled: boolean;
  durationMs: number;
  threats: Threat[];
  errors: ScanFailure[];
}

export interface HistoryEntry {
  id: number;
  scanId: string | null;
  filePath: string;
  isInfected: boolean;
  scanDate: string;
}

export interface HistoryQuery {
  limit: number;
  offset: number;
  filter: HistoryFilter;
}

export interface HistoryPage {
  total: number;
  entries: HistoryEntry[];
}

export interface DailyStat {
  date: string;
  total: number;
  infected: number;
}

export interface Stats {
  totalScanned: number;
  totalInfected: number;
  totalSafe: number;
  infectionRate: number;
  lastScanAt: string | null;
  daily: DailyStat[];
}

export interface QuarantineEntry {
  id: number;
  originalPath: string;
  storedPath: string;
  sha256: string;
  createdAt: string;
  restoredAt: string | null;
}

export interface FailedItem {
  path: string;
  message: string;
}

export interface QuarantineReport {
  moved: QuarantineEntry[];
  failed: FailedItem[];
}

export interface DeleteReport {
  deleted: string[];
  failed: FailedItem[];
}
