import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { open, save } from "@tauri-apps/plugin-dialog";
import type {
  AppInfo,
  DeleteReport,
  HistoryPage,
  HistoryQuery,
  QuarantineEntry,
  QuarantineReport,
  ScanProgress,
  ScanRequest,
  ScanResult,
  Stats,
} from "./types";

const SCAN_PROGRESS_EVENT = "scan-progress";

export function isTauriRuntime(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

export async function getAppInfo(): Promise<AppInfo> {
  if (!isTauriRuntime()) return mockInfo();
  return invoke<AppInfo>("app_info");
}

export async function setSignaturesDb(path: string): Promise<AppInfo> {
  if (!isTauriRuntime()) {
    mockState.signaturesDbPath = path;
    return mockInfo();
  }
  return invoke<AppInfo>("set_signatures_db", { path });
}

export async function startScan(request: ScanRequest): Promise<ScanResult> {
  if (!isTauriRuntime()) return mockScan(request);
  return invoke<ScanResult>("start_scan", { request });
}

export async function cancelScan(scanId: string): Promise<boolean> {
  if (!isTauriRuntime()) {
    mockState.cancelled = true;
    return true;
  }
  return invoke<boolean>("cancel_scan", { scanId });
}

export async function getHistory(query: HistoryQuery): Promise<HistoryPage> {
  if (!isTauriRuntime()) return mockHistoryPage(query);
  return invoke<HistoryPage>("get_history", { query });
}

export async function getStats(): Promise<Stats> {
  if (!isTauriRuntime()) return mockStats();
  return invoke<Stats>("get_stats");
}

export async function clearHistory(): Promise<number> {
  if (!isTauriRuntime()) {
    const removed = mockState.history.length;
    mockState.history = [];
    return removed;
  }
  return invoke<number>("clear_history");
}

export async function quarantineFiles(paths: string[]): Promise<QuarantineReport> {
  if (!isTauriRuntime()) return mockQuarantine(paths);
  return invoke<QuarantineReport>("quarantine_files", { paths });
}

export async function deleteFiles(paths: string[]): Promise<DeleteReport> {
  if (!isTauriRuntime()) return { deleted: paths, failed: [] };
  return invoke<DeleteReport>("delete_files", { paths });
}

export async function listQuarantine(): Promise<QuarantineEntry[]> {
  if (!isTauriRuntime()) return mockState.quarantine;
  return invoke<QuarantineEntry[]>("list_quarantine");
}

export async function restoreQuarantined(id: number): Promise<QuarantineEntry> {
  if (!isTauriRuntime()) {
    const entry = mockState.quarantine.find((item) => item.id === id);
    if (!entry) throw new Error("Entrada de cuarentena no encontrada");
    entry.restoredAt = new Date().toISOString();
    return entry;
  }
  return invoke<QuarantineEntry>("restore_quarantined", { id });
}

export async function exportCsv(path: string): Promise<string> {
  if (!isTauriRuntime()) return path;
  return invoke<string>("export_csv", { path });
}

export async function exportPdf(path: string): Promise<string> {
  if (!isTauriRuntime()) return path;
  return invoke<string>("export_pdf", { path });
}

export async function onScanProgress(
  callback: (progress: ScanProgress) => void,
): Promise<UnlistenFn> {
  if (!isTauriRuntime()) {
    mockState.listeners.add(callback);
    return () => {
      mockState.listeners.delete(callback);
    };
  }
  return listen<ScanProgress>(SCAN_PROGRESS_EVENT, (event) => callback(event.payload));
}

export async function pickFiles(): Promise<string[]> {
  if (!isTauriRuntime()) return [];
  const selected = await open({
    title: "Seleccionar archivos para escanear",
    multiple: true,
    directory: false,
  });
  if (!selected) return [];
  return Array.isArray(selected) ? selected : [selected];
}

export async function pickDirectory(): Promise<string | null> {
  if (!isTauriRuntime()) return null;
  const selected = await open({
    title: "Seleccionar carpeta para escanear",
    multiple: false,
    directory: true,
  });
  return typeof selected === "string" ? selected : null;
}

export async function pickSignaturesDb(): Promise<string | null> {
  if (!isTauriRuntime()) return null;
  const selected = await open({
    title: "Seleccionar virus_data.db",
    multiple: false,
    directory: false,
    filters: [{ name: "Base de datos SQLite", extensions: ["db", "sqlite", "sqlite3"] }],
  });
  return typeof selected === "string" ? selected : null;
}

export async function pickSavePath(
  defaultName: string,
  extension: "pdf" | "csv",
): Promise<string | null> {
  if (!isTauriRuntime()) return null;
  const selected = await save({
    title: extension === "pdf" ? "Guardar reporte PDF" : "Guardar reporte CSV",
    defaultPath: defaultName,
    filters: [
      {
        name: extension === "pdf" ? "Documento PDF" : "Archivo CSV",
        extensions: [extension],
      },
    ],
  });
  return selected ?? null;
}

/* ------------------------------------------------------------------ */
/* Browser demo backend: lets the UI be previewed without Tauri.        */
/* ------------------------------------------------------------------ */

interface MockState {
  cancelled: boolean;
  signaturesDbPath: string;
  history: HistoryPage["entries"];
  quarantine: QuarantineEntry[];
  listeners: Set<(progress: ScanProgress) => void>;
}

const now = Date.now();
const DAY = 86_400_000;

function isoDaysAgo(days: number, hour = 10): string {
  return new Date(now - days * DAY + hour * 3_600_000).toISOString();
}

function buildMockHistory(): HistoryPage["entries"] {
  const samples = [
    ["/home/analista/Descargas/factura.pdf", false],
    ["/home/analista/Descargas/eicar_com.zip", true],
    ["/home/analista/Documentos/notas.txt", false],
    ["/home/analista/Proyectos/app/main.rs", false],
    ["/home/analista/Descargas/instalador.exe", true],
    ["/home/analista/Imagenes/logo.png", false],
    ["/home/analista/Proyectos/app/package.json", false],
    ["/home/analista/Musica/tema.mp3", false],
    ["/home/analista/Descargas/script.sh", false],
    ["/home/analista/Documentos/presupuesto.xlsx", false],
  ] as const;

  return Array.from({ length: 48 }, (_, index) => {
    const [path, infected] = samples[index % samples.length];
    const day = Math.floor(index / 4);
    return {
      id: 1000 + index,
      scanId: "demo-scan",
      filePath: path,
      isInfected: infected,
      scanDate: isoDaysAgo(day, 9 + (index % 8)),
    };
  });
}

const mockState: MockState = {
  cancelled: false,
  signaturesDbPath: "/home/analista/Antivirus/virus_data.db",
  history: buildMockHistory(),
  quarantine: [],
  listeners: new Set(),
};

function mockInfo(): AppInfo {
  return {
    version: "0.1.0-demo",
    signaturesDbPath: mockState.signaturesDbPath,
    signaturesReady: true,
    signatureCounts: { md5: 897_084, sha1: 897_084, sha256: 897_075 },
    historyCount: mockState.history.length,
    appDataDir: "/home/analista/.local/share/antivirus",
  };
}

function emitMock(progress: ScanProgress): void {
  for (const listener of mockState.listeners) listener(progress);
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}

async function mockScan(request: ScanRequest): Promise<ScanResult> {
  if ((request.kind === "file" || request.kind === "directory") && request.paths.length === 0) {
    throw new Error("Selecciona al menos un archivo o carpeta");
  }

  const scanId = crypto.randomUUID();
  const total = request.kind === "file" ? Math.max(request.paths.length, 1) : request.kind === "directory" ? 24 : 120;
  const infected = request.kind === "quick" || request.kind === "full" ? 2 : 0;
  const threatPath =
    request.kind === "file" ? request.paths[0] : "/home/analista/Descargas/eicar_com.zip";

  mockState.cancelled = false;
  emitMock({
    scanId,
    phase: "preparing",
    scanned: 0,
    total: 0,
    infected: 0,
    currentPath: "",
    message: "Preparando firmas y conexiones",
  });
  await delay(250);
  emitMock({
    scanId,
    phase: "collecting",
    scanned: 0,
    total,
    infected: 0,
    currentPath: request.kind === "quick" ? "/usr/bin" : "/home/analista",
    message: "Recopilando archivos",
  });

  for (let step = 1; step <= 20; step += 1) {
    if (mockState.cancelled) {
      return {
        scanId,
        kind: request.kind,
        totalFiles: total,
        scannedFiles: Math.round((total * step) / 20),
        infectedFiles: 0,
        safeFiles: Math.round((total * step) / 20),
        cancelled: true,
        durationMs: step * 90,
        threats: [],
        errors: [],
      };
    }
    const scanned = Math.round((total * step) / 20);
    emitMock({
      scanId,
      phase: "scanning",
      scanned,
      total,
      infected: scanned === total ? infected : 0,
      currentPath: threatPath,
      message: null,
    });
    await delay(90);
  }

  const threats =
    infected > 0
      ? [
          {
            path: threatPath,
            md5: "44d88612fea8a8f36de82e1278abb02f",
            sha1: "3395856ce81f2b7382dee72602f798b642f14140",
            sha256: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            size: 68,
            matched: ["md5", "sha1", "sha256"],
          },
        ]
      : [];

  const entries = Array.from({ length: Math.min(total, 30) }, (_, index) => ({
    id: Date.now() + index,
    scanId,
    filePath: index === 0 && threats.length > 0 ? threatPath : `/home/analista/archivo_${index + 1}.bin`,
    isInfected: index === 0 && threats.length > 0,
    scanDate: new Date().toISOString(),
  }));
  mockState.history = [...entries, ...mockState.history];

  const result: ScanResult = {
    scanId,
    kind: request.kind,
    totalFiles: total,
    scannedFiles: total,
    infectedFiles: threats.length,
    safeFiles: total - threats.length,
    cancelled: false,
    durationMs: 1800,
    threats,
    errors: [],
  };
  emitMock({
    scanId,
    phase: "finished",
    scanned: total,
    total,
    infected: threats.length,
    currentPath: "",
    message: null,
  });
  return result;
}

function mockHistoryPage(query: HistoryQuery): HistoryPage {
  const filtered = mockState.history.filter((entry) => {
    if (query.filter === "infected") return entry.isInfected;
    if (query.filter === "safe") return !entry.isInfected;
    return true;
  });
  return {
    total: filtered.length,
    entries: filtered.slice(query.offset, query.offset + query.limit),
  };
}

function mockStats(): Stats {
  const totalScanned = mockState.history.length;
  const totalInfected = mockState.history.filter((entry) => entry.isInfected).length;
  const dailyMap = new Map<string, { total: number; infected: number }>();
  for (let day = 13; day >= 0; day -= 1) {
    dailyMap.set(new Date(now - day * DAY).toISOString().slice(0, 10), { total: 0, infected: 0 });
  }
  for (const entry of mockState.history) {
    const key = entry.scanDate.slice(0, 10);
    const bucket = dailyMap.get(key);
    if (bucket) {
      bucket.total += 1;
      if (entry.isInfected) bucket.infected += 1;
    }
  }
  return {
    totalScanned,
    totalInfected,
    totalSafe: totalScanned - totalInfected,
    infectionRate: totalScanned === 0 ? 0 : (totalInfected / totalScanned) * 100,
    lastScanAt: mockState.history[0]?.scanDate ?? null,
    daily: [...dailyMap.entries()].map(([date, value]) => ({ date, ...value })),
  };
}

function mockQuarantine(paths: string[]): QuarantineReport {
  const moved = paths.map((path, index) => {
    const entry: QuarantineEntry = {
      id: Date.now() + index,
      originalPath: path,
      storedPath: `/home/analista/.local/share/antivirus/quarantine/${Date.now()}_${index}_${path.split("/").pop() ?? "archivo"}`,
      sha256: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
      createdAt: new Date().toISOString(),
      restoredAt: null,
    };
    mockState.quarantine = [entry, ...mockState.quarantine];
    return entry;
  });
  return { moved, failed: [] };
}
