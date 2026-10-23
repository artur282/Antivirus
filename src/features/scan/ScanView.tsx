import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import {
  AlertTriangle,
  Archive,
  Check,
  CheckCircle2,
  Clock3,
  Database,
  Eraser,
  FileSearch,
  FolderSearch,
  HardDrive,
  ListChecks,
  MapPin,
  Play,
  ShieldAlert,
  ShieldCheck,
  Square,
  Trash2,
  Zap,
} from "lucide-react";
import {
  cancelScan,
  deleteFiles,
  onScanProgress,
  pickDirectory,
  pickFiles,
  quarantineFiles,
  startScan,
} from "../../api";
import type {
  AppInfo,
  FailedItem,
  ScanKind,
  ScanProgress,
  ScanRequest,
  ScanResult,
  Threat,
} from "../../types";
import { errorMessage } from "../../lib/errors";
import {
  basename,
  formatBytes,
  formatDuration,
  formatNumber,
  shortPath,
} from "../../lib/format";
import { Button } from "../../ui/Button";
import { Card, PageHeader } from "../../ui/Card";
import { ConfirmDialog } from "../../ui/ConfirmDialog";
import { EmptyState } from "../../ui/EmptyState";
import { Modal } from "../../ui/Modal";
import { ProgressBar } from "../../ui/ProgressBar";
import { StatusChip } from "../../ui/StatusChip";
import { useToast } from "../../ui/Toast";

interface ScanViewProps {
  appInfo: AppInfo;
  onDataChanged: () => void;
  onSetupDatabase: () => void;
}

type ToastTone = "info" | "success" | "warning" | "error";
type ChipTone = "infected" | "safe" | "warning" | "neutral" | "info" | "danger";
type TargetKind = Extract<ScanKind, "file" | "directory">;

type HeroState =
  | "idle"
  | "preparing"
  | "collecting"
  | "scanning"
  | "threats"
  | "cancelled"
  | "no-signatures";

interface CleanupFeedback {
  action: "quarantine" | "delete";
  succeeded: number;
  failed: FailedItem[];
}

interface ControlProgressView {
  phaseLabel: string;
  phaseTone: ChipTone;
  scanned: number | null;
  total: number | null;
  infected: number | null;
  percent: number;
  indeterminate: boolean;
  currentPath: string;
  barTone: "primary" | "success" | "danger" | "warning";
  active: boolean;
}

const PHASE_LABELS: Record<ScanProgress["phase"], string> = {
  preparing: "Preparando",
  collecting: "Recopilando archivos",
  scanning: "Escaneando",
  finished: "Escaneo completado",
  cancelled: "Escaneo cancelado",
  error: "Error",
};

const KIND_LABELS: Record<ScanKind, string> = {
  file: "Archivo",
  directory: "Carpeta",
  quick: "Escaneo rápido",
  full: "Escaneo completo",
};

export function ScanView({ appInfo, onDataChanged, onSetupDatabase }: ScanViewProps) {
  const toast = useToast();
  const [activeKind, setActiveKind] = useState<ScanKind>("quick");
  const [filePaths, setFilePaths] = useState<string[]>([]);
  const [directoryPath, setDirectoryPath] = useState<string | null>(null);
  const [picking, setPicking] = useState<"file" | "directory" | null>(null);
  const [running, setRunning] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const [progress, setProgress] = useState<ScanProgress | null>(null);
  const [scanId, setScanId] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [runError, setRunError] = useState<string | null>(null);
  const [threatsOpen, setThreatsOpen] = useState(false);
  const [deleteConfirm, setDeleteConfirm] = useState(false);
  const [quarantineBusy, setQuarantineBusy] = useState(false);
  const [deleteBusy, setDeleteBusy] = useState(false);
  const [feedback, setFeedback] = useState<CleanupFeedback | null>(null);
  const [handledPaths, setHandledPaths] = useState<string[]>([]);
  const runActiveRef = useRef(false);

  const selectedPaths = useMemo(() => {
    if (activeKind === "file") return filePaths;
    if (activeKind === "directory") return directoryPath ? [directoryPath] : [];
    return [];
  }, [activeKind, directoryPath, filePaths]);

  const remainingThreats = useMemo(() => {
    if (!result) return [];
    return result.threats.filter((threat) => !handledPaths.includes(threat.path));
  }, [handledPaths, result]);

  const blocked = !appInfo.signaturesReady;
  const tilesDisabled = blocked || running || picking !== null;
  const canStart = !blocked && !running && picking === null;
  const canCancel = running && !cancelling;

  const handleProgress = useCallback((next: ScanProgress) => {
    if (!runActiveRef.current) return;
    setProgress(next);
    setScanId(next.scanId);
  }, []);

  useEffect(() => {
    let disposed = false;
    let unlisten: (() => void) | null = null;

    void onScanProgress(handleProgress)
      .then((stop) => {
        if (disposed) stop();
        else unlisten = stop;
      })
      .catch(() => {
        if (!disposed) {
          toast.push("No se pudo suscribir al progreso del escaneo", "warning");
        }
      });

    return () => {
      disposed = true;
      if (unlisten) unlisten();
    };
  }, [handleProgress, toast]);

  const controlProgress = useMemo<ControlProgressView>(() => {
    if (running) {
      const infected = progress?.infected ?? 0;
      const total = progress?.total ?? 0;
      const scanned = progress?.scanned ?? 0;
      const phaseError = progress?.phase === "error";

      return {
        phaseLabel: progress ? PHASE_LABELS[progress.phase] : "Preparando",
        phaseTone: phaseError ? "danger" : infected > 0 ? "warning" : "info",
        scanned,
        total: total > 0 ? total : null,
        infected,
        percent: total > 0 ? (scanned / total) * 100 : 0,
        indeterminate:
          !progress ||
          progress.phase === "preparing" ||
          progress.phase === "collecting" ||
          total === 0,
        currentPath: progress?.currentPath ?? "",
        barTone: phaseError || infected > 0 ? "danger" : "primary",
        active: true,
      };
    }

    if (result) {
      const total = result.totalFiles;
      const scanned = result.scannedFiles;
      const hasInfections = result.threats.length > 0 || result.infectedFiles > 0;
      const phaseLabel = result.cancelled
        ? "Escaneo cancelado"
        : hasInfections
          ? "Escaneo completado con amenazas"
          : "Escaneo completado";

      return {
        phaseLabel,
        phaseTone: result.cancelled
          ? "warning"
          : hasInfections
            ? "danger"
            : "safe",
        scanned,
        total,
        infected: result.infectedFiles,
        percent: total > 0 ? Math.min(100, (scanned / total) * 100) : 100,
        indeterminate: false,
        currentPath: "",
        barTone: result.cancelled
          ? "warning"
          : hasInfections
            ? "danger"
            : "success",
        active: false,
      };
    }

    return {
      phaseLabel: "Sin escaneo en curso",
      phaseTone: "neutral",
      scanned: null,
      total: null,
      infected: null,
      percent: 0,
      indeterminate: false,
      currentPath: "",
      barTone: "primary",
      active: false,
    };
  }, [progress, result, running]);

  const startHint = useMemo(() => {
    if (blocked) {
      return "Conecta la base de datos de firmas para habilitar los escaneos.";
    }
    if (running) {
      return "Puedes detener el escaneo en cualquier momento; los resultados parciales se guardarán.";
    }
    if (picking) {
      return "Espera a que termine la selección de archivos.";
    }
    if (activeKind === "file" && filePaths.length === 0) {
      return "Selecciona al menos un archivo para iniciar el escaneo.";
    }
    if (activeKind === "directory" && !directoryPath) {
      return "Selecciona una carpeta para iniciar el escaneo.";
    }
    if (activeKind === "file") {
      return `Se analizarán ${formatNumber(filePaths.length)} ${
        filePaths.length === 1 ? "archivo" : "archivos"
      }.`;
    }
    if (activeKind === "directory") {
      return "Se analizará la carpeta seleccionada y todo su contenido.";
    }
    if (activeKind === "quick") {
      return "Se analizarán las zonas críticas del sistema.";
    }
    return "Se analizarán todas las raíces del sistema. Puede tardar varios minutos.";
  }, [activeKind, blocked, directoryPath, filePaths, picking, running]);

  async function handlePickFiles() {
    if (running || picking !== null || blocked) return;
    setPicking("file");
    try {
      const paths = await pickFiles();
      if (paths.length === 0) return;
      setFilePaths(paths);
      setActiveKind("file");
    } catch (error) {
      toast.push(`No se pudieron seleccionar los archivos: ${errorMessage(error)}`, "error");
    } finally {
      setPicking(null);
    }
  }

  async function handlePickDirectory() {
    if (running || picking !== null || blocked) return;
    setPicking("directory");
    try {
      const selected = await pickDirectory();
      if (!selected) return;
      setDirectoryPath(selected);
      setActiveKind("directory");
    } catch (error) {
      toast.push(`No se pudo seleccionar la carpeta: ${errorMessage(error)}`, "error");
    } finally {
      setPicking(null);
    }
  }

  function handleClearTargets() {
    if (running) return;
    if (activeKind === "file") setFilePaths([]);
    else if (activeKind === "directory") setDirectoryPath(null);
    toast.push("Selección de objetivos borrada", "info");
  }

  async function handleStart() {
    if (running) return;
    if (blocked) {
      toast.push("Conecta la base de datos de firmas para habilitar los escaneos", "warning");
      return;
    }
    if (activeKind === "file" && filePaths.length === 0) {
      toast.push("Selecciona al menos un archivo para escanear", "warning");
      return;
    }
    if (activeKind === "directory" && !directoryPath) {
      toast.push("Selecciona una carpeta para escanear", "warning");
      return;
    }

    const request: ScanRequest = { kind: activeKind, paths: selectedPaths };
    setRunning(true);
    runActiveRef.current = true;
    setProgress(null);
    setScanId(null);
    setResult(null);
    setRunError(null);
    setThreatsOpen(false);
    setDeleteConfirm(false);
    setFeedback(null);
    setHandledPaths([]);
    setCancelling(false);

    try {
      const scanResult = await startScan(request);
      setResult(scanResult);

      if (scanResult.cancelled) {
        toast.push(
          `Escaneo cancelado tras ${formatNumber(scanResult.scannedFiles)} archivos`,
          "warning",
        );
      } else if (scanResult.threats.length > 0) {
        setThreatsOpen(true);
        toast.push(
          `Se detectaron ${formatNumber(scanResult.threats.length)} amenazas`,
          "warning",
        );
      } else {
        toast.push(
          `Escaneo completado: ${formatNumber(scanResult.scannedFiles)} archivos sin amenazas`,
          "success",
        );
      }

      onDataChanged();
    } catch (error) {
      const message = errorMessage(error);
      setRunError(message);
      toast.push(`No se pudo completar el escaneo: ${message}`, "error");
    } finally {
      runActiveRef.current = false;
      setRunning(false);
      setCancelling(false);
      setScanId(null);
    }
  }

  async function handleCancel() {
    if (!running || cancelling) return;
    if (!scanId) {
      toast.push("El escaneo todavía se está preparando; espera un momento para detenerlo", "info");
      return;
    }

    setCancelling(true);
    try {
      const stopped = await cancelScan(scanId);
      if (stopped) {
        toast.push("Solicitud de cancelación enviada", "info");
      } else {
        toast.push("No se pudo detener el escaneo", "warning");
      }
    } catch (error) {
      toast.push(`No se pudo detener el escaneo: ${errorMessage(error)}`, "error");
    } finally {
      setCancelling(false);
    }
  }

  async function handleQuarantine() {
    if (remainingThreats.length === 0 || quarantineBusy || deleteBusy) return;
    const paths = remainingThreats.map((threat) => threat.path);

    setQuarantineBusy(true);
    try {
      const report = await quarantineFiles(paths);
      const movedPaths = report.moved.map((entry) => entry.originalPath);
      setHandledPaths((current) => [...new Set([...current, ...movedPaths])]);
      setFeedback({
        action: "quarantine",
        succeeded: report.moved.length,
        failed: report.failed,
      });
      setThreatsOpen(false);
      toast.push(
        quarantineMessage(report.moved.length, report.failed.length),
        cleanupTone(report.moved.length, report.failed.length),
      );
    } catch (error) {
      toast.push(`No se pudo mover a cuarentena: ${errorMessage(error)}`, "error");
    } finally {
      setQuarantineBusy(false);
      onDataChanged();
    }
  }

  function handleRequestDelete() {
    if (remainingThreats.length === 0 || quarantineBusy || deleteBusy) return;
    setThreatsOpen(false);
    setDeleteConfirm(true);
  }

  function closeDeleteConfirm() {
    if (deleteBusy) return;
    setDeleteConfirm(false);
    if (remainingThreats.length > 0) setThreatsOpen(true);
  }

  async function handleDelete() {
    if (remainingThreats.length === 0 || deleteBusy) return;
    const paths = remainingThreats.map((threat) => threat.path);

    setDeleteBusy(true);
    try {
      const report = await deleteFiles(paths);
      setHandledPaths((current) => [...new Set([...current, ...report.deleted])]);
      setFeedback({
        action: "delete",
        succeeded: report.deleted.length,
        failed: report.failed,
      });
      setDeleteConfirm(false);
      setThreatsOpen(false);
      toast.push(
        deleteMessage(report.deleted.length, report.failed.length),
        cleanupTone(report.deleted.length, report.failed.length),
      );
    } catch (error) {
      toast.push(
        `No se pudieron eliminar los archivos: ${errorMessage(error)}`,
        "error",
      );
    } finally {
      setDeleteBusy(false);
      onDataChanged();
    }
  }

  function closeThreats() {
    if (quarantineBusy || deleteBusy) return;
    setThreatsOpen(false);
  }

  return (
    <div className="page scan-page">
      <PageHeader
        title="Centro de escaneo"
        subtitle="Comprueba archivos y carpetas comparando sus hashes MD5, SHA1 y SHA256 con tu base de firmas local."
      />

      <ScanHero
        appInfo={appInfo}
        scanning={running}
        progress={progress}
        result={result}
        onSetupDatabase={onSetupDatabase}
        canStart={canStart}
        canCancel={canCancel}
        cancelling={cancelling}
        onStart={() => void handleStart()}
        onCancel={() => void handleCancel()}
        onReviewThreats={() => setThreatsOpen(true)}
        hasPendingThreats={remainingThreats.length > 0}
      />

      <section className="scan-actions-panel" aria-label="Objetivos de escaneo">
        <ScanActionRow
          icon={<FileSearch size={17} />}
          title="Escanear archivo"
          description="Analiza uno o varios archivos concretos."
          detail={
            picking === "file"
              ? "Abriendo selector…"
              : activeKind === "file" && filePaths.length > 0
                ? `${formatNumber(filePaths.length)} ${
                    filePaths.length === 1 ? "archivo" : "archivos"
                  }`
                : "Elegir archivos"
          }
          selected={activeKind === "file"}
          disabled={tilesDisabled}
          onClick={() => void handlePickFiles()}
        />
        <ScanActionRow
          icon={<FolderSearch size={17} />}
          title="Escanear carpeta"
          description="Analiza todos los archivos dentro de una carpeta."
          detail={
            picking === "directory"
              ? "Abriendo selector…"
              : activeKind === "directory" && directoryPath
                ? basename(directoryPath)
                : "Elegir carpeta"
          }
          selected={activeKind === "directory"}
          disabled={tilesDisabled}
          onClick={() => void handlePickDirectory()}
        />
        <ScanActionRow
          icon={<Zap size={17} />}
          title="Escanear rápido"
          description="Revisa las zonas críticas del sistema."
          detail={activeKind === "quick" ? "Zonas críticas" : "Seleccionar"}
          selected={activeKind === "quick"}
          disabled={tilesDisabled}
          onClick={() => setActiveKind("quick")}
        />
        <ScanActionRow
          icon={<HardDrive size={17} />}
          title="Escanear completo"
          description="Recorre las raíces y unidades del equipo."
          detail={activeKind === "full" ? "Todo el sistema" : "Seleccionar"}
          selected={activeKind === "full"}
          disabled={tilesDisabled}
          onClick={() => setActiveKind("full")}
        />
      </section>

      {blocked ? (
        <div className="scan-blocked" role="note">
          <span className="scan-blocked-icon">
            <ShieldAlert size={18} aria-hidden="true" />
          </span>
          <div className="scan-blocked-body">
            <strong>Escaneos deshabilitados</strong>
            <p>
              Conecta la base de datos de firmas para habilitar los escaneos. Sin firmas no
              es posible detectar amenazas.
            </p>
          </div>
          <Button
            variant="primary"
            size="sm"
            icon={<Database size={15} />}
            onClick={onSetupDatabase}
          >
            Conectar base de datos
          </Button>
        </div>
      ) : null}

      {activeKind === "file" || activeKind === "directory" ? (
        <TargetsPanel
          kind={activeKind}
          paths={selectedPaths}
          disabled={running}
          onClear={handleClearTargets}
        />
      ) : (
        <ScopePanel kind={activeKind} />
      )}

      <ControlCard view={controlProgress} hint={startHint} error={runError} />

      {result ? <ResultsPanel result={result} feedback={feedback} /> : null}

      {threatsOpen && remainingThreats.length > 0 ? (
        <ThreatsModal
          threats={remainingThreats}
          quarantineBusy={quarantineBusy}
          deleteBusy={deleteBusy}
          onQuarantine={() => void handleQuarantine()}
          onRequestDelete={handleRequestDelete}
          onClose={closeThreats}
        />
      ) : null}

      {deleteConfirm && remainingThreats.length > 0 ? (
        <ConfirmDialog
          title="Eliminar amenazas permanentemente"
          message={
            <div className="scan-confirm">
              <p>
                Se eliminarán permanentemente{" "}
                <strong>{formatNumber(remainingThreats.length)}</strong>{" "}
                {remainingThreats.length === 1 ? "archivo infectado" : "archivos infectados"}.
              </p>
              <p className="scan-confirm-warning">
                Esta acción es irreversible y no se puede deshacer. Los archivos no se
                moverán a la cuarentena.
              </p>
            </div>
          }
          confirmLabel="Eliminar permanentemente"
          cancelLabel="Cancelar"
          tone="danger"
          loading={deleteBusy}
          onConfirm={() => void handleDelete()}
          onCancel={closeDeleteConfirm}
        />
      ) : null}
    </div>
  );
}

interface ScanHeroProps {
  appInfo: AppInfo;
  scanning: boolean;
  progress: ScanProgress | null;
  result: ScanResult | null;
  onSetupDatabase: () => void;
  canStart: boolean;
  canCancel: boolean;
  cancelling: boolean;
  onStart: () => void;
  onCancel: () => void;
  onReviewThreats: () => void;
  hasPendingThreats: boolean;
}

function ScanHero({
  appInfo,
  scanning,
  progress,
  result,
  onSetupDatabase,
  canStart,
  canCancel,
  cancelling,
  onStart,
  onCancel,
  onReviewThreats,
  hasPendingThreats,
}: ScanHeroProps) {
  const state = resolveHeroState(appInfo, scanning, progress, result);
  const view = heroView(state, result);
  const counts = appInfo.signatureCounts;
  const lastFinding = result
    ? `${formatNumber(result.scannedFiles)} archivos analizados · ${formatNumber(
        result.infectedFiles,
      )} ${result.infectedFiles === 1 ? "amenaza" : "amenazas"}`
    : null;

  return (
    <Card className={`scan-status scan-status-${state}`}>
      <div className="scan-status-main">
        <div className="scan-status-copy">
          <div className="scan-status-line">
            <span className={`db-dot ${appInfo.signaturesReady ? "ok" : ""}`} />
            <span>{view.label}</span>
          </div>
          <h2 className="scan-status-title">{view.title}</h2>
          <p className="scan-status-text">{view.description}</p>
          {lastFinding ? <p className="scan-status-meta">{lastFinding}</p> : null}
        </div>
        <div className="scan-status-actions">
          {!appInfo.signaturesReady ? (
            <Button
              variant="primary"
              icon={<Database size={15} />}
              onClick={onSetupDatabase}
            >
              Conectar base de datos
            </Button>
          ) : (
            <>
              <Button
                variant="primary"
                icon={<Play size={15} />}
                onClick={onStart}
                disabled={!canStart}
              >
                Iniciar escaneo
              </Button>
              {scanning ? (
                <Button
                  variant="secondary"
                  icon={<Square size={13} />}
                  onClick={onCancel}
                  disabled={!canCancel}
                  loading={cancelling}
                >
                  Detener
                </Button>
              ) : null}
              {hasPendingThreats && !scanning ? (
                <Button
                  variant="secondary"
                  icon={<ShieldAlert size={15} />}
                  onClick={onReviewThreats}
                >
                  Revisar amenazas
                </Button>
              ) : null}
            </>
          )}
        </div>
      </div>

      <div className="scan-signature-lanes">
        <div className="scan-signature-lane">
          <span>MD5</span>
          <strong>{counts ? formatNumber(counts.md5) : "—"}</strong>
          <small>firmas</small>
        </div>
        <div className="scan-signature-lane">
          <span>SHA1</span>
          <strong>{counts ? formatNumber(counts.sha1) : "—"}</strong>
          <small>firmas</small>
        </div>
        <div className="scan-signature-lane">
          <span>SHA256</span>
          <strong>{counts ? formatNumber(counts.sha256) : "—"}</strong>
          <small>firmas</small>
        </div>
        <div
          className="scan-signature-lane scan-signature-path"
          title={appInfo.signaturesDbPath ?? undefined}
        >
          <span>Base de firmas</span>
          <strong className="mono">
            {appInfo.signaturesDbPath
              ? basename(appInfo.signaturesDbPath)
              : "Sin configurar"}
          </strong>
        </div>
      </div>
    </Card>
  );
}

interface ScanActionRowProps {
  icon: ReactNode;
  title: string;
  description: string;
  detail: string;
  selected: boolean;
  disabled: boolean;
  onClick: () => void;
}

function ScanActionRow({
  icon,
  title,
  description,
  detail,
  selected,
  disabled,
  onClick,
}: ScanActionRowProps) {
  return (
    <button
      type="button"
      className={`scan-action-row ${selected ? "scan-action-row-active" : ""}`}
      aria-pressed={selected}
      disabled={disabled}
      onClick={onClick}
    >
      <span className="scan-action-icon">{icon}</span>
      <span className="scan-action-copy">
        <strong>{title}</strong>
        <span>{description}</span>
      </span>
      <span className="scan-action-detail">
        {selected ? <Check size={14} aria-hidden="true" /> : null}
        {detail}
      </span>
    </button>
  );
}

interface TargetsPanelProps {
  kind: TargetKind;
  paths: string[];
  disabled: boolean;
  onClear: () => void;
}

function TargetsPanel({ kind, paths, disabled, onClear }: TargetsPanelProps) {
  const count = paths.length;
  const countLabel = `${formatNumber(count)} ${count === 1 ? "objetivo" : "objetivos"}`;

  return (
    <Card className="scan-targets">
      <div className="scan-targets-head">
        <div>
          <div className="scan-targets-heading">
            <ListChecks size={16} aria-hidden="true" />
            <strong>Objetivos seleccionados</strong>
            <StatusChip tone="neutral">{countLabel}</StatusChip>
          </div>
          <p className="scan-targets-hint">
            {kind === "file"
              ? "Se analizarán los archivos seleccionados."
              : "Se analizará la carpeta seleccionada y todo su contenido."}
          </p>
        </div>
        <Button
          variant="ghost"
          size="sm"
          icon={<Eraser size={14} />}
          onClick={onClear}
          disabled={disabled || count === 0}
        >
          Limpiar
        </Button>
      </div>

      {count > 0 ? (
        <ul className="scan-target-list" aria-label="Rutas seleccionadas">
          {paths.slice(0, 6).map((path, index) => (
            <li key={`${path}-${index}`} className="scan-target-item" title={path}>
              <span className="scan-target-name">{basename(path)}</span>
              <span className="scan-target-path mono">{shortPath(path, 56)}</span>
            </li>
          ))}
          {count > 6 ? (
            <li className="scan-target-more">+{formatNumber(count - 6)} más</li>
          ) : null}
        </ul>
      ) : (
        <p className="scan-targets-empty">
          Todavía no hay rutas seleccionadas. Usa una tarjeta de acción para elegir
          archivos o una carpeta.
        </p>
      )}
    </Card>
  );
}

function ScopePanel({ kind }: { kind: "quick" | "full" }) {
  return (
    <Card className="scan-scope">
      <span className="scan-scope-icon">
        <MapPin size={20} aria-hidden="true" />
      </span>
      <div className="scan-scope-copy">
        <div className="scan-scope-title">
          <strong>
            {kind === "quick" ? "Alcance del escaneo rápido" : "Alcance del escaneo completo"}
          </strong>
          <span
            className={`scan-scope-note ${
              kind === "full" ? "scan-scope-note-warning" : ""
            }`}
          >
            {kind === "quick" ? "Zonas críticas" : "Puede tardar"}
          </span>
        </div>
        <p>{describeScope(kind)}</p>
        {kind === "full" ? (
          <p className="scan-scope-warning">
            <Clock3 size={14} aria-hidden="true" />
            Un escaneo completo puede tardar varios minutos y consumir recursos del
            equipo.
          </p>
        ) : null}
      </div>
    </Card>
  );
}

interface ControlCardProps {
  view: ControlProgressView;
  hint: string;
  error: string | null;
}

function ControlCard({ view, hint, error }: ControlCardProps) {
  const scannedText = view.scanned === null ? "—" : formatNumber(view.scanned);
  const totalText = view.total === null ? "—" : formatNumber(view.total);
  const remaining =
    view.scanned !== null && view.total !== null
      ? Math.max(view.total - view.scanned, 0)
      : null;

  return (
    <Card className={`scan-control ${view.active ? "scan-control-active" : ""}`}>
      <div className="scan-control-head">
        <div>
          <h2 className="card-title">Progreso del escaneo</h2>
          <p className="card-subtitle">
            {view.active
              ? "El progreso se actualiza en tiempo real."
              : "El resultado de cada archivo queda en el historial."}
          </p>
        </div>
        <div className="scan-phase" role="status">
          <span
            className={`scan-phase-dot ${
              view.active ? "scan-phase-dot-live" : ""
            }`}
            aria-hidden="true"
          />
          {view.phaseLabel}
        </div>
      </div>

      <div className="scan-progress">
        <ProgressBar
          value={view.percent}
          label="Progreso"
          indeterminate={view.indeterminate}
          tone={view.barTone}
        />
        <div className="scan-current">
          <span className="scan-current-label">Archivo actual</span>
          <span
            className={`scan-current-path mono ${
              view.currentPath ? "" : "scan-current-empty"
            }`}
            title={view.currentPath || undefined}
            aria-label={view.currentPath || "Sin archivo actual"}
          >
            {view.currentPath ? shortPath(view.currentPath, 96) : "—"}
          </span>
        </div>
        <div className="scan-counters">
          <div className="scan-counter">
            <span className="scan-counter-label">Analizados</span>
            <strong className="scan-counter-value">
              {scannedText} / {totalText}
            </strong>
          </div>
          <div className="scan-counter">
            <span className="scan-counter-label">Infecciones</span>
            <strong
              className={`scan-counter-value ${
                view.infected !== null && view.infected > 0
                  ? "scan-counter-danger"
                  : ""
              }`}
            >
              {view.infected === null ? "—" : formatNumber(view.infected)}
            </strong>
          </div>
          <div className="scan-counter">
            <span className="scan-counter-label">Restantes</span>
            <strong className="scan-counter-value">
              {remaining === null ? "—" : formatNumber(remaining)}
            </strong>
          </div>
        </div>
      </div>

      <p className="scan-control-hint">{hint}</p>

      {error ? (
        <div className="scan-notice scan-notice-danger" role="alert">
          <AlertTriangle size={18} aria-hidden="true" />
          <div>
            <strong>No se pudo completar el escaneo</strong>
            <p>{error}</p>
          </div>
        </div>
      ) : null}
    </Card>
  );
}

interface ResultsPanelProps {
  result: ScanResult;
  feedback: CleanupFeedback | null;
}

function ResultsPanel({ result, feedback }: ResultsPanelProps) {
  const hasThreats = result.threats.length > 0;
  const hasInfections = hasThreats || result.infectedFiles > 0;
  const clean =
    !result.cancelled && !hasThreats && result.infectedFiles === 0;

  return (
    <section className="scan-results" aria-label="Resultado del escaneo">
      <div className="scan-results-head">
        <div>
          <h2 className="scan-results-title">Resultado del escaneo</h2>
          <div className="scan-results-meta">
            <span>{KIND_LABELS[result.kind]}</span>
            <span aria-hidden="true">·</span>
            <span className={`scan-results-status ${hasInfections ? "negative" : "positive"}`}>
              {result.cancelled
                ? "Cancelado"
                : hasInfections
                  ? "Con amenazas"
                  : "Sin amenazas"}
            </span>
          </div>
        </div>
      </div>

      <div className="kpi-strip scan-summary">
        <div className="kpi-cell">
          <span className="kpi-label">Total analizados</span>
          <strong className="kpi-value">{formatNumber(result.totalFiles)}</strong>
          <span className="kpi-hint">Archivos encontrados</span>
        </div>
        <div className="kpi-cell">
          <span className="kpi-label">Archivos seguros</span>
          <strong className="kpi-value positive">{formatNumber(result.safeFiles)}</strong>
          <span className="kpi-hint">Sin coincidencias</span>
        </div>
        <div className="kpi-cell">
          <span className="kpi-label">Amenazas</span>
          <strong className={`kpi-value ${hasInfections ? "negative" : ""}`.trim()}>
            {formatNumber(result.infectedFiles)}
          </strong>
          <span className="kpi-hint">Requieren revisión</span>
        </div>
        <div className="kpi-cell">
          <span className="kpi-label">Duración</span>
          <strong className="kpi-value">{formatDuration(result.durationMs)}</strong>
          <span className="kpi-hint">Tiempo total</span>
        </div>
      </div>

      {feedback ? <FeedbackBanner feedback={feedback} /> : null}

      {result.cancelled ? (
        <div className="scan-notice scan-notice-warning" role="status">
          <AlertTriangle size={18} aria-hidden="true" />
          <div>
            <strong>Escaneo cancelado</strong>
            <p>
              Se analizaron {formatNumber(result.scannedFiles)} de{" "}
              {formatNumber(result.totalFiles)} archivos. Los resultados parciales se
              guardaron en el historial.
            </p>
          </div>
        </div>
      ) : null}

      {hasThreats ? (
        <section className="scan-result-section" aria-labelledby="scan-threats-title">
          <div className="scan-result-section-head">
            <h3 id="scan-threats-title">Amenazas detectadas</h3>
            <StatusChip tone="infected">
              {formatNumber(result.threats.length)}
            </StatusChip>
          </div>
          <div className="table-wrap scan-table-wrap">
            <table className="table scan-table">
              <thead>
                <tr>
                  <th scope="col">Archivo</th>
                  <th scope="col">Estado</th>
                  <th scope="col">Hashes coincidentes</th>
                  <th scope="col">Tamaño</th>
                </tr>
              </thead>
              <tbody>
                {result.threats.map((threat, index) => (
                  <tr key={`${threat.path}-${index}`}>
                    <td className="path-cell">
                      <span className="path" title={threat.path} aria-label={threat.path}>
                        {shortPath(threat.path, 80)}
                      </span>
                    </td>
                    <td>
                      <StatusChip tone="infected">Infección</StatusChip>
                    </td>
                    <td>
                      <HashBadgeList threat={threat} />
                    </td>
                    <td>{formatBytes(threat.size)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      ) : null}

      {clean ? (
        <Card padded={false} className="scan-safe">
          <EmptyState
            icon={<ShieldCheck size={26} />}
            title="Sin amenazas detectadas"
            description={`Se analizaron ${formatNumber(
              result.scannedFiles,
            )} archivos y ninguno coincide con las firmas conocidas.`}
          />
        </Card>
      ) : null}

      {!hasThreats && result.infectedFiles > 0 ? (
        <div className="scan-notice scan-notice-danger" role="status">
          <ShieldAlert size={18} aria-hidden="true" />
          <div>
            <strong>Infecciones sin detalle</strong>
            <p>
              El escaneo reportó {formatNumber(result.infectedFiles)} infecciones, pero no
              devolvió la lista de archivos. Revisa el historial para más información.
            </p>
          </div>
        </div>
      ) : null}

      {result.errors.length > 0 ? (
        <section className="scan-result-section" aria-labelledby="scan-errors-title">
          <div className="scan-result-section-head">
            <h3 id="scan-errors-title">Errores del escaneo</h3>
            <StatusChip tone="danger">{formatNumber(result.errors.length)}</StatusChip>
          </div>
          <div className="table-wrap scan-table-wrap">
            <table className="table scan-table">
              <thead>
                <tr>
                  <th scope="col">Archivo</th>
                  <th scope="col">Estado</th>
                  <th scope="col">Detalle</th>
                </tr>
              </thead>
              <tbody>
                {result.errors.map((failure, index) => (
                  <tr key={`${failure.path}-${index}`}>
                    <td className="path-cell">
                      <span className="path" title={failure.path} aria-label={failure.path}>
                        {shortPath(failure.path, 80)}
                      </span>
                    </td>
                    <td>
                      <StatusChip tone="danger">Error</StatusChip>
                    </td>
                    <td>{failure.message}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      ) : null}
    </section>
  );
}

function HashBadgeList({ threat }: { threat: Threat }) {
  const badges = hashBadges(threat);
  if (badges.length === 0) {
    return <span className="scan-hash-empty">—</span>;
  }

  return (
    <span className="scan-hash-list">
      {badges.map((hash, index) => (
        <span
          key={`${hash.label}-${index}`}
          className="badge scan-hash-badge"
          title={hash.value || undefined}
        >
          {hash.label}
        </span>
      ))}
    </span>
  );
}

function FeedbackBanner({ feedback }: { feedback: CleanupFeedback }) {
  const hasFailures = feedback.failed.length > 0;

  return (
    <div
      className={`scan-feedback ${
        hasFailures ? "scan-feedback-warning" : "scan-feedback-success"
      }`}
      role="status"
    >
      {hasFailures ? (
        <AlertTriangle size={18} aria-hidden="true" />
      ) : (
        <CheckCircle2 size={18} aria-hidden="true" />
      )}
      <div className="scan-feedback-body">
        <strong>{feedbackTitle(feedback)}</strong>
        {hasFailures ? (
          <ul className="scan-feedback-list">
            {feedback.failed.map((item, index) => (
              <li key={`${item.path}-${index}`}>
                <span className="mono">{shortPath(item.path, 64)}</span> — {item.message}
              </li>
            ))}
          </ul>
        ) : null}
      </div>
    </div>
  );
}

interface ThreatsModalProps {
  threats: Threat[];
  quarantineBusy: boolean;
  deleteBusy: boolean;
  onQuarantine: () => void;
  onRequestDelete: () => void;
  onClose: () => void;
}

function ThreatsModal({
  threats,
  quarantineBusy,
  deleteBusy,
  onQuarantine,
  onRequestDelete,
  onClose,
}: ThreatsModalProps) {
  return (
    <Modal
      title="Amenazas detectadas"
      subtitle={`${formatNumber(threats.length)} ${
        threats.length === 1 ? "archivo requiere" : "archivos requieren"
      } atención antes de continuar.`}
      size="lg"
      onClose={onClose}
      footer={
        <div className="scan-modal-actions">
          <Button
            variant="ghost"
            onClick={onClose}
            disabled={quarantineBusy || deleteBusy}
          >
            Cerrar
          </Button>
          <Button
            variant="warning"
            icon={<Archive size={16} />}
            onClick={onQuarantine}
            loading={quarantineBusy}
            disabled={deleteBusy}
          >
            Mover a cuarentena
          </Button>
          <Button
            variant="danger"
            icon={<Trash2 size={16} />}
            onClick={onRequestDelete}
            disabled={quarantineBusy || deleteBusy}
          >
            Eliminar permanentemente
          </Button>
        </div>
      }
    >
      <p className="scan-modal-intro">
        Estos archivos coinciden con hashes de la base de firmas. Elige una acción;
        eliminar es irreversible.
      </p>
      <ul className="scan-threat-list">
        {threats.map((threat, index) => (
          <li key={`${threat.path}-${index}`} className="scan-threat-item">
            <span className="scan-threat-icon">
              <ShieldAlert size={18} aria-hidden="true" />
            </span>
            <div className="scan-threat-main">
              <span className="scan-threat-path mono" title={threat.path} aria-label={threat.path}>
                {shortPath(threat.path, 86)}
              </span>
              <div className="scan-threat-meta">
                <StatusChip tone="infected">Infección</StatusChip>
                <HashBadgeList threat={threat} />
                <span className="scan-threat-size">{formatBytes(threat.size)}</span>
              </div>
            </div>
          </li>
        ))}
      </ul>
    </Modal>
  );
}

function resolveHeroState(
  appInfo: AppInfo,
  scanning: boolean,
  progress: ScanProgress | null,
  result: ScanResult | null,
): HeroState {
  if (!appInfo.signaturesReady) return "no-signatures";
  if (scanning) {
    if (progress?.phase === "cancelled") return "cancelled";
    if (progress?.phase === "collecting") return "collecting";
    if (progress?.phase === "scanning" || progress?.phase === "finished") {
      return "scanning";
    }
    return "preparing";
  }
  if (result?.cancelled) return "cancelled";
  if (result && (result.threats.length > 0 || result.infectedFiles > 0)) {
    return "threats";
  }
  return "idle";
}

function heroView(
  state: HeroState,
  result: ScanResult | null,
): { label: string; title: string; description: string; tone: ChipTone } {
  const threatCount = result
    ? Math.max(result.threats.length, result.infectedFiles)
    : 0;

  switch (state) {
    case "preparing":
      return {
        label: "Preparando",
        title: "Preparando el motor de escaneo",
        description:
          "Validando firmas y preparando el análisis. Esto solo toma un momento.",
        tone: "info",
      };
    case "collecting":
      return {
        label: "Recopilando archivos",
        title: "Recopilando la lista de archivos",
        description:
          "Recorriendo el objetivo para saber cuántos archivos se van a analizar.",
        tone: "info",
      };
    case "scanning":
      return {
        label: "Escaneando",
        title: "Analizando archivos",
        description:
          "Calculando hashes y comparándolos con la base de firmas en tiempo real.",
        tone: "info",
      };
    case "threats":
      return {
        label: "Amenazas detectadas",
        title: `${formatNumber(threatCount)} ${
          threatCount === 1 ? "amenaza detectada" : "amenazas detectadas"
        }`,
        description:
          "Revisa los archivos infectados antes de moverlos a cuarentena o eliminarlos.",
        tone: "infected",
      };
    case "cancelled":
      return {
        label: "Escaneo cancelado",
        title: "Análisis interrumpido",
        description:
          "Los archivos procesados hasta ese momento quedaron registrados en el historial.",
        tone: "warning",
      };
    case "no-signatures":
      return {
        label: "Sin base de firmas",
        title: "Conecta la base de datos de firmas",
        description:
          "Los escaneos están deshabilitados hasta que conectes virus_data.db.",
        tone: "warning",
      };
    case "idle":
    default:
      return {
        label: "Sin análisis reciente",
        title: "Aún no hay un análisis en esta sesión",
        description:
          "Elige un archivo, una carpeta o un análisis del sistema. La detección compara MD5, SHA1 y SHA256.",
        tone: "safe",
      };
  }
}

function describeScope(kind: "quick" | "full"): string {
  const userAgent =
    typeof navigator !== "undefined" ? navigator.userAgent : "";
  const isWindows = /Windows/i.test(userAgent);
  const isMac = /Macintosh|Mac OS X/i.test(userAgent);

  if (kind === "quick") {
    if (isWindows) {
      return "Analiza carpetas críticas de Windows como System32, Program Files y tu perfil de usuario.";
    }
    if (isMac) {
      return "Analiza carpetas críticas de macOS como /System, /Applications, /usr y tu carpeta de usuario.";
    }
    return "Analiza carpetas críticas del sistema como /bin, /usr, /etc y tu carpeta personal.";
  }

  if (isWindows) {
    return "Recorre las unidades del equipo y las carpetas del sistema, incluidas Windows, Program Files y tus datos.";
  }
  if (isMac) {
    return "Recorre la raíz del sistema y carpetas principales como /, /System, /Applications y /Users.";
  }
  return "Recorre la raíz del sistema y carpetas principales como /, /home, /usr y /etc.";
}

function hashBadges(threat: Threat): Array<{ label: string; value: string }> {
  return threat.matched.map((name) => {
    const normalized = name.toLowerCase();
    const value =
      normalized === "md5"
        ? threat.md5
        : normalized === "sha1"
          ? threat.sha1
          : normalized === "sha256"
            ? threat.sha256
            : "";
    return { label: normalized.toUpperCase(), value };
  });
}

function cleanupTone(succeeded: number, failed: number): ToastTone {
  if (succeeded > 0 && failed === 0) return "success";
  if (succeeded === 0) return "error";
  return "warning";
}

function quarantineMessage(succeeded: number, failed: number): string {
  const moved = `${formatNumber(succeeded)} ${
    succeeded === 1 ? "archivo movido" : "archivos movidos"
  } a cuarentena`;
  if (failed === 0) return moved;
  return `${moved}; ${formatNumber(failed)} ${failed === 1 ? "falló" : "fallaron"}`;
}

function deleteMessage(succeeded: number, failed: number): string {
  const deleted = `${formatNumber(succeeded)} ${
    succeeded === 1 ? "archivo eliminado" : "archivos eliminados"
  } permanentemente`;
  if (failed === 0) return deleted;
  return `${deleted}; ${formatNumber(failed)} ${failed === 1 ? "falló" : "fallaron"}`;
}

function feedbackTitle(feedback: CleanupFeedback): string {
  const noun = feedback.succeeded === 1 ? "archivo" : "archivos";

  if (feedback.action === "quarantine") {
    return `${formatNumber(feedback.succeeded)} ${noun} ${
      feedback.succeeded === 1 ? "movido" : "movidos"
    } a cuarentena${
      feedback.failed.length > 0
        ? ` · ${formatNumber(feedback.failed.length)} con error`
        : ""
    }`;
  }

  return `${formatNumber(feedback.succeeded)} ${noun} ${
    feedback.succeeded === 1 ? "eliminado" : "eliminados"
  } permanentemente${
    feedback.failed.length > 0
      ? ` · ${formatNumber(feedback.failed.length)} con error`
      : ""
  }`;
}
