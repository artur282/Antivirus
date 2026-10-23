import { useEffect, useState } from "react";
import {
  AlertTriangle,
  ArchiveRestore,
  Database,
  FileSpreadsheet,
  FileText,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Trash2,
} from "lucide-react";
import {
  clearHistory,
  exportCsv,
  exportPdf,
  getStats,
  listQuarantine,
  pickSavePath,
  restoreQuarantined,
} from "../../api";
import type { AppInfo, QuarantineEntry, Stats } from "../../types";
import { Button } from "../../ui/Button";
import { Card, PageHeader } from "../../ui/Card";
import { ConfirmDialog } from "../../ui/ConfirmDialog";
import { EmptyState } from "../../ui/EmptyState";
import { Spinner } from "../../ui/Spinner";
import { StatusChip } from "../../ui/StatusChip";
import { useToast } from "../../ui/Toast";
import { errorMessage } from "../../lib/errors";
import {
  formatDate,
  formatNumber,
  formatPercent,
  shortPath,
} from "../../lib/format";

interface ReportsViewProps {
  appInfo: AppInfo;
  onDataChanged: () => void;
  onSetupDatabase: () => void;
}

function todayStamp(): string {
  const now = new Date();
  const month = String(now.getMonth() + 1).padStart(2, "0");
  const day = String(now.getDate()).padStart(2, "0");
  return `${now.getFullYear()}-${month}-${day}`;
}

function SummaryItem({ label, value }: { label: string; value: string }) {
  return (
    <div className="reports-summary-item">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

export function ReportsView({ appInfo, onDataChanged, onSetupDatabase }: ReportsViewProps) {
  const toast = useToast();
  const [stats, setStats] = useState<Stats | null>(null);
  const [statsLoading, setStatsLoading] = useState(true);
  const [statsError, setStatsError] = useState<string | null>(null);
  const [statsToken, setStatsToken] = useState(0);

  const [quarantine, setQuarantine] = useState<QuarantineEntry[] | null>(null);
  const [quarantineLoading, setQuarantineLoading] = useState(true);
  const [quarantineError, setQuarantineError] = useState<string | null>(null);
  const [quarantineToken, setQuarantineToken] = useState(0);

  const [exporting, setExporting] = useState<"csv" | "pdf" | null>(null);
  const [restoreTarget, setRestoreTarget] = useState<QuarantineEntry | null>(null);
  const [restoring, setRestoring] = useState(false);
  const [confirmClear, setConfirmClear] = useState(false);
  const [clearing, setClearing] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setStatsLoading(true);
    setStatsError(null);

    getStats()
      .then((result) => {
        if (!cancelled) setStats(result);
      })
      .catch((cause: unknown) => {
        if (!cancelled) setStatsError(errorMessage(cause));
      })
      .finally(() => {
        if (!cancelled) setStatsLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [statsToken]);

  useEffect(() => {
    let cancelled = false;
    setQuarantineLoading(true);
    setQuarantineError(null);

    listQuarantine()
      .then((result) => {
        if (!cancelled) setQuarantine(result);
      })
      .catch((cause: unknown) => {
        if (!cancelled) setQuarantineError(errorMessage(cause));
      })
      .finally(() => {
        if (!cancelled) setQuarantineLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [quarantineToken]);

  const activeQuarantine = (quarantine ?? []).filter((entry) => entry.restoredAt === null);
  const restoredCount = (quarantine ?? []).filter((entry) => entry.restoredAt !== null).length;

  const handleRefresh = () => {
    setStatsToken((current) => current + 1);
    setQuarantineToken((current) => current + 1);
  };

  const handleExport = async (format: "csv" | "pdf") => {
    const defaultName = `reporte-antivirus-${todayStamp()}.${format}`;
    setExporting(format);
    try {
      const path = await pickSavePath(defaultName, format);
      if (!path) return;
      const saved = format === "csv" ? await exportCsv(path) : await exportPdf(path);
      toast.push(`Reporte ${format.toUpperCase()} guardado en ${saved}`, "success");
    } catch (cause) {
      toast.push(errorMessage(cause), "error");
    } finally {
      setExporting(null);
    }
  };

  const handleRestore = async () => {
    if (!restoreTarget) return;
    setRestoring(true);
    try {
      await restoreQuarantined(restoreTarget.id);
      toast.push(`Archivo restaurado en ${restoreTarget.originalPath}`, "success");
      setRestoreTarget(null);
      setQuarantineToken((current) => current + 1);
    } catch (cause) {
      toast.push(errorMessage(cause), "error");
    } finally {
      setRestoring(false);
    }
  };

  const handleClearHistory = async () => {
    setClearing(true);
    try {
      const removed = await clearHistory();
      toast.push(`Historial eliminado (${formatNumber(removed)} registros)`, "success");
      setConfirmClear(false);
      setStatsToken((current) => current + 1);
      onDataChanged();
    } catch (cause) {
      toast.push(errorMessage(cause), "error");
    } finally {
      setClearing(false);
    }
  };

  const signatureCounts = appInfo.signatureCounts;

  return (
    <div className="page">
      <PageHeader
        title="Reportes y cuarentena"
        subtitle="Exporta el estado del análisis, administra las amenazas en cuarentena y depura el historial."
        actions={
          <Button
            variant="secondary"
            icon={<RefreshCw size={15} />}
            onClick={handleRefresh}
            disabled={statsLoading || quarantineLoading}
          >
            Actualizar
          </Button>
        }
      />

      <div className="reports-grid">
        <Card>
          <div className="card-header">
            <div>
              <h2 className="card-title">Base de datos de firmas</h2>
              <p className="card-subtitle">Origen de los hashes de detección</p>
            </div>
            <StatusChip tone={appInfo.signaturesReady ? "safe" : "warning"}>
              {appInfo.signaturesReady ? "Conectada" : "Sin conectar"}
            </StatusChip>
          </div>

          <dl className="reports-facts">
            <div className="reports-fact">
              <dt>Ruta de firmas</dt>
              <dd className="mono">{appInfo.signaturesDbPath ?? "Sin configurar"}</dd>
            </div>
            <div className="reports-fact">
              <dt>Datos de la aplicación</dt>
              <dd className="mono">{appInfo.appDataDir}</dd>
            </div>
            <div className="reports-fact">
              <dt>Versión</dt>
              <dd>v{appInfo.version}</dd>
            </div>
          </dl>

          {signatureCounts ? (
            <div className="reports-counts">
              <div className="reports-count">
                <strong>{formatNumber(signatureCounts.md5)}</strong>
                <span>hashes MD5</span>
              </div>
              <div className="reports-count">
                <strong>{formatNumber(signatureCounts.sha1)}</strong>
                <span>hashes SHA1</span>
              </div>
              <div className="reports-count">
                <strong>{formatNumber(signatureCounts.sha256)}</strong>
                <span>hashes SHA256</span>
              </div>
            </div>
          ) : null}

          {!appInfo.signaturesReady ? (
            <>
              <div className="reports-warning">
                <AlertTriangle size={16} aria-hidden="true" />
                <div>
                  <strong>Firmas no conectadas</strong>
                  <span>
                    El escaneo necesita virus_data.db. Historia, dashboard y reportes siguen
                    disponibles.
                  </span>
                </div>
              </div>
              <div className="reports-db-action">
                <Button variant="primary" icon={<Database size={15} />} onClick={onSetupDatabase}>
                  Conectar base de datos
                </Button>
              </div>
            </>
          ) : null}
        </Card>

        <Card>
          <div className="card-header">
            <div>
              <h2 className="card-title">Resumen de actividad</h2>
              <p className="card-subtitle">Totales acumulados del historial</p>
            </div>
            <StatusChip tone="info">
              {stats ? formatNumber(stats.totalScanned) : "—"} archivos
            </StatusChip>
          </div>

          {statsError ? (
            <div className="reports-inline-error" role="alert">
              <span>
                <ShieldAlert size={15} aria-hidden="true" /> {statsError}
              </span>
              <Button variant="secondary" size="sm" onClick={handleRefresh}>
                Reintentar
              </Button>
            </div>
          ) : statsLoading && !stats ? (
            <div className="reports-loading">
              <Spinner label="Cargando resumen" />
            </div>
          ) : stats ? (
            <div className="reports-summary-values">
              <SummaryItem label="Total escaneado" value={formatNumber(stats.totalScanned)} />
              <SummaryItem label="Seguros" value={formatNumber(stats.totalSafe)} />
              <SummaryItem label="Infectados" value={formatNumber(stats.totalInfected)} />
              <SummaryItem label="Tasa de infección" value={formatPercent(stats.infectionRate)} />
            </div>
          ) : null}

          <div className="reports-actions">
            <Button
              variant="primary"
              icon={<FileSpreadsheet size={15} />}
              onClick={() => void handleExport("csv")}
              loading={exporting === "csv"}
              disabled={exporting !== null}
            >
              Exportar CSV
            </Button>
            <Button
              variant="secondary"
              icon={<FileText size={15} />}
              onClick={() => void handleExport("pdf")}
              loading={exporting === "pdf"}
              disabled={exporting !== null}
            >
              Exportar PDF
            </Button>
          </div>
        </Card>
      </div>

      <Card className="quarantine-card">
        <div className="quarantine-head">
          <div>
            <h2 className="card-title">Cuarentena</h2>
            <p className="card-subtitle">
              Archivos movidos a un lugar seguro. Restaurarlos los devuelve a su ruta original.
            </p>
          </div>
          <div className="quarantine-meta">
            <StatusChip tone={activeQuarantine.length > 0 ? "warning" : "neutral"}>
              {formatNumber(activeQuarantine.length)} en cuarentena
            </StatusChip>
            {restoredCount > 0 ? (
              <StatusChip tone="neutral">
                {formatNumber(restoredCount)} restaurados
              </StatusChip>
            ) : null}
          </div>
        </div>

        {quarantineError ? (
          <EmptyState
            icon={<ShieldAlert size={26} />}
            title="No se pudo cargar la cuarentena"
            description={quarantineError}
            action={
              <Button
                variant="secondary"
                icon={<RefreshCw size={15} />}
                onClick={() => setQuarantineToken((current) => current + 1)}
              >
                Reintentar
              </Button>
            }
          />
        ) : quarantine === null && quarantineLoading ? (
          <div className="quarantine-loading">
            <Spinner label="Cargando cuarentena" />
          </div>
        ) : activeQuarantine.length === 0 ? (
          <EmptyState
            icon={<ShieldCheck size={26} />}
            title="No hay archivos en cuarentena"
            description="Cuando muevas una amenaza a cuarentena desde un escaneo aparecerá aquí."
          />
        ) : (
          <div className="table-wrap" aria-busy={quarantineLoading}>
            <table className="table quarantine-table">
              <thead>
                <tr>
                  <th scope="col">Archivo original</th>
                  <th scope="col">Ruta almacenada</th>
                  <th scope="col">Fecha</th>
                  <th scope="col">Estado</th>
                  <th scope="col">Acción</th>
                </tr>
              </thead>
              <tbody>
                {activeQuarantine.map((entry) => (
                  <tr key={entry.id}>
                    <td className="path-cell">
                      <span className="path" title={entry.originalPath}>
                        {shortPath(entry.originalPath, 56)}
                      </span>
                      <span className="sub mono">SHA256 {entry.sha256.slice(0, 16)}…</span>
                    </td>
                    <td className="path-cell">
                      <span className="path" title={entry.storedPath}>
                        {shortPath(entry.storedPath, 56)}
                      </span>
                    </td>
                    <td>{formatDate(entry.createdAt)}</td>
                    <td>
                      <StatusChip tone="warning">En cuarentena</StatusChip>
                    </td>
                    <td>
                      <Button
                        variant="secondary"
                        size="sm"
                        icon={<ArchiveRestore size={14} />}
                        onClick={() => setRestoreTarget(entry)}
                      >
                        Restaurar
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <Card>
        <div className="reports-maintenance">
          <div>
            <h2 className="card-title">Historial de escaneos</h2>
            <p className="card-subtitle">
              Elimina todos los registros de archivos analizados. Los reportes ya exportados no se
              modifican.
            </p>
          </div>
          <Button
            variant="danger"
            icon={<Trash2 size={15} />}
            onClick={() => setConfirmClear(true)}
            disabled={stats !== null && stats.totalScanned === 0}
          >
            Limpiar historial
          </Button>
        </div>
      </Card>

      {restoreTarget ? (
        <ConfirmDialog
          title="Restaurar archivo"
          message={
            <>
              El archivo volverá a su ruta original:{" "}
              <strong className="mono">{restoreTarget.originalPath}</strong>. Asegúrate de que no
              quieras mantenerlo aislado.
            </>
          }
          confirmLabel="Restaurar"
          tone="primary"
          loading={restoring}
          onConfirm={() => void handleRestore()}
          onCancel={() => setRestoreTarget(null)}
        />
      ) : null}

      {confirmClear ? (
        <ConfirmDialog
          title="Limpiar historial"
          message="¿Eliminar todo el historial? Esta acción no se puede deshacer."
          confirmLabel="Eliminar historial"
          tone="danger"
          loading={clearing}
          onConfirm={() => void handleClearHistory()}
          onCancel={() => setConfirmClear(false)}
        />
      ) : null}
    </div>
  );
}
