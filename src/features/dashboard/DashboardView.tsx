import { useEffect, useState } from "react";
import {
  ChartPie,
  Grid3x3,
  LayoutGrid,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import { getHistory, getStats } from "../../api";
import type { DailyStat, HistoryEntry, Stats } from "../../types";
import { Button } from "../../ui/Button";
import { Card, PageHeader } from "../../ui/Card";
import { EmptyState } from "../../ui/EmptyState";
import { ProgressBar } from "../../ui/ProgressBar";
import { Spinner } from "../../ui/Spinner";
import { StatusChip } from "../../ui/StatusChip";
import { errorMessage } from "../../lib/errors";
import {
  basename,
  formatDate,
  formatDay,
  formatNumber,
  formatPercent,
} from "../../lib/format";

type ChartKind = "cards" | "donut" | "heatmap";

const CHART_OPTIONS: ReadonlyArray<{ id: ChartKind; label: string }> = [
  { id: "cards", label: "Tarjetas" },
  { id: "donut", label: "Dona" },
  { id: "heatmap", label: "Mapa de calor" },
];

const CHART_ICONS = {
  cards: LayoutGrid,
  donut: ChartPie,
  heatmap: Grid3x3,
} satisfies Record<ChartKind, typeof LayoutGrid>;

function heatLevel(total: number, max: number): number {
  if (total <= 0 || max <= 0) return 0;
  const ratio = total / max;
  if (ratio <= 0.25) return 1;
  if (ratio <= 0.5) return 2;
  if (ratio <= 0.75) return 3;
  return 4;
}

function sharePercent(value: number, total: number): number {
  return total === 0 ? 0 : (value / total) * 100;
}

function DonutChart({ safe, infected, total }: { safe: number; infected: number; total: number }) {
  const radius = 62;
  const strokeWidth = 5;
  const circumference = 2 * Math.PI * radius;
  const safeLength = (sharePercent(safe, total) / 100) * circumference;
  const infectedLength = (sharePercent(infected, total) / 100) * circumference;
  const safeText = `${formatNumber(safe)} seguros`;
  const infectedText = `${formatNumber(infected)} infectados`;

  return (
    <div className="chart-donut-panel">
      <div className="chart-donut-wrap">
        <svg
          className="chart-donut"
          viewBox="0 0 160 160"
          role="img"
          aria-label={`Distribución de ${formatNumber(total)} archivos: ${safeText} y ${infectedText}.`}
        >
          <circle
            cx="80"
            cy="80"
            r={radius}
            fill="none"
            stroke="var(--border)"
            strokeWidth={strokeWidth}
          />
          {safeLength > 0 ? (
            <circle
              cx="80"
              cy="80"
              r={radius}
              fill="none"
              stroke="var(--chart-1)"
              strokeWidth={strokeWidth}
              strokeDasharray={`${safeLength} ${circumference - safeLength}`}
              transform="rotate(-90 80 80)"
            />
          ) : null}
          {infectedLength > 0 ? (
            <circle
              cx="80"
              cy="80"
              r={radius}
              fill="none"
              stroke="var(--negative)"
              strokeWidth={strokeWidth}
              strokeDasharray={`${infectedLength} ${circumference - infectedLength}`}
              strokeDashoffset={-safeLength}
              transform="rotate(-90 80 80)"
            />
          ) : null}
        </svg>
        <div className="chart-donut-center" aria-hidden="true">
          <strong>{formatNumber(total)}</strong>
          <span>archivos</span>
        </div>
      </div>
      <div className="chart-legend">
        <span className="chart-legend-item">
          <span className="chart-swatch safe" aria-hidden="true" />
          Seguros <strong>{formatNumber(safe)}</strong> · {formatPercent(sharePercent(safe, total))}
        </span>
        <span className="chart-legend-item">
          <span className="chart-swatch infected" aria-hidden="true" />
          Infectados <strong>{formatNumber(infected)}</strong> ·{" "}
          {formatPercent(sharePercent(infected, total))}
        </span>
      </div>
    </div>
  );
}

function ShareCards({ safe, infected, total }: { safe: number; infected: number; total: number }) {
  const safeShare = sharePercent(safe, total);
  const infectedShare = sharePercent(infected, total);

  return (
    <div className="chart-bars">
      <div className="chart-bar-block">
        <div className="chart-bar-top">
          <span className="chart-bar-name">
            <ShieldCheck size={15} aria-hidden="true" /> Archivos seguros
          </span>
          <strong>{formatNumber(safe)}</strong>
        </div>
        <ProgressBar value={safeShare} label="Proporción de archivos seguros" />
      </div>
      <div className="chart-bar-block">
        <div className="chart-bar-top">
          <span className="chart-bar-name">
            <ShieldAlert size={15} aria-hidden="true" /> Archivos infectados
          </span>
          <strong>{formatNumber(infected)}</strong>
        </div>
        <ProgressBar
          value={infectedShare}
          label="Proporción de archivos infectados"
          tone="danger"
        />
      </div>
    </div>
  );
}

function Heatmap({ daily }: { daily: DailyStat[] }) {
  const maxTotal = daily.reduce((max, day) => Math.max(max, day.total), 0);

  return (
    <div className="heatmap">
      <div className="heatmap-grid" role="list" aria-label="Actividad diaria de los últimos 14 días">
        {daily.map((day) => {
          const level = heatLevel(day.total, maxTotal);
          const description = `${formatDay(day.date)}: ${formatNumber(day.total)} archivos escaneados, ${formatNumber(day.infected)} infectados`;
          return (
            <div key={day.date} className={`heatmap-cell level-${level}`} role="listitem">
              <div
                className="heatmap-square"
                role="img"
                aria-label={description}
                title={description}
              >
                <span className="heatmap-count" aria-hidden="true">
                  {day.total}
                </span>
                {day.infected > 0 ? (
                  <span className="heatmap-dot" aria-hidden="true" />
                ) : null}
              </div>
              <span className="heatmap-label">{formatDay(day.date)}</span>
            </div>
          );
        })}
      </div>
      <div className="heatmap-legend">
        <span>Menos</span>
        {[0, 1, 2, 3, 4].map((level) => (
          <span
            key={level}
            className={`heatmap-swatch level-${level}`}
            aria-hidden="true"
          />
        ))}
        <span>Más</span>
        <span className="heatmap-legend-danger">
          <span className="heatmap-dot" aria-hidden="true" />
          Con amenazas
        </span>
      </div>
    </div>
  );
}

interface DashboardViewProps {
  onOpenHistory: () => void;
}

export function DashboardView({ onOpenHistory }: DashboardViewProps) {
  const [stats, setStats] = useState<Stats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [reloadToken, setReloadToken] = useState(0);
  const [chart, setChart] = useState<ChartKind>("donut");
  const [recent, setRecent] = useState<HistoryEntry[] | null>(null);
  const [recentLoading, setRecentLoading] = useState(true);
  const [recentError, setRecentError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    getStats()
      .then((result) => {
        if (!cancelled) setStats(result);
      })
      .catch((cause: unknown) => {
        if (!cancelled) setError(errorMessage(cause));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [reloadToken]);

  useEffect(() => {
    let cancelled = false;
    setRecentLoading(true);
    setRecentError(null);

    getHistory({ limit: 6, offset: 0, filter: "all" })
      .then((page) => {
        if (!cancelled) setRecent(page.entries);
      })
      .catch((cause: unknown) => {
        if (!cancelled) setRecentError(errorMessage(cause));
      })
      .finally(() => {
        if (!cancelled) setRecentLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [reloadToken]);

  const total = stats?.totalScanned ?? 0;
  const safe = stats?.totalSafe ?? 0;
  const infected = stats?.totalInfected ?? 0;
  const rate = stats?.infectionRate ?? 0;
  const daily = stats?.daily.slice(-14) ?? [];

  const handleRefresh = () => {
    setReloadToken((current) => current + 1);
  };

  return (
    <div className="page">
      <PageHeader
        title="Dashboard"
        subtitle="Estado general de la protección y actividad de los últimos 14 días."
        actions={
          <Button
            variant="secondary"
            icon={<RefreshCw size={15} />}
            onClick={handleRefresh}
            disabled={loading}
          >
            Actualizar
          </Button>
        }
      />

      <div className="kpi-strip">
        <div className="kpi-cell">
          <span className="kpi-label">Total escaneado</span>
          <strong className="kpi-value">{stats ? formatNumber(total) : "—"}</strong>
          <span className="kpi-hint">Archivos analizados</span>
        </div>
        <div className="kpi-cell">
          <span className="kpi-label">Seguros</span>
          <strong className="kpi-value positive">{stats ? formatNumber(safe) : "—"}</strong>
          <span className="kpi-hint">Sin coincidencias</span>
        </div>
        <div className="kpi-cell">
          <span className="kpi-label">Infectados</span>
          <strong className="kpi-value negative">
            {stats ? formatNumber(infected) : "—"}
          </strong>
          <span className="kpi-hint">Amenazas detectadas</span>
        </div>
        <div className="kpi-cell">
          <span className="kpi-label">Tasa de infección</span>
          <strong className={`kpi-value ${rate > 0 ? "negative" : "positive"}`}>
            {stats ? formatPercent(rate) : "—"}
          </strong>
          <span className="kpi-hint">Infectados sobre el total</span>
        </div>
      </div>

      <div className="dashboard-grid">
        <Card className="dashboard-chart-card">
          <div className="dashboard-chart-head">
          <div>
            <h2 className="card-title">
              {chart === "heatmap"
                ? "Actividad de los últimos 14 días"
                : "Distribución de archivos"}
            </h2>
            <p className="card-subtitle dashboard-last-scan">
              Último escaneo: <strong>{formatDate(stats?.lastScanAt)}</strong>
            </p>
          </div>
          {total > 0 ? (
            <div className="chart-tabs" role="group" aria-label="Elegir visualización">
              {CHART_OPTIONS.map((option) => {
                const Icon = CHART_ICONS[option.id];
                return (
                  <button
                    key={option.id}
                    type="button"
                    className={`chart-tab ${chart === option.id ? "active" : ""}`.trim()}
                    aria-pressed={chart === option.id}
                    onClick={() => setChart(option.id)}
                  >
                    <Icon size={15} aria-hidden="true" />
                    {option.label}
                  </button>
                );
              })}
            </div>
          ) : null}
        </div>

        {error ? (
          <EmptyState
            icon={<ShieldAlert size={26} />}
            title="No se pudieron cargar las estadísticas"
            description={error}
            action={
              <Button variant="secondary" icon={<RefreshCw size={15} />} onClick={handleRefresh}>
                Reintentar
              </Button>
            }
          />
        ) : !stats ? (
          <div className="chart-loading">
            <Spinner label="Cargando estadísticas" />
          </div>
        ) : total === 0 ? (
          <EmptyState
            icon={<ChartPie size={26} />}
            title="Sin actividad todavía"
            description="Cuando completes tu primer escaneo verás aquí la distribución de archivos seguros e infectados."
          />
        ) : (
          <div className="chart-panel" aria-busy={loading}>
            {chart === "cards" ? (
              <ShareCards safe={safe} infected={infected} total={total} />
            ) : chart === "donut" ? (
              <DonutChart safe={safe} infected={infected} total={total} />
            ) : (
              <Heatmap daily={daily} />
            )}
          </div>
        )}
        </Card>

        <Card className="dashboard-recent">
          <div className="card-header">
            <div>
              <h2 className="card-title">Últimos escaneos</h2>
              <p className="card-subtitle">Los seis archivos más recientes</p>
            </div>
            <button type="button" className="text-link" onClick={onOpenHistory}>
              Ver historial
            </button>
          </div>

          {recentError ? (
            <p className="dashboard-recent-error">{recentError}</p>
          ) : recentLoading && !recent ? (
            <div className="dashboard-recent-loading">
              <Spinner label="Cargando" />
            </div>
          ) : recent && recent.length > 0 ? (
            <ul className="dashboard-recent-list">
              {recent.map((entry) => (
                <li key={entry.id} className="dashboard-recent-row">
                  <div className="dashboard-recent-main">
                    <span className="dashboard-recent-path" title={entry.filePath}>
                      {basename(entry.filePath)}
                    </span>
                    <span className="dashboard-recent-date">
                      {formatDate(entry.scanDate)}
                    </span>
                  </div>
                  <StatusChip tone={entry.isInfected ? "infected" : "safe"}>
                    {entry.isInfected ? "Infectado" : "Seguro"}
                  </StatusChip>
                </li>
              ))}
            </ul>
          ) : (
            <EmptyState
              icon={<ShieldCheck size={24} />}
              title="Sin archivos todavía"
              description="Los resultados de tus escaneos aparecerán aquí."
            />
          )}
        </Card>
      </div>
    </div>
  );
}
