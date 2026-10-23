import { useEffect, useMemo, useState } from "react";
import {
  ChevronLeft,
  ChevronRight,
  History,
  RefreshCw,
  Search,
  ShieldAlert,
  Trash2,
} from "lucide-react";
import { clearHistory, getHistory, getStats } from "../../api";
import type { HistoryFilter, HistoryPage, Stats } from "../../types";
import { Button } from "../../ui/Button";
import { Card, PageHeader } from "../../ui/Card";
import { ConfirmDialog } from "../../ui/ConfirmDialog";
import { EmptyState } from "../../ui/EmptyState";
import { Spinner } from "../../ui/Spinner";
import { StatusChip } from "../../ui/StatusChip";
import { useToast } from "../../ui/Toast";
import { errorMessage } from "../../lib/errors";
import { formatDate, formatNumber, shortPath } from "../../lib/format";

const PAGE_SIZE = 100;

const FILTERS: ReadonlyArray<{ id: HistoryFilter; label: string }> = [
  { id: "all", label: "Todos" },
  { id: "infected", label: "Infectados" },
  { id: "safe", label: "Seguros" },
];

export function HistoryView() {
  const toast = useToast();
  const [page, setPage] = useState(0);
  const [filter, setFilter] = useState<HistoryFilter>("all");
  const [search, setSearch] = useState("");
  const [historyPage, setHistoryPage] = useState<HistoryPage | null>(null);
  const [stats, setStats] = useState<Stats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [reloadToken, setReloadToken] = useState(0);
  const [confirmClear, setConfirmClear] = useState(false);
  const [clearing, setClearing] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    const load = async () => {
      try {
        const [pageResult, statsResult] = await Promise.all([
          getHistory({ limit: PAGE_SIZE, offset: page * PAGE_SIZE, filter }),
          getStats(),
        ]);
        if (cancelled) return;
        setHistoryPage(pageResult);
        setStats(statsResult);
      } catch (cause) {
        if (!cancelled) setError(errorMessage(cause));
      } finally {
        if (!cancelled) setLoading(false);
      }
    };

    void load();
    return () => {
      cancelled = true;
    };
  }, [page, filter, reloadToken]);

  const entries = historyPage?.entries ?? [];
  const total = historyPage?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const rangeStart = total === 0 ? 0 : page * PAGE_SIZE + 1;
  const rangeEnd = page * PAGE_SIZE + entries.length;
  const isSearching = search.trim().length > 0;

  const visibleEntries = useMemo(() => {
    const term = search.trim().toLowerCase();
    if (!term) return entries;
    return entries.filter((entry) => entry.filePath.toLowerCase().includes(term));
  }, [entries, search]);

  const handleRefresh = () => {
    setReloadToken((current) => current + 1);
  };

  const handleFilterChange = (next: HistoryFilter) => {
    if (next === filter) return;
    setFilter(next);
    setPage(0);
  };

  const handleClear = async () => {
    setClearing(true);
    try {
      const removed = await clearHistory();
      setConfirmClear(false);
      setSearch("");
      setPage(0);
      setReloadToken((current) => current + 1);
      toast.push(`Historial eliminado (${formatNumber(removed)} registros)`, "success");
    } catch (cause) {
      toast.push(errorMessage(cause), "error");
    } finally {
      setClearing(false);
    }
  };

  return (
    <div className="page">
      <PageHeader
        title="Historial de escaneos"
        subtitle="Consulta cada archivo analizado, filtra por resultado y limpia los registros cuando ya no los necesites."
        actions={
          <>
            <Button
              variant="secondary"
              icon={<RefreshCw size={15} />}
              onClick={handleRefresh}
              disabled={loading}
            >
              Actualizar
            </Button>
            <Button
              variant="danger"
              icon={<Trash2 size={15} />}
              onClick={() => setConfirmClear(true)}
              disabled={loading || total === 0}
            >
              Limpiar historial
            </Button>
          </>
        }
      />

      <div className="kpi-strip">
        <div className="kpi-cell">
          <span className="kpi-label">Total escaneado</span>
          <strong className="kpi-value">{stats ? formatNumber(stats.totalScanned) : "—"}</strong>
          <span className="kpi-hint">Archivos registrados</span>
        </div>
        <div className="kpi-cell">
          <span className="kpi-label">Seguros</span>
          <strong className="kpi-value positive">
            {stats ? formatNumber(stats.totalSafe) : "—"}
          </strong>
          <span className="kpi-hint">Sin coincidencias</span>
        </div>
        <div className="kpi-cell">
          <span className="kpi-label">Infectados</span>
          <strong className="kpi-value negative">
            {stats ? formatNumber(stats.totalInfected) : "—"}
          </strong>
          <span className="kpi-hint">Con amenazas detectadas</span>
        </div>
      </div>

      <Card className="history-card">
        <div className="history-toolbar">
          <div className="history-tabs" role="group" aria-label="Filtrar historial por estado">
            {FILTERS.map((option) => (
              <button
                key={option.id}
                type="button"
                className={`history-tab ${filter === option.id ? "active" : ""}`.trim()}
                aria-pressed={filter === option.id}
                onClick={() => handleFilterChange(option.id)}
              >
                {option.label}
              </button>
            ))}
          </div>
          <div className="search history-search">
            <Search size={15} aria-hidden="true" />
            <input
              className="input"
              type="search"
              placeholder="Buscar por ruta…"
              aria-label="Buscar en el historial por ruta"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
            />
          </div>
        </div>

        {isSearching ? (
          <p className="history-search-hint" aria-live="polite">
            {formatNumber(visibleEntries.length)} de {formatNumber(entries.length)} registros de esta
            página coinciden con la búsqueda.
          </p>
        ) : null}

        {error ? (
          <EmptyState
            icon={<ShieldAlert size={26} />}
            title="No se pudo cargar el historial"
            description={error}
            action={
              <Button variant="secondary" icon={<RefreshCw size={15} />} onClick={handleRefresh}>
                Reintentar
              </Button>
            }
          />
        ) : historyPage === null && loading ? (
          <div className="history-loading">
            <Spinner label="Cargando historial" />
          </div>
        ) : total === 0 ? (
          <EmptyState
            icon={<History size={26} />}
            title={
              filter === "all"
                ? "Todavía no hay escaneos"
                : "Sin resultados para este filtro"
            }
            description={
              filter === "all"
                ? "Los archivos analizados aparecerán aquí con su estado y la fecha del análisis."
                : "Prueba con otro filtro para ver más registros del historial."
            }
          />
        ) : (
          <div className="table-wrap" aria-busy={loading}>
            <table className="table history-table">
              <thead>
                <tr>
                  <th scope="col">Archivo</th>
                  <th scope="col">Estado</th>
                  <th scope="col">Fecha</th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr>
                    <td colSpan={3} className="table-empty">
                      <Spinner label="Actualizando historial" />
                    </td>
                  </tr>
                ) : visibleEntries.length === 0 ? (
                  <tr>
                    <td colSpan={3} className="table-empty">
                      Ningún archivo coincide con la búsqueda.
                    </td>
                  </tr>
                ) : (
                  visibleEntries.map((entry) => (
                    <tr key={entry.id}>
                      <td className="path-cell">
                        <span className="path" title={entry.filePath}>
                          {shortPath(entry.filePath)}
                        </span>
                        <span className="sub">
                          {entry.scanId ? `Escaneo ${entry.scanId}` : "Sin identificador de escaneo"}
                        </span>
                      </td>
                      <td>
                        {entry.isInfected ? (
                          <StatusChip tone="infected">Infectado</StatusChip>
                        ) : (
                          <StatusChip tone="safe">Seguro</StatusChip>
                        )}
                      </td>
                      <td>{formatDate(entry.scanDate)}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        )}

        <div className="history-footer">
          <span className="history-range">
            {total === 0
              ? "Sin registros"
              : `${formatNumber(rangeStart)}-${formatNumber(rangeEnd)} de ${formatNumber(total)}`}
          </span>
          <div className="history-pagination">
            <Button
              variant="secondary"
              size="sm"
              icon={<ChevronLeft size={14} />}
              onClick={() => setPage((current) => Math.max(0, current - 1))}
              disabled={page === 0 || loading}
            >
              Anterior
            </Button>
            <span className="history-page-indicator">
              {formatNumber(page + 1)} / {formatNumber(totalPages)}
            </span>
            <Button
              variant="secondary"
              size="sm"
              icon={<ChevronRight size={14} />}
              onClick={() => setPage((current) => Math.min(totalPages - 1, current + 1))}
              disabled={page + 1 >= totalPages || loading}
            >
              Siguiente
            </Button>
          </div>
        </div>
      </Card>

      {confirmClear ? (
        <ConfirmDialog
          title="Limpiar historial"
          message="¿Eliminar todo el historial? Esta acción no se puede deshacer."
          confirmLabel="Eliminar historial"
          tone="danger"
          loading={clearing}
          onConfirm={() => void handleClear()}
          onCancel={() => setConfirmClear(false)}
        />
      ) : null}
    </div>
  );
}
