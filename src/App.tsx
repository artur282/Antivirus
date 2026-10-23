import { useCallback, useEffect, useState } from "react";
import {
  ChartNoAxesCombined,
  FileText,
  History,
  Moon,
  Shield,
  Sun,
} from "lucide-react";
import { getAppInfo, isTauriRuntime, pickSignaturesDb, setSignaturesDb } from "./api";
import type { AppInfo } from "./types";
import { ScanView } from "./features/scan/ScanView";
import { HistoryView } from "./features/history/HistoryView";
import { DashboardView } from "./features/dashboard/DashboardView";
import { ReportsView } from "./features/reports/ReportsView";
import { IconButton } from "./ui/Button";
import { Spinner } from "./ui/Spinner";
import { useToast } from "./ui/Toast";
import { errorMessage } from "./lib/errors";
import { formatNumber } from "./lib/format";

type View = "scan" | "history" | "dashboard" | "reports";
type Theme = "light" | "dark";

const VIEW_TITLES: Record<View, string> = {
  scan: "Centro de escaneo",
  history: "Historial",
  dashboard: "Dashboard",
  reports: "Reportes",
};

const NAV_ITEMS: Array<{ id: View; label: string; icon: typeof Shield }> = [
  { id: "scan", label: "Escaneo", icon: Shield },
  { id: "history", label: "Historial", icon: History },
  { id: "dashboard", label: "Dashboard", icon: ChartNoAxesCombined },
  { id: "reports", label: "Reportes", icon: FileText },
];

function initialTheme(): Theme {
  const saved = localStorage.getItem("antivirus-theme");
  if (saved === "light" || saved === "dark") return saved;
  return "light";
}

function initialView(): View {
  const requested = new URLSearchParams(window.location.search).get("view");
  if (requested && Object.prototype.hasOwnProperty.call(VIEW_TITLES, requested)) {
    return requested as View;
  }
  return "scan";
}

export default function App() {
  const [theme, setTheme] = useState<Theme>(initialTheme);
  const [view, setView] = useState<View>(initialView);

  useEffect(() => {
    const url = new URL(window.location.href);
    if (view === "scan") url.searchParams.delete("view");
    else url.searchParams.set("view", view);
    window.history.replaceState({}, "", url);
  }, [view]);
  const [appInfo, setAppInfo] = useState<AppInfo | null>(null);
  const [bootError, setBootError] = useState<string | null>(null);
  const toast = useToast();

  const refreshAppInfo = useCallback(async () => {
    try {
      const info = await getAppInfo();
      setAppInfo(info);
      setBootError(null);
    } catch (error) {
      setBootError(errorMessage(error));
    }
  }, []);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem("antivirus-theme", theme);
  }, [theme]);

  useEffect(() => {
    void refreshAppInfo();
  }, [refreshAppInfo]);

  const handleDataChanged = useCallback(() => {
    void refreshAppInfo();
  }, [refreshAppInfo]);

  const handleSetupDatabase = useCallback(async () => {
    try {
      const path = await pickSignaturesDb();
      if (!path) return;
      const info = await setSignaturesDb(path);
      setAppInfo(info);
      toast.push("Base de datos de firmas cargada", "success");
    } catch (error) {
      toast.push(errorMessage(error), "error");
    }
  }, [toast]);

  if (bootError) {
    return (
      <div className="boot-screen">
        <div className="boot-card">
          <div className="boot-mark">
            <Shield size={30} />
          </div>
          <h1>No se pudo iniciar el antivirus</h1>
          <p>{bootError}</p>
          <button className="btn btn-primary btn-md" onClick={() => void refreshAppInfo()}>
            Reintentar
          </button>
        </div>
      </div>
    );
  }

  if (!appInfo) {
    return (
      <div className="boot-screen">
        <div className="boot-card">
          <div className="boot-mark">
            <Shield size={30} />
          </div>
          <h1>Antivirus Rust</h1>
          <Spinner label="Iniciando protección" />
        </div>
      </div>
    );
  }

  const ThemeIcon = theme === "dark" ? Sun : Moon;

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">
            <img src="/logo.png" alt="Logo Antivirus Rust" />
          </div>
          <div className="brand-name">
            <strong>Antivirus</strong>
            <span>Rust + Tauri</span>
          </div>
        </div>

        <nav className="nav" aria-label="Navegación principal">
          <span className="nav-label">Panel</span>
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            return (
              <button
                key={item.id}
                className={`nav-item ${view === item.id ? "active" : ""}`}
                onClick={() => setView(item.id)}
                aria-current={view === item.id ? "page" : undefined}
              >
                <span className="nav-icon">
                  <Icon size={18} />
                </span>
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>

        <div className="sidebar-footer">
          <div className="db-status">
            <span className={`db-dot ${appInfo.signaturesReady ? "ok" : ""}`} />
            <div>
              <strong>{appInfo.signaturesReady ? "Firmas activas" : "Sin firmas"}</strong>
              <span>
                {appInfo.signatureCounts
                  ? `${formatNumber(appInfo.signatureCounts.md5)} hashes MD5`
                  : "Conecta virus_data.db"}
              </span>
            </div>
          </div>
          <button className="sidebar-action" onClick={() => void handleSetupDatabase()}>
            {appInfo.signaturesReady ? "Cambiar base de datos" : "Conectar base de datos"}
          </button>
          <span className="sidebar-version">v{appInfo.version}</span>
        </div>
      </aside>

      <div className="frame-main">
        <div className="topbar">
          <div className="topbar-left">
            <span className="topbar-title">{VIEW_TITLES[view]}</span>
          </div>
          <div className="topbar-right">
            {!isTauriRuntime() ? <span className="topbar-note">Modo demo</span> : null}
            <span className="topbar-status">
              <span className={`db-dot ${appInfo.signaturesReady ? "ok" : ""}`} />
              {appInfo.signaturesReady ? "Firmas activas" : "Firmas pendientes"}
            </span>
            <IconButton
              label={theme === "dark" ? "Cambiar a tema claro" : "Cambiar a tema oscuro"}
              onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
            >
              <ThemeIcon size={17} />
            </IconButton>
          </div>
        </div>

        <main className="sheet">
          <div className="content">
            {view === "scan" ? (
              <ScanView
                appInfo={appInfo}
                onDataChanged={handleDataChanged}
                onSetupDatabase={() => void handleSetupDatabase()}
              />
            ) : null}
            {view === "history" ? <HistoryView /> : null}
            {view === "dashboard" ? (
              <DashboardView onOpenHistory={() => setView("history")} />
            ) : null}
            {view === "reports" ? (
              <ReportsView
                appInfo={appInfo}
                onDataChanged={handleDataChanged}
                onSetupDatabase={() => void handleSetupDatabase()}
              />
            ) : null}
          </div>
        </main>
      </div>
    </div>
  );
}
