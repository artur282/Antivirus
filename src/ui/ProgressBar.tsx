interface ProgressBarProps {
  value: number;
  label?: string;
  indeterminate?: boolean;
  tone?: "primary" | "success" | "danger" | "warning";
}

export function ProgressBar({
  value,
  label,
  indeterminate = false,
  tone = "primary",
}: ProgressBarProps) {
  const safeValue = Math.max(0, Math.min(100, Number.isFinite(value) ? value : 0));
  return (
    <div className="progress-wrap">
      {label || !indeterminate ? (
        <div className="progress-meta">
          <span>{label ?? "Progreso"}</span>
          {!indeterminate ? <strong>{Math.round(safeValue)}%</strong> : null}
        </div>
      ) : null}
      <div
        className={`progress progress-${tone} ${indeterminate ? "progress-indeterminate" : ""}`}
        role="progressbar"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={indeterminate ? undefined : Math.round(safeValue)}
      >
        <span style={indeterminate ? undefined : { width: `${safeValue}%` }} />
      </div>
    </div>
  );
}
