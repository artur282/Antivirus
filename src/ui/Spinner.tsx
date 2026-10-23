import { Loader2 } from "lucide-react";

export function Spinner({ label = "Cargando" }: { label?: string }) {
  return (
    <div className="spinner" role="status" aria-label={label}>
      <Loader2 size={20} className="btn-spinner" />
      <span>{label}</span>
    </div>
  );
}
