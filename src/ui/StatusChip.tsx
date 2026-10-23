import type { ReactNode } from "react";
import { AlertCircle, CheckCircle2, Info, ShieldAlert } from "lucide-react";

type ChipTone = "infected" | "safe" | "warning" | "neutral" | "info" | "danger";

const icons: Record<ChipTone, ReactNode> = {
  infected: <ShieldAlert size={14} />,
  safe: <CheckCircle2 size={14} />,
  warning: <AlertCircle size={14} />,
  neutral: null,
  info: <Info size={14} />,
  danger: <AlertCircle size={14} />,
};

export function StatusChip({ tone, children }: { tone: ChipTone; children: ReactNode }) {
  return (
    <span className={`chip chip-${tone}`}>
      {icons[tone]}
      {children}
    </span>
  );
}
