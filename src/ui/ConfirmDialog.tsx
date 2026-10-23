import { AlertTriangle, ShieldCheck, X } from "lucide-react";
import { Modal } from "./Modal";
import { Button } from "./Button";
import type { ReactNode } from "react";

interface ConfirmDialogProps {
  title: string;
  message: ReactNode;
  confirmLabel: string;
  cancelLabel?: string;
  tone?: "danger" | "warning" | "primary";
  loading?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

export function ConfirmDialog({
  title,
  message,
  confirmLabel,
  cancelLabel = "Cancelar",
  tone = "danger",
  loading = false,
  onConfirm,
  onCancel,
}: ConfirmDialogProps) {
  const Icon = tone === "danger" ? AlertTriangle : ShieldCheck;
  return (
    <Modal
      title={title}
      onClose={onCancel}
      size="sm"
      footer={
        <>
          <Button variant="ghost" onClick={onCancel} disabled={loading}>
            {cancelLabel}
          </Button>
          <Button
            variant={tone === "danger" ? "danger" : tone === "warning" ? "warning" : "primary"}
            onClick={onConfirm}
            loading={loading}
          >
            {confirmLabel}
          </Button>
        </>
      }
    >
      <div className={`confirm-content confirm-${tone}`}>
        <span className="confirm-icon">
          <Icon size={22} />
        </span>
        <div>{message}</div>
      </div>
    </Modal>
  );
}

export function CloseButton({ onClick }: { onClick: () => void }) {
  return (
    <button className="icon-btn" aria-label="Cerrar" onClick={onClick}>
      <X size={18} />
    </button>
  );
}
