import { cn } from "@/lib/utils";
import type { SensorStatus } from "@/types/api";

const STATUS_STYLES: Record<SensorStatus, { dot: string; label: string }> = {
  ok: { dot: "bg-primary", label: "OK" },
  warning: { dot: "bg-warning", label: "Warning" },
  stale: { dot: "bg-destructive", label: "Stale" }
};

interface SensorStatusBadgeProps {
  status: SensorStatus;
  showLabel?: boolean;
  className?: string;
}

export function SensorStatusBadge({ status, showLabel = true, className }: SensorStatusBadgeProps) {
  const style = STATUS_STYLES[status];
  return (
    <span className={cn("inline-flex items-center gap-2 text-sm", className)}>
      <span className={cn("h-2 w-2 rounded-full", style.dot)} aria-hidden />
      {showLabel && <span>{style.label}</span>}
    </span>
  );
}
