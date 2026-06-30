import { Link } from "react-router-dom";
import { SensorStatusBadge } from "@/components/ops/sensor-status-badge";
import { useOpsStatus } from "@/hooks/use-queries";
import { cn } from "@/lib/utils";
import type { SensorStatus } from "@/types/api";

function worstStatus(statuses: SensorStatus[]): SensorStatus {
  if (statuses.includes("stale")) return "stale";
  if (statuses.includes("warning")) return "warning";
  return "ok";
}

const DOT_CLASS: Record<SensorStatus, string> = {
  ok: "bg-primary",
  warning: "bg-warning",
  stale: "bg-destructive"
};

export function OpsStatusStrip() {
  const { data } = useOpsStatus({ refetchInterval: 60_000 });
  const sensors = data?.sensors ?? [];
  const status = worstStatus(sensors.map((sensor) => sensor.status));

  return (
    <Link
      to="/health"
      className={cn(
        "hidden items-center gap-2 rounded-md border border-border px-3 py-1.5 text-xs text-muted-foreground transition-colors hover:bg-border/40 md:inline-flex",
        status === "warning" && "border-warning/40 text-warning",
        status === "stale" && "border-destructive/40 text-destructive"
      )}
    >
      <span className={cn("h-2 w-2 rounded-full", DOT_CLASS[status])} aria-hidden />
      <span>Live</span>
      <span aria-hidden>·</span>
      <span>{sensors.length} sensors</span>
      {status !== "ok" && (
        <>
          <span aria-hidden>·</span>
          <SensorStatusBadge status={status} />
        </>
      )}
    </Link>
  );
}
