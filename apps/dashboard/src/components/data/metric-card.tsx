import type { LucideIcon } from "lucide-react";
import { formatCount } from "@/lib/format";
import { cn } from "@/lib/utils";

interface MetricCardProps {
  label: string;
  value: number | string;
  icon: LucideIcon;
  className?: string;
}

export function MetricCard({ label, value, icon: Icon, className }: MetricCardProps) {
  const display = typeof value === "number" ? formatCount(value) : value;

  return (
    <div className={cn("rounded-lg border border-border bg-card p-4", className)}>
      <div className="flex items-center justify-between gap-2">
        <p className="text-xs text-muted-foreground">{label}</p>
        <Icon className="h-4 w-4 text-primary" />
      </div>
      <p className="mt-2 text-2xl font-semibold tabular-nums">{display}</p>
    </div>
  );
}
