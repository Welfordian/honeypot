import { RefreshCcw } from "lucide-react";
import { OpsStatusStrip } from "@/components/ops/ops-status-strip";
import { Button } from "@/components/ui/button";

interface PageHeaderProps {
  title: string;
  subtitle?: string;
  onRefresh?: () => void;
  refreshing?: boolean;
  children?: React.ReactNode;
}

export function PageHeader({
  title,
  subtitle = "Public honeypot telemetry from decoy systems. Raw payloads and secrets are redacted.",
  onRefresh,
  refreshing,
  children
}: PageHeaderProps) {
  return (
    <header className="shell-header-bar box-border flex items-center justify-between gap-4 border-b border-border bg-card/50 px-4 max-md:flex-col max-md:items-start max-md:gap-3 max-md:py-4">
      <div className="min-w-0">
        <h1 className="truncate text-xl font-semibold leading-tight tracking-tight">{title}</h1>
        <p className="truncate text-sm leading-tight text-muted-foreground">{subtitle}</p>
        {children}
      </div>
      <div className="flex shrink-0 items-center gap-2">
        <OpsStatusStrip />
        {onRefresh && (
          <Button variant="outline" size="sm" onClick={onRefresh} disabled={refreshing}>
            <RefreshCcw className={refreshing ? "animate-spin" : ""} />
            Refresh
          </Button>
        )}
      </div>
    </header>
  );
}
