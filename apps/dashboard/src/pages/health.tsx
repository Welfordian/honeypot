import { Activity, FileWarning, Network, Signal } from "lucide-react";
import { Link } from "react-router-dom";
import { EmptyState } from "@/components/data/empty-state";
import { ErrorBanner } from "@/components/data/error-banner";
import { MetricCard } from "@/components/data/metric-card";
import { SensorStatusBadge } from "@/components/ops/sensor-status-badge";
import { PageHeader } from "@/components/layout/page-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow
} from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";
import { useOpsStatus } from "@/hooks/use-queries";
import { formatCount } from "@/lib/format";
import { formatTime } from "@/lib/utils";
import type { SensorStatus } from "@/types/api";

function worstStatus(statuses: SensorStatus[]): SensorStatus {
  if (statuses.includes("stale")) return "stale";
  if (statuses.includes("warning")) return "warning";
  return "ok";
}

const OVERALL_VARIANT: Record<SensorStatus, "default" | "high" | "critical"> = {
  ok: "default",
  warning: "high",
  stale: "critical"
};

export function HealthPage() {
  const { data, isLoading, error } = useOpsStatus({ refetchInterval: 60_000 });
  const overall = worstStatus(data?.sensors.map((sensor) => sensor.status) ?? []);

  return (
    <>
      <PageHeader title="Ops Health" />
      <div className="flex flex-col gap-4 p-4 sm:p-6">
        {error && (
          <ErrorBanner message={error instanceof Error ? error.message : "Failed to load ops status."} />
        )}

        {isLoading ? (
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {Array.from({ length: 4 }).map((_, i) => (
              <Skeleton key={i} className="h-20" />
            ))}
          </div>
        ) : !data ? (
          <EmptyState message="No ops status loaded." />
        ) : (
          <>
            <div className="flex flex-wrap items-center gap-3">
              <Badge variant={OVERALL_VARIANT[overall]}>System {overall}</Badge>
              <span className="text-sm text-muted-foreground">
                Last event {formatTime(data.ingest.last_event_at ?? undefined) || "—"}
              </span>
            </div>

            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
              <MetricCard label="Events (24h)" value={data.totals24h.events} icon={Activity} />
              <MetricCard label="Unique IPs (24h)" value={data.totals24h.unique_ips} icon={Network} />
              <MetricCard label="Sensors" value={data.sensors.length} icon={Signal} />
              <MetricCard label="PCAP chunks (24h)" value={data.capture.chunks_24h} icon={FileWarning} />
            </div>

            <Card>
              <CardHeader>
                <CardTitle>Sensor Health</CardTitle>
              </CardHeader>
              <CardContent className="p-0">
                <div className="overflow-x-auto">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Sensor</TableHead>
                        <TableHead>Status</TableHead>
                        <TableHead>Last seen</TableHead>
                        <TableHead>Last trap/protocol</TableHead>
                        <TableHead>Events</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {data.sensors.map((sensor) => (
                        <TableRow key={sensor.sensor_id}>
                          <TableCell>{sensor.sensor_id}</TableCell>
                          <TableCell>
                            <SensorStatusBadge status={sensor.status} />
                          </TableCell>
                          <TableCell>{formatTime(sensor.last_seen)}</TableCell>
                          <TableCell>
                            {sensor.last_protocol}/{sensor.last_trap}
                          </TableCell>
                          <TableCell>{formatCount(sensor.event_count)}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Capture Pipeline</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
                  <div>
                    <p className="text-xs text-muted-foreground">Chunks (24h)</p>
                    <p className="text-lg font-semibold">{formatCount(data.capture.chunks_24h)}</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">Packets (24h)</p>
                    <p className="text-lg font-semibold">{formatCount(data.capture.packets_24h)}</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">Bytes (24h)</p>
                    <p className="text-lg font-semibold">{formatCount(data.capture.bytes_24h)}</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">Expiring within 48h</p>
                    <p className="text-lg font-semibold">{formatCount(data.capture.expiring_soon)}</p>
                  </div>
                </div>
                <p className="mt-4 text-xs text-muted-foreground">
                  Last ingest received {formatTime(data.ingest.last_received_at ?? undefined) || "—"}
                </p>
              </CardContent>
            </Card>

            <div className="flex flex-wrap gap-2">
              <Button variant="outline" size="sm" asChild>
                <Link to="/network">Network analytics</Link>
              </Button>
              <Button variant="outline" size="sm" asChild>
                <Link to="/exports">Exports</Link>
              </Button>
            </div>
          </>
        )}
      </div>
    </>
  );
}
