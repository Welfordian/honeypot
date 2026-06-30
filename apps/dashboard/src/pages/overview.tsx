import { Activity, Network, ShieldAlert, Signal } from "lucide-react";
import { useQueryClient } from "@tanstack/react-query";
import { BarChartPanel } from "@/components/data/charts/bar-chart-panel";
import { TimelineChart } from "@/components/data/charts/timeline-chart";
import { EmptyState } from "@/components/data/empty-state";
import { ErrorBanner } from "@/components/data/error-banner";
import { MetricCard } from "@/components/data/metric-card";
import { PageHeader } from "@/components/layout/page-header";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow
} from "@/components/ui/table";
import { useOverview } from "@/hooks/use-queries";
import { useMediaQuery } from "@/hooks/use-media-query";
import { formatTime } from "@/lib/utils";

export function OverviewPage() {
  const queryClient = useQueryClient();
  const { data, isLoading, error, isFetching } = useOverview();
  const compact = useMediaQuery("(max-width: 700px)");

  return (
    <>
      <PageHeader
        title="Overview"
        onRefresh={() => void queryClient.invalidateQueries({ queryKey: ["overview"] })}
        refreshing={isFetching}
      />
      <div className="flex flex-col gap-4 p-4 sm:p-6">
        {error && <ErrorBanner message={error instanceof Error ? error.message : "Failed to load dashboard."} />}
        {isLoading ? (
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {Array.from({ length: 4 }).map((_, i) => (
              <Skeleton key={i} className="h-20" />
            ))}
          </div>
        ) : !data ? (
          <EmptyState message="No overview data loaded." />
        ) : (
          <>
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
              <MetricCard label="Events" value={data.totals.events} icon={Activity} />
              <MetricCard label="Unique IPs" value={data.totals.unique_ips} icon={Network} />
              <MetricCard label="Max severity" value={data.totals.max_severity ?? 0} icon={ShieldAlert} />
              <MetricCard label="Sensors" value={data.sensors.length} icon={Signal} />
            </div>

            <TimelineChart title="Attack Timeline" data={data.timeline} height={compact ? 180 : 240} />

            <div className="grid gap-4 lg:grid-cols-2">
              <BarChartPanel title="Top Protocols" data={data.topProtocols} height={compact ? 180 : 220} />
              <BarChartPanel title="Top Traps" data={data.topTraps} height={compact ? 180 : 220} />
            </div>

            <div className="grid gap-4 lg:grid-cols-2">
              <BarChartPanel title="Severity Spread" data={data.topSeverities} height={compact ? 180 : 220} />
              <div className="rounded-lg border border-border bg-card">
                <div className="border-b border-border px-4 py-3">
                  <h2 className="text-sm font-semibold">Sensor Health</h2>
                </div>
                <div className="overflow-x-auto p-2">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Sensor</TableHead>
                        <TableHead>Last Seen</TableHead>
                        <TableHead>Last Trap</TableHead>
                        <TableHead>Events</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {data.sensors.map((sensor) => (
                        <TableRow key={sensor.sensor_id}>
                          <TableCell>{sensor.sensor_id}</TableCell>
                          <TableCell>{formatTime(sensor.last_seen)}</TableCell>
                          <TableCell>
                            {sensor.last_protocol}/{sensor.last_trap}
                          </TableCell>
                          <TableCell>{sensor.event_count}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              </div>
            </div>
          </>
        )}
      </div>
    </>
  );
}
