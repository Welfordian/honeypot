import { Activity, Network, ShieldAlert, Signal } from "lucide-react";
import { useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { BarChartPanel } from "@/components/data/charts/bar-chart-panel";
import { TimelineChart } from "@/components/data/charts/timeline-chart";
import { EmptyState } from "@/components/data/empty-state";
import { ErrorBanner } from "@/components/data/error-banner";
import { MetricCard } from "@/components/data/metric-card";
import { PageHeader } from "@/components/layout/page-header";
import { SeverityBadge } from "@/components/data/severity-badge";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow
} from "@/components/ui/table";
import { useOverviewCharts, useOverviewSummary } from "@/hooks/use-queries";
import { useMediaQuery } from "@/hooks/use-media-query";
import { formatCount } from "@/lib/format";
import { formatTime } from "@/lib/utils";

function ChartSkeleton({ height }: { height: number }) {
  return <Skeleton className="w-full rounded-lg" style={{ height }} />;
}

export function OverviewPage() {
  const queryClient = useQueryClient();
  const summary = useOverviewSummary();
  const charts = useOverviewCharts();
  const compact = useMediaQuery("(max-width: 700px)");
  const chartHeight = compact ? 180 : 220;
  const timelineHeight = compact ? 180 : 240;

  const isRefreshing = summary.isFetching || charts.isFetching;
  const error = summary.error ?? charts.error;

  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: ["overview"] });
  };

  return (
    <>
      <PageHeader title="Overview" onRefresh={refresh} refreshing={isRefreshing} />
      <div className="flex flex-col gap-4 p-4 sm:p-6">
        {error && (
          <ErrorBanner message={error instanceof Error ? error.message : "Failed to load dashboard."} />
        )}

        {summary.isLoading ? (
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {Array.from({ length: 4 }).map((_, i) => (
              <Skeleton key={i} className="h-20" />
            ))}
          </div>
        ) : !summary.data ? (
          <EmptyState message="No overview data loaded." />
        ) : (
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <MetricCard label="Events" value={summary.data.totals.events} icon={Activity} />
            <MetricCard label="Unique IPs" value={summary.data.totals.unique_ips} icon={Network} />
            <MetricCard
              label="Max severity"
              value={summary.data.totals.max_severity ?? 0}
              icon={ShieldAlert}
            />
            <MetricCard label="Sensors" value={summary.data.sensors.length} icon={Signal} />
          </div>
        )}

        {charts.isLoading ? (
          <ChartSkeleton height={timelineHeight} />
        ) : charts.data ? (
          <TimelineChart title="Attack Timeline" data={charts.data.timeline} height={timelineHeight} />
        ) : null}

        <div className="grid gap-4 lg:grid-cols-2">
          {charts.isLoading ? (
            <>
              <ChartSkeleton height={chartHeight} />
              <ChartSkeleton height={chartHeight} />
            </>
          ) : charts.data ? (
            <>
              <BarChartPanel title="Top Protocols" data={charts.data.topProtocols} height={chartHeight} />
              <BarChartPanel title="Top Traps" data={charts.data.topTraps} height={chartHeight} />
            </>
          ) : null}
        </div>

        <div className="grid gap-4 lg:grid-cols-2">
          {charts.isLoading ? (
            <>
              <ChartSkeleton height={chartHeight} />
              <Skeleton className="h-64 w-full rounded-lg" />
            </>
          ) : charts.data ? (
            <>
              <BarChartPanel title="Severity Spread" data={charts.data.topSeverities} height={chartHeight} />
              <div className="rounded-lg border border-border bg-card">
                <div className="flex items-center justify-between border-b border-border px-4 py-3">
                  <h2 className="text-sm font-semibold">Top Attackers</h2>
                  <Link to="/intel" className="text-xs text-primary hover:underline">
                    View all intel →
                  </Link>
                </div>
                <div className="overflow-x-auto p-2">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>IP</TableHead>
                        <TableHead>Events</TableHead>
                        <TableHead>Max severity</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {charts.data.topIps.map((ip) => (
                        <TableRow key={ip.key}>
                          <TableCell className="font-mono">
                            <Link
                              to={`/ips/${encodeURIComponent(ip.key)}`}
                              className="text-primary hover:underline"
                            >
                              {ip.key}
                            </Link>
                          </TableCell>
                          <TableCell>{formatCount(ip.count)}</TableCell>
                          <TableCell>
                            <SeverityBadge value={ip.max_severity} type="severity" />
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              </div>
            </>
          ) : null}
        </div>

        {summary.isLoading ? (
          <Skeleton className="h-48 w-full rounded-lg" />
        ) : summary.data ? (
          <div className="grid gap-4 lg:grid-cols-2">
            <div className="rounded-lg border border-border bg-card lg:col-span-2">
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
                    {summary.data.sensors.map((sensor) => (
                      <TableRow key={sensor.sensor_id}>
                        <TableCell>{sensor.sensor_id}</TableCell>
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
            </div>
          </div>
        ) : null}
      </div>
    </>
  );
}
