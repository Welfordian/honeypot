import { FileWarning, Network, ShieldAlert, Signal } from "lucide-react";
import { Link, useParams } from "react-router-dom";
import { BarChartPanel } from "@/components/data/charts/bar-chart-panel";
import { TimelineChart } from "@/components/data/charts/timeline-chart";
import { EmptyState } from "@/components/data/empty-state";
import { ErrorBanner } from "@/components/data/error-banner";
import { EventsTable } from "@/components/data/events-table";
import { InfiniteLoader } from "@/components/data/infinite-loader";
import { MetricCard } from "@/components/data/metric-card";
import { SeverityBadge } from "@/components/data/severity-badge";
import { EventDetailSheet } from "@/components/investigation/event-detail-sheet";
import { PageHeader } from "@/components/layout/page-header";
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
import { useEventInspector } from "@/hooks/use-event-inspector";
import { usePayloadDetailInfinite } from "@/hooks/use-queries";
import { buildSearchUrl } from "@/lib/investigation-links";
import { formatTime, shortHash } from "@/lib/utils";

export function PayloadDetailPage() {
  const { sha256: rawSha } = useParams<{ sha256: string }>();
  const sha256 = rawSha?.toLowerCase() ?? "";
  const { selectedEvent, openEvent, closeEvent } = useEventInspector();

  const {
    data,
    timeline,
    isLoading,
    isFetchingNextPage,
    fetchNextPage,
    hasNextPage,
    error
  } = usePayloadDetailInfinite(sha256);

  return (
    <>
      <PageHeader title={sha256 ? shortHash(sha256) : "Payload Detail"} />
      <div className="flex flex-col gap-4 p-4 sm:p-6">
        <div className="flex flex-wrap items-center gap-2">
          <Button variant="outline" size="sm" asChild>
            <Link to="/payloads">Back to Payloads</Link>
          </Button>
          <span className="font-mono text-sm text-muted-foreground">{shortHash(sha256)}</span>
        </div>

        {error && (
          <ErrorBanner
            message={error instanceof Error ? error.message : "Failed to load payload detail."}
          />
        )}
        {isLoading ? (
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {Array.from({ length: 4 }).map((_, i) => (
              <Skeleton key={i} className="h-20" />
            ))}
          </div>
        ) : !data ? (
          <EmptyState message="Loading payload detail." />
        ) : (
          <>
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
              <MetricCard label="Max confidence" value={data.payload.max_confidence} icon={ShieldAlert} />
              <MetricCard label="Events" value={data.payload.event_count} icon={Signal} />
              <MetricCard label="Unique IPs" value={data.payload.unique_ips} icon={Network} />
              <MetricCard label="Bytes" value={data.payload.size_bytes} icon={FileWarning} />
            </div>

            <Card>
              <CardHeader>
                <CardTitle>Payload Hash</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                  <div>
                    <p className="text-xs text-muted-foreground">SHA-256</p>
                    <p className="break-all font-mono text-sm">{data.payload.sha256}</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">MIME</p>
                    <p className="font-medium">{data.payload.mime_guess}</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">First seen</p>
                    <p className="font-medium">{formatTime(data.payload.first_seen)}</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">Last seen</p>
                    <p className="font-medium">{formatTime(data.payload.last_seen)}</p>
                  </div>
                </div>
                <div>
                  <h3 className="mb-2 text-sm font-medium">Redacted Preview</h3>
                  <p className="rounded-md border border-border bg-background p-3 font-mono text-sm text-muted-foreground">
                    {data.payload.preview || "No preview stored."}
                  </p>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Related searches</CardTitle>
              </CardHeader>
              <CardContent className="flex flex-wrap gap-2">
                <Button variant="outline" size="sm" asChild>
                  <Link to={buildSearchUrl({ payloadHash: sha256 })}>All events with this payload</Link>
                </Button>
                {data.traps[0] && (
                  <Button variant="outline" size="sm" asChild>
                    <Link to={buildSearchUrl({ payloadHash: sha256, trap: data.traps[0].key })}>
                      Same payload + top trap
                    </Link>
                  </Button>
                )}
              </CardContent>
            </Card>

            <TimelineChart title="Payload Timeline" data={timeline} />
            <div className="grid gap-4 lg:grid-cols-2">
              <BarChartPanel title="Protocols" data={data.protocols} height={180} />
              <BarChartPanel title="Traps" data={data.traps} height={180} />
            </div>

            <Card>
              <CardHeader>
                <CardTitle>Related IPs</CardTitle>
              </CardHeader>
              <CardContent className="p-0">
                <div className="overflow-x-auto">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>IP</TableHead>
                        <TableHead>Events</TableHead>
                        <TableHead>Confidence</TableHead>
                        <TableHead>Last Seen</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {data.related_ips.map((ip) => (
                        <TableRow key={ip.source_ip}>
                          <TableCell className="font-mono">
                            <Link
                              to={`/ips/${encodeURIComponent(ip.source_ip)}`}
                              className="text-primary hover:underline"
                            >
                              {ip.source_ip}
                            </Link>
                          </TableCell>
                          <TableCell>{ip.event_count}</TableCell>
                          <TableCell>
                            <SeverityBadge value={ip.max_confidence} type="confidence" />
                          </TableCell>
                          <TableCell>{formatTime(ip.last_seen)}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              </CardContent>
            </Card>

            <EventsTable events={data.events} onSelectEvent={openEvent} />
            <InfiniteLoader
              hasMore={Boolean(hasNextPage)}
              loading={isFetchingNextPage}
              onLoadMore={() => void fetchNextPage()}
            />
            <EventDetailSheet event={selectedEvent} onClose={closeEvent} />
          </>
        )}
      </div>
    </>
  );
}
