import { Activity, Network, ShieldAlert, Signal } from "lucide-react";
import { Link, useParams } from "react-router-dom";
import { TimelineChart } from "@/components/data/charts/timeline-chart";
import { EmptyState } from "@/components/data/empty-state";
import { ErrorBanner } from "@/components/data/error-banner";
import { EventsTable } from "@/components/data/events-table";
import { InfiniteLoader } from "@/components/data/infinite-loader";
import { MetricCard } from "@/components/data/metric-card";
import { ReasonChips } from "@/components/data/reason-chips";
import { EventDetailSheet } from "@/components/investigation/event-detail-sheet";
import { PageHeader } from "@/components/layout/page-header";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { useEventInspector } from "@/hooks/use-event-inspector";
import { useIpDetailInfinite } from "@/hooks/use-queries";
import { buildSearchUrl } from "@/lib/investigation-links";
import { formatTime } from "@/lib/utils";

export function IpDetailPage() {
  const { ip: rawIp } = useParams<{ ip: string }>();
  const ip = rawIp ? decodeURIComponent(rawIp) : "";
  const { selectedEvent, openEvent, closeEvent } = useEventInspector();

  const {
    profile,
    events,
    timeline,
    isLoading,
    isFetchingNextPage,
    fetchNextPage,
    hasNextPage,
    error
  } = useIpDetailInfinite(ip);

  return (
    <>
      <PageHeader title={ip || "IP Detail"} />
      <div className="flex flex-col gap-4 p-4 sm:p-6">
        <div className="flex flex-wrap items-center gap-2">
          <Button variant="outline" size="sm" asChild>
            <Link to="/ips">Back to IPs</Link>
          </Button>
          <span className="font-mono text-sm text-muted-foreground">{ip}</span>
        </div>

        {error && (
          <ErrorBanner message={error instanceof Error ? error.message : "Failed to load IP detail."} />
        )}
        {isLoading ? (
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {Array.from({ length: 4 }).map((_, i) => (
              <Skeleton key={i} className="h-20" />
            ))}
          </div>
        ) : !profile ? (
          <EmptyState message="Loading IP detail." />
        ) : (
          <>
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
              <MetricCard label="Confidence" value={profile.confidence} icon={ShieldAlert} />
              <MetricCard label="Score" value={profile.score} icon={Activity} />
              <MetricCard label="Events" value={profile.event_count} icon={Signal} />
              <MetricCard label="Protocols" value={profile.protocols.length} icon={Network} />
            </div>

            <Card>
              <CardHeader>
                <CardTitle>Profile</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
                  <div>
                    <p className="text-xs text-muted-foreground">First seen</p>
                    <p className="font-medium">{formatTime(profile.first_seen)}</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">Last seen</p>
                    <p className="font-medium">{formatTime(profile.last_seen)}</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">Last protocol</p>
                    <p className="font-medium">{profile.last_protocol || ""}</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">Last trap</p>
                    <p className="font-medium">{profile.last_trap || ""}</p>
                  </div>
                </div>
                <div>
                  <h3 className="mb-2 text-sm font-medium">Confidence Reasons</h3>
                  <ReasonChips reasons={profile.confidence_reasons} linkable />
                </div>
                <div>
                  <h3 className="mb-2 text-sm font-medium">Traps and Protocols</h3>
                  <div className="flex flex-wrap gap-2">
                    {profile.unique_traps.map((trap) => (
                      <Button key={trap} variant="outline" size="sm" asChild>
                        <Link to={buildSearchUrl({ ip, trap })}>{trap}</Link>
                      </Button>
                    ))}
                    {profile.protocols.map((protocol) => (
                      <span
                        key={protocol}
                        className="rounded-md border border-border px-2 py-1 text-xs"
                      >
                        {protocol}
                      </span>
                    ))}
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Related searches</CardTitle>
              </CardHeader>
              <CardContent className="flex flex-wrap gap-2">
                <Button variant="outline" size="sm" asChild>
                  <Link to={buildSearchUrl({ ip, hasCredentials: "true" })}>
                    Credential attempts from this IP
                  </Link>
                </Button>
                {profile.last_trap && (
                  <Button variant="outline" size="sm" asChild>
                    <Link to={buildSearchUrl({ ip, trap: profile.last_trap })}>
                      Same trap from this IP
                    </Link>
                  </Button>
                )}
              </CardContent>
            </Card>

            <TimelineChart title="IP Timeline" data={timeline} />
            <EventsTable events={events} onSelectEvent={openEvent} />
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
