import { Activity, Globe, Network, ShieldAlert, Signal } from "lucide-react";
import { Link, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { TimelineChart } from "@/components/data/charts/timeline-chart";
import { EmptyState } from "@/components/data/empty-state";
import { ErrorBanner } from "@/components/data/error-banner";
import { EventsTable } from "@/components/data/events-table";
import { InfiniteLoader } from "@/components/data/infinite-loader";
import { MetricCard } from "@/components/data/metric-card";
import { ReputationBadges } from "@/components/data/reputation-badges";
import { ReasonChips } from "@/components/data/reason-chips";
import { EventDetailSheet } from "@/components/investigation/event-detail-sheet";
import { PageHeader } from "@/components/layout/page-header";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { useEventInspector } from "@/hooks/use-event-inspector";
import { useIpDetailInfinite } from "@/hooks/use-queries";
import { api } from "@/lib/api";
import { buildSearchUrl } from "@/lib/investigation-links";
import { formatTime } from "@/lib/utils";
import type { IpDetail, ReputationSummary } from "@/types/api";

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

  const enrichQuery = useQuery({
    queryKey: ["ip-enrich", ip],
    queryFn: () =>
      api.get<IpDetail>(`/api/v1/ips/${encodeURIComponent(ip)}?enrich=true&limit=1`),
    enabled: Boolean(
      ip &&
        profile &&
        profile.country_code == null &&
        profile.asn == null &&
        profile.as_name == null
    ),
    staleTime: 60_000
  });

  const reputationQuery = useQuery({
    queryKey: ["ip-reputation", ip],
    queryFn: () =>
      api.get<{ ip: string; reputation: ReputationSummary }>(
        `/api/v1/reputation/ips/${encodeURIComponent(ip)}`
      ),
    enabled: Boolean(ip),
    staleTime: 60_000
  });

  const displayProfile = enrichQuery.data?.profile ?? profile;
  const reputation = reputationQuery.data?.reputation;

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
        {reputationQuery.error && (
          <ErrorBanner
            message={
              reputationQuery.error instanceof Error
                ? reputationQuery.error.message
                : "Failed to load IP reputation."
            }
          />
        )}
        {isLoading ? (
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {Array.from({ length: 4 }).map((_, i) => (
              <Skeleton key={i} className="h-20" />
            ))}
          </div>
        ) : !displayProfile ? (
          <EmptyState message="Loading IP detail." />
        ) : (
          <>
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
              <MetricCard label="Confidence" value={displayProfile.confidence} icon={ShieldAlert} />
              <MetricCard label="Score" value={displayProfile.score} icon={Activity} />
              <MetricCard label="Events" value={displayProfile.event_count} icon={Signal} />
              <MetricCard label="Protocols" value={displayProfile.protocols.length} icon={Network} />
            </div>

            <Card>
              <CardHeader>
                <CardTitle>Profile</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
                  <div>
                    <p className="text-xs text-muted-foreground">First seen</p>
                    <p className="font-medium">{formatTime(displayProfile.first_seen)}</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">Last seen</p>
                    <p className="font-medium">{formatTime(displayProfile.last_seen)}</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">Last protocol</p>
                    <p className="font-medium">{displayProfile.last_protocol || ""}</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">Last trap</p>
                    <p className="font-medium">{displayProfile.last_trap || ""}</p>
                  </div>
                </div>
                {(displayProfile.country_code || displayProfile.asn || displayProfile.as_name) && (
                  <div className="grid grid-cols-2 gap-4 sm:grid-cols-3">
                    <div>
                      <p className="text-xs text-muted-foreground">Country</p>
                      <p className="flex items-center gap-1 font-medium">
                        <Globe className="h-3.5 w-3.5 text-muted-foreground" />
                        {displayProfile.country_code || "—"}
                      </p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">ASN</p>
                      <p className="font-medium">
                        {displayProfile.asn != null ? `AS${displayProfile.asn}` : "—"}
                      </p>
                    </div>
                    <div className="col-span-2 sm:col-span-1">
                      <p className="text-xs text-muted-foreground">Organization</p>
                      <p className="font-medium">{displayProfile.as_name || "—"}</p>
                    </div>
                  </div>
                )}
                {reputation?.providers.greynoise && (
                  <div>
                    <h3 className="mb-2 text-sm font-medium">External Reputation</h3>
                    <ReputationBadges greynoise={reputation.providers.greynoise} />
                  </div>
                )}
                <div>
                  <h3 className="mb-2 text-sm font-medium">Confidence Reasons</h3>
                  <ReasonChips reasons={displayProfile.confidence_reasons} linkable />
                </div>
                <div>
                  <h3 className="mb-2 text-sm font-medium">Traps and Protocols</h3>
                  <div className="flex flex-wrap gap-2">
                    {displayProfile.unique_traps.map((trap) => (
                      <Button key={trap} variant="outline" size="sm" asChild>
                        <Link to={buildSearchUrl({ ip, trap })}>{trap}</Link>
                      </Button>
                    ))}
                    {displayProfile.protocols.map((protocol) => (
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
                {displayProfile.last_trap && (
                  <Button variant="outline" size="sm" asChild>
                    <Link to={buildSearchUrl({ ip, trap: displayProfile.last_trap })}>
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
