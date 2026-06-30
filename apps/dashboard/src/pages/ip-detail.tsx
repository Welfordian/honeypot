import { Activity, Network, ShieldAlert, Signal } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { TimelineChart } from "@/components/data/charts/timeline-chart";
import { EmptyState } from "@/components/data/empty-state";
import { ErrorBanner } from "@/components/data/error-banner";
import { EventsTable } from "@/components/data/events-table";
import { InfiniteLoader } from "@/components/data/infinite-loader";
import { MetricCard } from "@/components/data/metric-card";
import { ReasonChips } from "@/components/data/reason-chips";
import { PageHeader } from "@/components/layout/page-header";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { api } from "@/lib/api";
import { formatTime, mergeByKey } from "@/lib/utils";
import type { EventRow, IpDetail, IpProfile, TimelinePoint } from "@/types/api";

export function IpDetailPage() {
  const { ip: rawIp } = useParams<{ ip: string }>();
  const ip = rawIp ? decodeURIComponent(rawIp) : "";

  const [profile, setProfile] = useState<IpProfile | null>(null);
  const [events, setEvents] = useState<EventRow[]>([]);
  const [timeline, setTimeline] = useState<TimelinePoint[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    setProfile(null);
    setEvents([]);
    setTimeline([]);
    setNextCursor(null);
    setError("");
    setLoading(true);

    Promise.all([
      api.get<IpDetail>(`/api/v1/ips/${encodeURIComponent(ip)}?limit=100`),
      api.get<{ timeline: TimelinePoint[] }>(
        `/api/v1/ips/${encodeURIComponent(ip)}/timeline?sinceHours=168`
      )
    ])
      .then(([detail, timelineResponse]) => {
        if (cancelled) return;
        setProfile(detail.profile);
        setEvents(detail.events);
        setNextCursor(detail.next_cursor);
        setTimeline(timelineResponse.timeline);
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load IP detail.");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [ip]);

  const loadMore = useCallback(async () => {
    if (!nextCursor || loadingMore) return;
    setLoadingMore(true);
    try {
      const response = await api.get<IpDetail>(
        `/api/v1/ips/${encodeURIComponent(ip)}?limit=100&cursor=${encodeURIComponent(nextCursor)}`
      );
      setEvents((current) => mergeByKey(current, response.events, (event) => event.id));
      setNextCursor(response.next_cursor);
    } finally {
      setLoadingMore(false);
    }
  }, [ip, loadingMore, nextCursor]);

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

        {error && <ErrorBanner message={error} />}
        {loading ? (
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
                  <ReasonChips reasons={profile.confidence_reasons} />
                </div>
                <div>
                  <h3 className="mb-2 text-sm font-medium">Traps and Protocols</h3>
                  <div className="flex flex-wrap gap-2">
                    {profile.unique_traps.map((trap) => (
                      <span
                        key={trap}
                        className="rounded-md border border-border px-2 py-1 text-xs"
                      >
                        {trap}
                      </span>
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

            <TimelineChart title="IP Timeline" data={timeline} />
            <EventsTable events={events} />
            <InfiniteLoader
              hasMore={Boolean(nextCursor)}
              loading={loadingMore}
              onLoadMore={() => void loadMore()}
            />
          </>
        )}
      </div>
    </>
  );
}
