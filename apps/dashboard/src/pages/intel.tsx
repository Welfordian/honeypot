import { Crosshair, Filter, Search } from "lucide-react";
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useQueries } from "@tanstack/react-query";
import { BarChartPanel } from "@/components/data/charts/bar-chart-panel";
import { EmptyState } from "@/components/data/empty-state";
import { ErrorBanner } from "@/components/data/error-banner";
import { MetricCard } from "@/components/data/metric-card";
import { SeverityBadge } from "@/components/data/severity-badge";
import { PageHeader } from "@/components/layout/page-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow
} from "@/components/ui/table";
import { RollupLineChart } from "@/components/data/charts/rollup-line-chart";
import { Skeleton } from "@/components/ui/skeleton";
import { useIntelOverview, useHttpIntel, useRollups } from "@/hooks/use-queries";
import { api } from "@/lib/api";
import { buildSearchUrl } from "@/lib/investigation-links";
import { shortHash } from "@/lib/utils";
import type { IpDetail } from "@/types/api";

export function IntelPage() {
  const [sinceHours, setSinceHours] = useState("24");
  const [appliedHours, setAppliedHours] = useState("24");
  const { data, isLoading, error } = useIntelOverview(appliedHours);
  const {
    data: httpIntel,
    isLoading: httpLoading,
    error: httpError
  } = useHttpIntel(appliedHours);
  const attackerIps = data?.topAttackers.map((attacker) => attacker.key) ?? [];

  const enrichmentQueries = useQueries({
    queries: attackerIps.map((ip) => ({
      queryKey: ["ip-enrich", ip],
      queryFn: () =>
        api.get<IpDetail>(`/api/v1/ips/${encodeURIComponent(ip)}?enrich=true&limit=1`),
      enabled: Boolean(ip),
      staleTime: 60_000
    }))
  });

  const enrichmentByIp = useMemo(() => {
    const map = new Map<string, IpDetail["profile"]>();
    attackerIps.forEach((ip, index) => {
      const profile = enrichmentQueries[index]?.data?.profile;
      if (profile) map.set(ip, profile);
    });
    return map;
  }, [attackerIps, enrichmentQueries]);

  const topAttackers = useMemo(
    () =>
      (data?.topAttackers ?? []).map((attacker) => {
        const enrichment = enrichmentByIp.get(attacker.key);
        return {
          ...attacker,
          country_code: enrichment?.country_code ?? attacker.country_code,
          asn: enrichment?.asn ?? attacker.asn,
          as_name: enrichment?.as_name ?? attacker.as_name
        };
      }),
    [data?.topAttackers, enrichmentByIp]
  );
  const {
    data: rollups,
    isLoading: rollupsLoading,
    error: rollupsError
  } = useRollups({ sinceHours: "168", bucketWidth: "hour", dimension: "protocol" });

  return (
    <>
      <PageHeader title="Threat Intelligence" />
      <div className="flex flex-col gap-4 p-4 sm:p-6">
        <section className="flex flex-wrap items-center gap-2 rounded-md border border-border bg-card p-3">
          <Filter className="h-4 w-4 text-muted-foreground" />
          <Input
            aria-label="Hours"
            placeholder="Hours"
            value={sinceHours}
            onChange={(e) => setSinceHours(e.target.value)}
            className="w-24"
          />
          <Button
            onClick={() => setAppliedHours(sinceHours)}
          >
            <Search className="h-4 w-4" />
            Apply window
          </Button>
        </section>

        {error && (
          <ErrorBanner message={error instanceof Error ? error.message : "Failed to load intel overview."} />
        )}

        {isLoading ? (
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {Array.from({ length: 3 }).map((_, i) => (
              <Skeleton key={i} className="h-20" />
            ))}
          </div>
        ) : !data ? (
          <EmptyState message="No intelligence data loaded." />
        ) : (
          <>
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              <MetricCard label="Credential attempts" value={data.credentialAttempts} icon={Crosshair} />
              <MetricCard label="High-confidence IPs" value={data.highConfidenceIps} icon={Crosshair} />
              <MetricCard label="Active campaigns" value={data.campaigns.length} icon={Crosshair} />
            </div>

            <section className="space-y-3">
              <h2 className="text-sm font-semibold">Trends</h2>
              {rollupsError && (
                <ErrorBanner
                  message={
                    rollupsError instanceof Error ? rollupsError.message : "Failed to load protocol trends."
                  }
                />
              )}
              {rollupsLoading ? (
                <Skeleton className="h-[300px]" />
              ) : (
                <RollupLineChart
                  title="Protocol activity (7 days)"
                  series={rollups?.series ?? []}
                  height={300}
                />
              )}
            </section>

            <section className="space-y-3">
              <h2 className="text-sm font-semibold">HTTP Attack Surface</h2>
              {httpError && (
                <ErrorBanner
                  message={
                    httpError instanceof Error ? httpError.message : "Failed to load HTTP intelligence."
                  }
                />
              )}
              {httpLoading ? (
                <div className="grid gap-4 lg:grid-cols-2">
                  <Skeleton className="h-[220px]" />
                  <Skeleton className="h-[220px]" />
                </div>
              ) : !httpIntel ? (
                <EmptyState message="No HTTP intelligence loaded." />
              ) : (
                <>
                  <div className="grid gap-4 lg:grid-cols-2">
                    <BarChartPanel
                      title="Top HTTP Paths"
                      data={httpIntel.topPaths.map(({ key, count }) => ({ key, count }))}
                      height={220}
                    />
                    <Card>
                      <CardHeader>
                        <CardTitle>Top User Agents</CardTitle>
                      </CardHeader>
                      <CardContent className="p-0">
                        <div className="overflow-x-auto">
                          <Table>
                            <TableHeader>
                              <TableRow>
                                <TableHead>User agent</TableHead>
                                <TableHead>Events</TableHead>
                                <TableHead>Unique IPs</TableHead>
                              </TableRow>
                            </TableHeader>
                            <TableBody>
                              {httpIntel.topUserAgents.map((row) => (
                                <TableRow key={row.key}>
                                  <TableCell className="max-w-[320px]">
                                    <Link
                                      to={buildSearchUrl({
                                        userAgent: row.key.replace(/…$/, ""),
                                        sinceHours: appliedHours
                                      })}
                                      className="break-all text-xs text-primary hover:underline"
                                    >
                                      {row.key}
                                    </Link>
                                  </TableCell>
                                  <TableCell>{row.count}</TableCell>
                                  <TableCell>{row.unique_ips}</TableCell>
                                </TableRow>
                              ))}
                            </TableBody>
                          </Table>
                        </div>
                      </CardContent>
                    </Card>
                  </div>

                  {httpIntel.probeTrends.length > 0 && (
                    <Card>
                      <CardHeader>
                        <CardTitle>Exploit Probe Trends</CardTitle>
                      </CardHeader>
                      <CardContent className="space-y-4">
                        {httpIntel.probeTrends.map((trend) => (
                          <div key={trend.key} className="space-y-1">
                            <p className="font-mono text-xs text-muted-foreground">{trend.key}</p>
                            <div className="flex flex-wrap gap-2 text-xs">
                              {trend.timeline.map((point) => (
                                <span key={`${trend.key}-${point.bucket}`} className="rounded border px-2 py-1">
                                  {point.bucket.slice(11, 16)}Z · {point.count}
                                </span>
                              ))}
                            </div>
                          </div>
                        ))}
                      </CardContent>
                    </Card>
                  )}

                  {httpIntel.credentialPaths.length > 0 && (
                    <Card>
                      <CardHeader>
                        <CardTitle>Credential Probe Paths</CardTitle>
                      </CardHeader>
                      <CardContent className="p-0">
                        <div className="overflow-x-auto">
                          <Table>
                            <TableHeader>
                              <TableRow>
                                <TableHead>Path</TableHead>
                                <TableHead>Events</TableHead>
                                <TableHead>Unique IPs</TableHead>
                              </TableRow>
                            </TableHeader>
                            <TableBody>
                              {httpIntel.credentialPaths.map((row) => (
                                <TableRow key={row.key}>
                                  <TableCell className="font-mono text-xs">{row.key}</TableCell>
                                  <TableCell>{row.count}</TableCell>
                                  <TableCell>{row.unique_ips}</TableCell>
                                </TableRow>
                              ))}
                            </TableBody>
                          </Table>
                        </div>
                      </CardContent>
                    </Card>
                  )}
                </>
              )}
            </section>

            <Card>
              <CardHeader>
                <CardTitle>Top Attackers</CardTitle>
              </CardHeader>
              <CardContent className="p-0">
                <div className="overflow-x-auto">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>IP</TableHead>
                        <TableHead>Country</TableHead>
                        <TableHead>ASN / Org</TableHead>
                        <TableHead>Events</TableHead>
                        <TableHead>Max severity</TableHead>
                        <TableHead>Confidence</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {topAttackers.map((attacker) => (
                        <TableRow key={attacker.key}>
                          <TableCell className="font-mono">
                            <Link
                              to={`/ips/${encodeURIComponent(attacker.key)}`}
                              className="text-primary hover:underline"
                            >
                              {attacker.key}
                            </Link>
                          </TableCell>
                          <TableCell>{attacker.country_code || "—"}</TableCell>
                          <TableCell className="max-w-[220px] truncate text-sm">
                            {attacker.asn != null ? `AS${attacker.asn}` : "—"}
                            {attacker.as_name ? ` · ${attacker.as_name}` : ""}
                          </TableCell>
                          <TableCell>{attacker.count}</TableCell>
                          <TableCell>
                            <SeverityBadge value={attacker.max_severity} type="severity" />
                          </TableCell>
                          <TableCell>
                            <SeverityBadge value={attacker.max_confidence} type="confidence" />
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              </CardContent>
            </Card>

            <div className="grid gap-4 lg:grid-cols-2">
              <BarChartPanel title="Confidence Signals" data={data.topConfidenceReasons} height={220} />
              <Card>
                <CardHeader>
                  <CardTitle>Tag Activity</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="flex flex-wrap gap-2">
                    {data.topTags.map((tag) => (
                      <Link key={tag.key} to={buildSearchUrl({ tag: tag.key, sinceHours: appliedHours })}>
                        <Badge variant="outline" className="hover:bg-primary/10">
                          {tag.key} ({tag.count})
                        </Badge>
                      </Link>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </div>

            <div className="space-y-3">
              <h2 className="text-sm font-semibold">Active Campaigns</h2>
              <div className="grid gap-4 md:grid-cols-2">
                {data.campaigns.map((campaign) => (
                  <Card key={campaign.sha256}>
                    <CardHeader>
                      <CardTitle className="font-mono text-sm">{shortHash(campaign.sha256)}</CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-3">
                      <div className="grid grid-cols-3 gap-2 text-sm">
                        <div>
                          <p className="text-xs text-muted-foreground">Events</p>
                          <p className="font-medium">{campaign.event_count}</p>
                        </div>
                        <div>
                          <p className="text-xs text-muted-foreground">Unique IPs</p>
                          <p className="font-medium">{campaign.unique_ips}</p>
                        </div>
                        <div>
                          <p className="text-xs text-muted-foreground">Max conf.</p>
                          <SeverityBadge value={campaign.max_confidence} type="confidence" />
                        </div>
                      </div>
                      <div className="flex flex-wrap gap-2">
                        <Button variant="outline" size="sm" asChild>
                          <Link to={`/payloads/${campaign.sha256}`}>Payload detail</Link>
                        </Button>
                        <Button variant="outline" size="sm" asChild>
                          <Link to={buildSearchUrl({ payloadHash: campaign.sha256, sinceHours: appliedHours })}>
                            View events
                          </Link>
                        </Button>
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            </div>

            <div className="flex flex-wrap gap-2">
              {data.topConfidenceReasons.map((reason) => (
                <Button key={reason.key} variant="outline" size="sm" asChild>
                  <Link to={buildSearchUrl({ confidenceReason: reason.key, sinceHours: appliedHours })}>
                    {reason.key}
                  </Link>
                </Button>
              ))}
            </div>
          </>
        )}
      </div>
    </>
  );
}
