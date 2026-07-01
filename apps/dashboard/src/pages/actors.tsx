import { Filter, Search, Users } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { EmptyState } from "@/components/data/empty-state";
import { ErrorBanner } from "@/components/data/error-banner";
import { SeverityBadge } from "@/components/data/severity-badge";
import { PageHeader } from "@/components/layout/page-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { useActors } from "@/hooks/use-queries";
import { formatCount } from "@/lib/format";
import { buildSearchUrl } from "@/lib/investigation-links";
import { formatTime, shortHash } from "@/lib/utils";

export function ActorsPage() {
  const [sinceHours, setSinceHours] = useState("168");
  const [appliedHours, setAppliedHours] = useState("168");
  const { data, isLoading, error } = useActors(appliedHours);

  return (
    <>
      <PageHeader title="Actors" />
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
          <Button onClick={() => setAppliedHours(sinceHours)}>
            <Search className="h-4 w-4" />
            Apply window
          </Button>
        </section>

        {error && (
          <ErrorBanner message={error instanceof Error ? error.message : "Failed to load actors."} />
        )}

        {isLoading ? (
          <div className="grid gap-4 md:grid-cols-2">
            {Array.from({ length: 4 }).map((_, i) => (
              <Skeleton key={i} className="h-48" />
            ))}
          </div>
        ) : !data?.actors.length ? (
          <EmptyState message="No actor profiles in this window." />
        ) : (
          <div className="grid gap-4 md:grid-cols-2">
            {data.actors.map((actor) => (
              <Card key={actor.actor_id}>
                <CardHeader className="pb-3">
                  <div className="flex items-start justify-between gap-2">
                    <CardTitle className="font-mono text-sm">
                      <Link
                        to={`/ips/${encodeURIComponent(actor.source_ip)}`}
                        className="text-primary hover:underline"
                      >
                        {actor.source_ip}
                      </Link>
                    </CardTitle>
                    <SeverityBadge value={actor.confidence} type="confidence" />
                  </div>
                  <p className="text-xs text-muted-foreground">
                    {formatCount(actor.event_count)} events · {formatTime(actor.first_seen)} – {formatTime(actor.last_seen)}
                  </p>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div>
                    <p className="mb-1.5 text-xs font-medium text-muted-foreground">Trap timeline</p>
                    <div className="flex flex-wrap gap-1.5">
                      {actor.trap_sequence.map((trap, index) => (
                        <Badge key={`${trap}-${index}`} variant="secondary" className="font-mono text-xs">
                          {index + 1}. {trap}
                        </Badge>
                      ))}
                    </div>
                  </div>

                  {actor.protocols.length > 0 && (
                    <div>
                      <p className="mb-1.5 text-xs font-medium text-muted-foreground">Protocols</p>
                      <div className="flex flex-wrap gap-1.5">
                        {actor.protocols.map((protocol) => (
                          <Badge key={protocol} variant="outline" className="text-xs">
                            {protocol}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}

                  {actor.tags.length > 0 && (
                    <div>
                      <p className="mb-1.5 text-xs font-medium text-muted-foreground">Tags</p>
                      <div className="flex flex-wrap gap-1.5">
                        {actor.tags.map((tag) => (
                          <Link key={tag} to={buildSearchUrl({ tag, sinceHours: appliedHours })}>
                            <Badge variant="outline" className="text-xs hover:bg-primary/10">
                              {tag}
                            </Badge>
                          </Link>
                        ))}
                      </div>
                    </div>
                  )}

                  {actor.related_payloads.length > 0 && (
                    <div>
                      <p className="mb-1.5 text-xs font-medium text-muted-foreground">Related payloads</p>
                      <div className="flex flex-wrap gap-1.5">
                        {actor.related_payloads.map((sha256) => (
                          <Button key={sha256} variant="outline" size="sm" className="h-7 font-mono text-xs" asChild>
                            <Link to={`/payloads/${sha256}`}>{shortHash(sha256)}</Link>
                          </Button>
                        ))}
                      </div>
                    </div>
                  )}

                  {actor.related_ips.length > 0 && (
                    <div>
                      <p className="mb-1.5 flex items-center gap-1 text-xs font-medium text-muted-foreground">
                        <Users className="h-3 w-3" />
                        Behavioral siblings
                      </p>
                      <div className="flex flex-wrap gap-1.5">
                        {actor.related_ips.map((ip) => (
                          <Button key={ip} variant="outline" size="sm" className="h-7 font-mono text-xs" asChild>
                            <Link to={`/ips/${encodeURIComponent(ip)}`}>{ip}</Link>
                          </Button>
                        ))}
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </div>
    </>
  );
}
