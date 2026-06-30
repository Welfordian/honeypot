import { Download, Filter, Search } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { EventsTable } from "@/components/data/events-table";
import { InfiniteLoader } from "@/components/data/infinite-loader";
import { EventDetailSheet } from "@/components/investigation/event-detail-sheet";
import { PageHeader } from "@/components/layout/page-header";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue
} from "@/components/ui/select";
import { useEventInspector } from "@/hooks/use-event-inspector";
import {
  DEFAULT_EVENT_FILTERS,
  buildEventParams,
  useEvents,
  type EventFilters
} from "@/hooks/use-queries";
import { filtersFromSearchParams, searchParamsFromFilters } from "@/lib/investigation-links";
import { api } from "@/lib/api";
import { CONFIDENCE_REASONS } from "@/types/api";

export function EventsPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const appliedFilters = useMemo(
    () => filtersFromSearchParams(searchParams),
    [searchParams]
  );
  const [filters, setFilters] = useState<EventFilters>(appliedFilters);
  const { selectedEvent, openEvent, closeEvent } = useEventInspector();

  useEffect(() => {
    setFilters(appliedFilters);
  }, [appliedFilters]);

  const { data, isLoading, isFetchingNextPage, fetchNextPage, hasNextPage } = useEvents(appliedFilters);

  const applyFilters = () => {
    setSearchParams(searchParamsFromFilters(filters), { replace: true });
  };

  const exportResults = () => {
    const params = buildEventParams(appliedFilters);
    params.delete("limit");
    void api.download(`/api/v1/feeds/search-export.json?${params.toString()}`, "honeypot-search-export.json");
  };

  return (
    <>
      <PageHeader title="Search" />
      <div className="flex flex-col gap-4 p-4 sm:p-6">
        <section className="flex flex-wrap items-center gap-2 rounded-md border border-border bg-card p-3">
          <Filter className="h-4 w-4 text-muted-foreground" />
          <Input
            aria-label="IP address"
            placeholder="IP address"
            value={filters.ip}
            onChange={(e) => setFilters({ ...filters, ip: e.target.value })}
            className="w-full sm:w-36"
          />
          <Input
            aria-label="Event type, protocol, or trap"
            placeholder="Event type, protocol, or trap"
            value={filters.eventType}
            onChange={(e) => setFilters({ ...filters, eventType: e.target.value })}
            className="w-full sm:w-52"
          />
          <Select
            value={filters.eventKind || "any"}
            onValueChange={(v) => setFilters({ ...filters, eventKind: v === "any" ? "" : v })}
          >
            <SelectTrigger className="w-full sm:w-40" aria-label="Event kind">
              <SelectValue placeholder="Any kind" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="any">Any kind</SelectItem>
              <SelectItem value="trap">Trap</SelectItem>
              <SelectItem value="network-attempt">Network attempt</SelectItem>
              <SelectItem value="tcp-banner">TCP banner</SelectItem>
            </SelectContent>
          </Select>
          <Input
            aria-label="Destination port"
            placeholder="Port"
            value={filters.destinationPort}
            onChange={(e) => setFilters({ ...filters, destinationPort: e.target.value })}
            className="w-full sm:w-24"
          />
          <Input
            aria-label="Tag"
            placeholder="Tag"
            value={filters.tag}
            onChange={(e) => setFilters({ ...filters, tag: e.target.value })}
            className="w-full sm:w-36"
          />
          <Select
            value={filters.confidenceReason || "any"}
            onValueChange={(v) =>
              setFilters({ ...filters, confidenceReason: v === "any" ? "" : v })
            }
          >
            <SelectTrigger className="w-full sm:w-44" aria-label="Confidence reason">
              <SelectValue placeholder="Any reason" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="any">Any reason</SelectItem>
              {CONFIDENCE_REASONS.map((reason) => (
                <SelectItem key={reason} value={reason}>
                  {reason}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Input
            aria-label="Minimum confidence"
            placeholder="Min conf."
            value={filters.minConfidence}
            onChange={(e) => setFilters({ ...filters, minConfidence: e.target.value })}
            className="w-full sm:w-24"
          />
          <Select
            value={filters.hasCredentials || "any"}
            onValueChange={(v) =>
              setFilters({ ...filters, hasCredentials: v === "any" ? "" : v })
            }
          >
            <SelectTrigger className="w-full sm:w-40" aria-label="Credentials filter">
              <SelectValue placeholder="All events" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="any">All events</SelectItem>
              <SelectItem value="true">Credentials only</SelectItem>
            </SelectContent>
          </Select>
          <Input
            aria-label="Payload hash"
            placeholder="Payload hash"
            value={filters.payloadHash}
            onChange={(e) => setFilters({ ...filters, payloadHash: e.target.value })}
            className="w-full sm:w-44 font-mono text-xs"
          />
          <Input
            aria-label="User agent"
            placeholder="User agent"
            value={filters.userAgent}
            onChange={(e) => setFilters({ ...filters, userAgent: e.target.value })}
            className="w-full sm:w-52"
          />
          <Input
            aria-label="HTTP path"
            placeholder="HTTP path"
            value={filters.httpPath}
            onChange={(e) => setFilters({ ...filters, httpPath: e.target.value })}
            className="w-full sm:w-52 font-mono text-xs"
          />
          <Select
            value={filters.aggregate || "both"}
            onValueChange={(v) =>
              setFilters({ ...filters, aggregate: v === "both" ? "" : v })
            }
          >
            <SelectTrigger className="w-full sm:w-44" aria-label="Aggregate state">
              <SelectValue placeholder="Detail + aggregate" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="both">Detail + aggregate</SelectItem>
              <SelectItem value="false">Detail only</SelectItem>
              <SelectItem value="true">Aggregates only</SelectItem>
            </SelectContent>
          </Select>
          <Input
            aria-label="Hours"
            placeholder="Hours"
            value={filters.sinceHours}
            onChange={(e) => setFilters({ ...filters, sinceHours: e.target.value })}
            className="w-full sm:w-20"
          />
          <Button onClick={applyFilters}>
            <Search className="h-4 w-4" />
            Search
          </Button>
          <Button variant="outline" onClick={exportResults}>
            <Download className="h-4 w-4" />
            Export results
          </Button>
          <Button
            variant="outline"
            onClick={() => {
              setFilters(DEFAULT_EVENT_FILTERS);
              setSearchParams({}, { replace: true });
            }}
          >
            Clear
          </Button>
        </section>

        <EventsTable events={data?.events ?? []} onSelectEvent={openEvent} />
        <InfiniteLoader
          hasMore={Boolean(hasNextPage)}
          loading={isLoading || isFetchingNextPage}
          onLoadMore={() => void fetchNextPage()}
        />
        <EventDetailSheet event={selectedEvent} onClose={closeEvent} />
      </div>
    </>
  );
}
