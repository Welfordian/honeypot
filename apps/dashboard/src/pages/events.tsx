import { Filter, Search } from "lucide-react";
import { useState } from "react";
import { EventsTable } from "@/components/data/events-table";
import { InfiniteLoader } from "@/components/data/infinite-loader";
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
import { DEFAULT_EVENT_FILTERS, useEvents, type EventFilters } from "@/hooks/use-queries";

export function EventsPage() {
  const [filters, setFilters] = useState<EventFilters>(DEFAULT_EVENT_FILTERS);
  const [appliedFilters, setAppliedFilters] = useState<EventFilters>(DEFAULT_EVENT_FILTERS);

  const { data, isLoading, isFetchingNextPage, fetchNextPage, hasNextPage } = useEvents(appliedFilters);

  const applyFilters = () => setAppliedFilters({ ...filters });

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
        </section>

        <EventsTable events={data?.events ?? []} />
        <InfiniteLoader
          hasMore={Boolean(hasNextPage)}
          loading={isLoading || isFetchingNextPage}
          onLoadMore={() => void fetchNextPage()}
        />
      </div>
    </>
  );
}
