import { Activity, FileWarning, Filter, Network, Search, Signal } from "lucide-react";
import { useState } from "react";
import { BarChartPanel } from "@/components/data/charts/bar-chart-panel";
import { TimelineChart } from "@/components/data/charts/timeline-chart";
import { EmptyState } from "@/components/data/empty-state";
import { MetricCard } from "@/components/data/metric-card";
import { PageHeader } from "@/components/layout/page-header";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { useNetwork } from "@/hooks/use-queries";
import { useMediaQuery } from "@/hooks/use-media-query";

export function NetworkPage() {
  const [sinceHours, setSinceHours] = useState("24");
  const [appliedHours, setAppliedHours] = useState("24");
  const { data, isLoading, isFetching, refetch } = useNetwork(appliedHours);
  const compact = useMediaQuery("(max-width: 700px)");

  const refresh = () => {
    setAppliedHours(sinceHours);
    void refetch();
  };

  return (
    <>
      <PageHeader title="Network" />
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
          <Button onClick={refresh}>
            <Search className="h-4 w-4" />
            Refresh
          </Button>
          {isFetching && <span className="text-sm text-muted-foreground">Loading...</span>}
        </section>

        {isLoading ? (
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {Array.from({ length: 4 }).map((_, i) => (
              <Skeleton key={i} className="h-20" />
            ))}
          </div>
        ) : !data ? (
          <EmptyState message="Loading network capture analytics." />
        ) : (
          <>
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
              <MetricCard label="Network events" value={data.totals.events} icon={Activity} />
              <MetricCard label="Unique IPs" value={data.totals.unique_ips} icon={Network} />
              <MetricCard label="Packets" value={data.totals.packets} icon={Signal} />
              <MetricCard label="Private PCAP chunks" value={data.pcap.chunks} icon={FileWarning} />
            </div>

            <TimelineChart title="Network Timeline" data={data.timeline} />

            <div className="grid gap-4 lg:grid-cols-2">
              <BarChartPanel title="Top Destination Ports" data={data.topPorts} height={compact ? 180 : 220} />
              <BarChartPanel title="Network Event Kinds" data={data.eventKinds} height={compact ? 180 : 220} />
            </div>

            <div className="grid gap-4 lg:grid-cols-2">
              <BarChartPanel title="Network Protocols" data={data.topProtocols} height={compact ? 180 : 220} />
              <BarChartPanel title="TCP Flags" data={data.tcpFlags} height={compact ? 180 : 220} />
            </div>

            <div className="grid gap-4 lg:grid-cols-2">
              <BarChartPanel title="Banner Hit IPs" data={data.topBannerIps} height={compact ? 180 : 220} />
              <div className="rounded-lg border border-border bg-card p-4">
                <h2 className="mb-4 text-sm font-semibold">Private Capture Storage</h2>
                <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
                  <div>
                    <p className="text-xs text-muted-foreground">Chunks</p>
                    <p className="text-lg font-semibold">{data.pcap.chunks}</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">Packets</p>
                    <p className="text-lg font-semibold">{data.pcap.packets}</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">Bytes</p>
                    <p className="text-lg font-semibold">{data.pcap.bytes}</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">Aggregates</p>
                    <p className="text-lg font-semibold">{data.totals.aggregate_events}</p>
                  </div>
                </div>
              </div>
            </div>
          </>
        )}
      </div>
    </>
  );
}
