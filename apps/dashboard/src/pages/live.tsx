import { Signal } from "lucide-react";
import { EventsTable } from "@/components/data/events-table";
import { EventDetailSheet } from "@/components/investigation/event-detail-sheet";
import { PageHeader } from "@/components/layout/page-header";
import { useEventInspector } from "@/hooks/use-event-inspector";
import { useLiveStream } from "@/hooks/use-live-stream";
import { formatTime } from "@/lib/utils";
import { LIVE_STATUS_LABELS } from "@/types/api";
import { cn } from "@/lib/utils";

const STATUS_DOT: Record<string, string> = {
  live: "bg-primary",
  connecting: "bg-warning pulse-dot",
  reconnecting: "bg-warning pulse-dot",
  offline: "bg-destructive"
};

export function LivePage() {
  const { events, status, lastUpdate } = useLiveStream();
  const { selectedEvent, openEvent, closeEvent } = useEventInspector();

  return (
    <>
      <PageHeader title="Live" />
      <div className="flex flex-col gap-4 p-4 sm:p-6">
        <section
          className={cn(
            "flex flex-wrap items-center gap-3 rounded-md border border-border bg-card px-4 py-3 text-sm",
            status === "live" && "border-primary/30"
          )}
        >
          <Signal className="h-4 w-4 text-primary" />
          <span
            className={cn("h-2 w-2 rounded-full", STATUS_DOT[status] ?? STATUS_DOT.offline)}
            aria-hidden
          />
          <span className="font-medium">{LIVE_STATUS_LABELS[status]}</span>
          <span className="text-muted-foreground">Last update {formatTime(lastUpdate)}</span>
        </section>
        <EventsTable events={events} onSelectEvent={openEvent} />
        <EventDetailSheet event={selectedEvent} onClose={closeEvent} />
      </div>
    </>
  );
}
