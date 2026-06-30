import { Link } from "react-router-dom";
import { SeverityBadge } from "@/components/data/severity-badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow
} from "@/components/ui/table";
import { formatTime, shortHash } from "@/lib/utils";
import type { EventRow } from "@/types/api";
import { cn } from "@/lib/utils";

interface EventsTableProps {
  events: EventRow[];
  onSelectEvent?: (event: EventRow) => void;
}

export function EventsTable({ events, onSelectEvent }: EventsTableProps) {
  return (
    <div className="shrink-0 overflow-x-auto rounded-lg border border-border bg-card">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Time</TableHead>
            <TableHead>IP</TableHead>
            <TableHead>Protocol</TableHead>
            <TableHead>Trap</TableHead>
            <TableHead>Kind</TableHead>
            <TableHead>Severity</TableHead>
            <TableHead>Confidence</TableHead>
            <TableHead>Tags</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {events.length === 0 ? (
            <TableRow>
              <TableCell colSpan={8} className="py-8 text-center text-muted-foreground">
                No events found.
              </TableCell>
            </TableRow>
          ) : (
            events.map((event) => (
              <TableRow
                key={event.id}
                className={cn(onSelectEvent && "cursor-pointer hover:bg-border/30")}
                onClick={() => onSelectEvent?.(event)}
              >
                <TableCell>{formatTime(event.occurred_at)}</TableCell>
                <TableCell className="font-mono">
                  <Link
                    to={`/ips/${encodeURIComponent(event.source_ip)}`}
                    className="text-primary hover:underline"
                    onClick={(e) => e.stopPropagation()}
                  >
                    {event.source_ip}
                  </Link>
                </TableCell>
                <TableCell>{event.protocol}</TableCell>
                <TableCell>{event.trap}</TableCell>
                <TableCell>{event.event_kind}</TableCell>
                <TableCell>
                  <SeverityBadge value={event.severity} type="severity" />
                </TableCell>
                <TableCell>
                  <SeverityBadge value={event.confidence} type="confidence" />
                </TableCell>
                <TableCell>
                  <div className="flex max-w-xs flex-wrap gap-1" onClick={(e) => e.stopPropagation()}>
                    {event.tags.slice(0, 3).map((tag) => (
                      <span key={tag} className="rounded border border-border px-1.5 py-0.5 text-[10px]">
                        {tag}
                      </span>
                    ))}
                    {event.payload_sha256 && (
                      <Link
                        to={`/payloads/${event.payload_sha256}`}
                        className="font-mono text-[10px] text-primary hover:underline"
                      >
                        {shortHash(event.payload_sha256)}
                      </Link>
                    )}
                  </div>
                </TableCell>
              </TableRow>
            ))
          )}
        </TableBody>
      </Table>
    </div>
  );
}
