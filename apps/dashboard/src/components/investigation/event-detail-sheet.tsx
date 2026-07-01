import { Download } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { ReasonChips } from "@/components/data/reason-chips";
import { SeverityBadge } from "@/components/data/severity-badge";
import { Button } from "@/components/ui/button";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle
} from "@/components/ui/sheet";
import { formatCount } from "@/lib/format";
import { buildSearchUrl } from "@/lib/investigation-links";
import { downloadResearcherResource, getResearcherToken } from "@/lib/researcher-token";
import { formatTime, shortHash } from "@/lib/utils";
import type { EventRow } from "@/types/api";

interface EventDetailSheetProps {
  event: EventRow | null;
  onClose: () => void;
}

function DetailField({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <p className="text-xs text-muted-foreground">{label}</p>
      <div className="mt-1 text-sm">{children}</div>
    </div>
  );
}

export function EventDetailSheet({ event, onClose }: EventDetailSheetProps) {
  const [downloadError, setDownloadError] = useState<string | null>(null);
  const researcherToken = getResearcherToken();

  return (
    <Sheet open={Boolean(event)} onOpenChange={(open) => !open && onClose()}>
      <SheetContent className="overflow-y-auto">
        {event && (
          <>
            <SheetHeader>
              <SheetTitle>Event Inspector</SheetTitle>
              <SheetDescription>
                {formatTime(event.occurred_at)} · {event.source_ip}
              </SheetDescription>
            </SheetHeader>

            <div className="grid grid-cols-2 gap-4">
              <DetailField label="Protocol">{event.protocol}</DetailField>
              <DetailField label="Trap">{event.trap}</DetailField>
              <DetailField label="Event kind">{event.event_kind}</DetailField>
              <DetailField label="Sensor">{event.sensor_id}</DetailField>
              <DetailField label="Severity">
                <SeverityBadge value={event.severity} type="severity" />
              </DetailField>
              <DetailField label="Confidence">
                <SeverityBadge value={event.confidence} type="confidence" />
              </DetailField>
            </div>

            {(event.http_method || event.http_path || event.http_status) && (
              <div className="space-y-2 rounded-md border border-border p-3">
                <h3 className="text-sm font-medium">HTTP</h3>
                <div className="grid grid-cols-2 gap-3 text-sm">
                  <DetailField label="Method">{event.http_method || "—"}</DetailField>
                  <DetailField label="Status">{event.http_status ?? "—"}</DetailField>
                  <div className="col-span-2">
                    <DetailField label="Path">
                      <span className="break-all font-mono text-xs">{event.http_path || "—"}</span>
                    </DetailField>
                  </div>
                  {event.user_agent && (
                    <div className="col-span-2">
                      <DetailField label="User agent">
                        <span className="break-all text-xs text-muted-foreground">{event.user_agent}</span>
                      </DetailField>
                    </div>
                  )}
                </div>
              </div>
            )}

            <div className="space-y-2">
              <h3 className="text-sm font-medium">Confidence signals</h3>
              <ReasonChips reasons={event.confidence_reasons} linkable />
            </div>

            {event.attack_techniques.length > 0 && (
              <div className="space-y-2">
                <h3 className="text-sm font-medium">ATT&CK techniques</h3>
                <div className="flex flex-wrap gap-2">
                  {event.attack_techniques.map((technique) => (
                    <Button key={technique} variant="outline" size="sm" asChild>
                      <a
                        href={`https://attack.mitre.org/techniques/${technique.replace(".", "/")}/`}
                        target="_blank"
                        rel="noopener noreferrer"
                      >
                        {technique}
                      </a>
                    </Button>
                  ))}
                </div>
              </div>
            )}

            {event.tags.length > 0 && (
              <div className="space-y-2">
                <h3 className="text-sm font-medium">Tags</h3>
                <div className="flex flex-wrap gap-2">
                  {event.tags.map((tag) => (
                    <Button key={tag} variant="outline" size="sm" asChild>
                      <Link to={buildSearchUrl({ tag })}>{tag}</Link>
                    </Button>
                  ))}
                </div>
              </div>
            )}

            <div className="grid grid-cols-2 gap-4">
              <DetailField label="Source port">{event.source_port ?? "—"}</DetailField>
              <DetailField label="Destination port">{event.destination_port ?? "—"}</DetailField>
              <DetailField label="Packets">{formatCount(event.packet_count)}</DetailField>
              <DetailField label="Bytes">{formatCount(event.byte_count)}</DetailField>
              <DetailField label="TCP flags">{event.tcp_flags || "—"}</DetailField>
              <DetailField label="PCAP">
                {event.pcap_available ? (
                  event.pcap_sha256 && researcherToken ? (
                    <Button
                      variant="outline"
                      size="sm"
                      className="h-8"
                      onClick={() => {
                        setDownloadError(null);
                        void downloadResearcherResource(
                          `/api/v1/researcher/pcap/${event.pcap_sha256}`,
                          `${event.pcap_sha256}.pcap`
                        ).catch((error: unknown) => {
                          setDownloadError(
                            error instanceof Error ? error.message : "PCAP download failed."
                          );
                        });
                      }}
                    >
                      <Download className="h-3.5 w-3.5" />
                      Download PCAP
                    </Button>
                  ) : (
                    "Available (set researcher token in Exports)"
                  )
                ) : (
                  "None"
                )}
              </DetailField>
            </div>

            {downloadError && <p className="text-xs text-destructive">{downloadError}</p>}

            {event.credential_kind && (
              <DetailField label="Credential kind">{event.credential_kind}</DetailField>
            )}

            {event.payload_preview && (
              <div className="space-y-2">
                <h3 className="text-sm font-medium">Redacted payload preview</h3>
                <pre className="overflow-x-auto rounded-md border border-border bg-background p-3 font-mono text-xs text-muted-foreground">
                  {event.payload_preview}
                </pre>
              </div>
            )}

            <div className="space-y-2 border-t border-border pt-4">
              <h3 className="text-sm font-medium">Pivot</h3>
              <div className="flex flex-wrap gap-2">
                <Button variant="outline" size="sm" asChild>
                  <Link to={`/ips/${encodeURIComponent(event.source_ip)}`}>View IP profile</Link>
                </Button>
                <Button variant="outline" size="sm" asChild>
                  <Link to={buildSearchUrl({ ip: event.source_ip })}>Search this IP</Link>
                </Button>
                {event.payload_sha256 && (
                  <Button variant="outline" size="sm" asChild>
                    <Link to={`/payloads/${event.payload_sha256}`}>
                      Payload {shortHash(event.payload_sha256)}
                    </Link>
                  </Button>
                )}
                {event.payload_sha256 && (
                  <Button variant="outline" size="sm" asChild>
                    <Link to={buildSearchUrl({ payloadHash: event.payload_sha256 })}>
                      Search payload hash
                    </Link>
                  </Button>
                )}
                <Button variant="outline" size="sm" asChild>
                  <Link to={buildSearchUrl({ trap: event.trap })}>Same trap</Link>
                </Button>
                {event.destination_port != null && (
                  <Button variant="outline" size="sm" asChild>
                    <Link to={buildSearchUrl({ destinationPort: String(event.destination_port) })}>
                      Port {event.destination_port}
                    </Link>
                  </Button>
                )}
              </div>
            </div>
          </>
        )}
      </SheetContent>
    </Sheet>
  );
}
