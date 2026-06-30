import { Download } from "lucide-react";
import { PageHeader } from "@/components/layout/page-header";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { api } from "@/lib/api";

const NEW_FEED_SINCE = encodeURIComponent(new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString());

export function ExportsPage() {
  return (
    <>
      <PageHeader title="Exports" />
      <div className="p-4 sm:p-6">
        <Card>
          <CardContent className="flex flex-col gap-3 p-4">
            <Button
              variant="outline"
              className="justify-start"
              onClick={() => void api.download("/api/exports/blocklist.txt", "honeypot-blocklist.txt")}
            >
              <Download className="h-4 w-4" />
              Public IP Blocklist
            </Button>
            <Button
              variant="outline"
              className="justify-start"
              onClick={() =>
                void api.download(
                  "/api/exports/blocklist.txt?minScore=8",
                  "honeypot-high-confidence-blocklist.txt"
                )
              }
            >
              <Download className="h-4 w-4" />
              High Confidence Blocklist
            </Button>
            <Button
              variant="outline"
              className="justify-start"
              onClick={() =>
                void api.download("/api/exports/network.csv", "honeypot-network-metadata.csv")
              }
            >
              <Download className="h-4 w-4" />
              Network Metadata CSV
            </Button>
            <Button
              variant="outline"
              className="justify-start"
              onClick={() =>
                void api.download("/api/v1/feeds/events.ndjson?limit=1000", "honeypot-events.ndjson")
              }
            >
              <Download className="h-4 w-4" />
              Events NDJSON Feed
            </Button>
            <Button
              variant="outline"
              className="justify-start"
              onClick={() => void api.download("/api/v1/feeds/ips.json?limit=500", "honeypot-ips.json")}
            >
              <Download className="h-4 w-4" />
              IP IOC JSON Feed
            </Button>
            <Button
              variant="outline"
              className="justify-start"
              onClick={() =>
                void api.download("/api/v1/feeds/ips.ndjson?limit=500", "honeypot-ips.ndjson")
              }
            >
              <Download className="h-4 w-4" />
              IP IOC NDJSON Feed
            </Button>
            <Button
              variant="outline"
              className="justify-start"
              onClick={() =>
                void api.download("/api/v1/feeds/ips.stix.json?limit=500", "honeypot-ips.stix.json")
              }
            >
              <Download className="h-4 w-4" />
              IP IOC STIX 2.1 Bundle
            </Button>
            <Button
              variant="outline"
              className="justify-start"
              onClick={() =>
                void api.download(
                  `/api/v1/feeds/new.json?since=${NEW_FEED_SINCE}`,
                  "honeypot-new.json"
                )
              }
            >
              <Download className="h-4 w-4" />
              New IOCs &amp; Events (24h)
            </Button>
          </CardContent>
        </Card>
      </div>
    </>
  );
}
