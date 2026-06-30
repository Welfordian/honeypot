import { Download } from "lucide-react";
import { PageHeader } from "@/components/layout/page-header";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { api } from "@/lib/api";

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
          </CardContent>
        </Card>
      </div>
    </>
  );
}
