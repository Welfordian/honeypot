import { Link } from "react-router-dom";
import { InfiniteLoader } from "@/components/data/infinite-loader";
import { SeverityBadge } from "@/components/data/severity-badge";
import { PageHeader } from "@/components/layout/page-header";
import { Card, CardContent } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow
} from "@/components/ui/table";
import { useIps } from "@/hooks/use-queries";

export function IpsPage() {
  const { data, isLoading, isFetchingNextPage, fetchNextPage, hasNextPage } = useIps();

  return (
    <>
      <PageHeader title="IPs" />
      <div className="flex flex-col gap-4 p-4 sm:p-6">
        <Card>
          <CardContent className="p-0 pt-4">
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>IP</TableHead>
                    <TableHead>Country</TableHead>
                    <TableHead>Confidence</TableHead>
                    <TableHead>Score</TableHead>
                    <TableHead>Events</TableHead>
                    <TableHead>Last Type</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(data?.ips ?? []).map((ip) => (
                    <TableRow key={ip.source_ip}>
                      <TableCell className="font-mono">
                        <Link
                          to={`/ips/${encodeURIComponent(ip.source_ip)}`}
                          className="text-primary hover:underline"
                        >
                          {ip.source_ip}
                        </Link>
                      </TableCell>
                      <TableCell>{ip.country_code || "—"}</TableCell>
                      <TableCell>
                        <SeverityBadge value={ip.confidence} type="confidence" />
                      </TableCell>
                      <TableCell>
                        <SeverityBadge value={ip.score} type="severity" />
                      </TableCell>
                      <TableCell>{ip.event_count}</TableCell>
                      <TableCell>
                        {ip.last_protocol}/{ip.last_trap}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>
        <InfiniteLoader
          hasMore={Boolean(hasNextPage)}
          loading={isLoading || isFetchingNextPage}
          onLoadMore={() => void fetchNextPage()}
        />
      </div>
    </>
  );
}
