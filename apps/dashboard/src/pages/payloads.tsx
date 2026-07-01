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
import { formatCount } from "@/lib/format";
import { usePayloads } from "@/hooks/use-queries";
import { shortHash } from "@/lib/utils";

export function PayloadsPage() {
  const { data, isLoading, isFetchingNextPage, fetchNextPage, hasNextPage } = usePayloads();

  return (
    <>
      <PageHeader title="Payloads" />
      <div className="flex flex-col gap-4 p-4 sm:p-6">
        <Card>
          <CardContent className="p-0 pt-4">
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>SHA-256</TableHead>
                    <TableHead>Events</TableHead>
                    <TableHead>IPs</TableHead>
                    <TableHead>Confidence</TableHead>
                    <TableHead>Size</TableHead>
                    <TableHead>MIME</TableHead>
                    <TableHead>Preview</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(data?.payloads ?? []).map((payload) => (
                    <TableRow key={payload.sha256}>
                      <TableCell className="font-mono">
                        <Link
                          to={`/payloads/${payload.sha256}`}
                          className="text-primary hover:underline"
                        >
                          {shortHash(payload.sha256)}
                        </Link>
                      </TableCell>
                      <TableCell>{formatCount(payload.event_count)}</TableCell>
                      <TableCell>{formatCount(payload.unique_ips)}</TableCell>
                      <TableCell>
                        <SeverityBadge value={payload.max_confidence} type="confidence" />
                      </TableCell>
                      <TableCell>{formatCount(payload.size_bytes)}</TableCell>
                      <TableCell>{payload.mime_guess}</TableCell>
                      <TableCell className="max-w-[200px] truncate">{payload.preview}</TableCell>
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
