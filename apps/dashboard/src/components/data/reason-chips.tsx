import { Link } from "react-router-dom";
import { Badge } from "@/components/ui/badge";
import { buildSearchUrl } from "@/lib/investigation-links";

interface ReasonChipsProps {
  reasons: string[];
  linkable?: boolean;
}

export function ReasonChips({ reasons, linkable = false }: ReasonChipsProps) {
  if (!reasons.length) {
    return <span className="text-sm text-muted-foreground">None</span>;
  }

  return (
    <div className="flex flex-wrap gap-2">
      {reasons.map((reason) =>
        linkable ? (
          <Link key={reason} to={buildSearchUrl({ confidenceReason: reason })}>
            <Badge variant="outline" className="hover:bg-primary/10">
              {reason}
            </Badge>
          </Link>
        ) : (
          <Badge key={reason} variant="outline">
            {reason}
          </Badge>
        )
      )}
    </div>
  );
}
