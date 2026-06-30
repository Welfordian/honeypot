import { Link } from "react-router-dom";
import { PageHeader } from "@/components/layout/page-header";
import { Button } from "@/components/ui/button";

export function NotFoundPage() {
  return (
    <>
      <PageHeader title="Page not found" />
      <div className="flex flex-col items-start gap-4 p-4 sm:p-6">
        <p className="text-sm text-muted-foreground">
          The page you requested does not exist or may have moved.
        </p>
        <Button variant="outline" size="sm" asChild>
          <Link to="/">Back to overview</Link>
        </Button>
      </div>
    </>
  );
}
