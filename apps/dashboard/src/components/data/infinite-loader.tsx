import { Button } from "@/components/ui/button";
import { useInfiniteLoader } from "@/hooks/use-infinite-loader";

interface InfiniteLoaderProps {
  hasMore: boolean;
  loading: boolean;
  onLoadMore: () => void;
}

export function InfiniteLoader({ hasMore, loading, onLoadMore }: InfiniteLoaderProps) {
  const sentinelRef = useInfiniteLoader(hasMore, loading, onLoadMore);

  if (!hasMore && !loading) return null;

  return (
    <div ref={sentinelRef} className="flex justify-center py-4">
      {loading ? (
        <span className="text-sm text-muted-foreground">Loading more...</span>
      ) : (
        <Button variant="outline" size="sm" onClick={onLoadMore}>
          Load more
        </Button>
      )}
    </div>
  );
}
