import { Skeleton } from "@/components/ui/skeleton";

export function RouteFallback() {
  return (
    <div className="flex flex-col gap-4 p-4 sm:p-6">
      <Skeleton className="h-9 w-40" />
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <Skeleton key={i} className="h-20" />
        ))}
      </div>
      <Skeleton className="h-60 w-full" />
    </div>
  );
}
