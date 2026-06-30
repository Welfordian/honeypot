export function EmptyState({ message }: { message: string }) {
  return (
    <div className="flex h-20 items-center justify-center rounded-lg border border-dashed border-border bg-card/50 px-4 py-4 text-sm text-muted-foreground">
      {message}
    </div>
  );
}
