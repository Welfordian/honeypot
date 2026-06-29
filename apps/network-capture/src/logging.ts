const lastWarnings = new Map<string, number>();

export function warnThrottled(key: string, message: string, error: unknown, intervalMs = 60000): void {
  const now = Date.now();
  const last = lastWarnings.get(key) ?? 0;
  if (now - last < intervalMs) return;
  lastWarnings.set(key, now);

  const detail = error instanceof Error ? `${error.name}: ${error.message}` : String(error);
  console.warn(`${message}: ${detail}`);
}
