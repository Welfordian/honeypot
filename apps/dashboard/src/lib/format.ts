const countFormatter = new Intl.NumberFormat("en-US");

/** Format integers with thousands separators (e.g. 212,836). */
export function formatCount(value: number): string {
  return countFormatter.format(value);
}

/** Recharts axis/tooltip helper — coerces numeric strings safely. */
export function formatChartValue(value: number | string): string {
  const n = typeof value === "number" ? value : Number(value);
  return Number.isFinite(n) ? formatCount(n) : String(value);
}
