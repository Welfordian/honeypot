import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";
import type { EventRow } from "@/types/api";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatTime(value?: string): string {
  if (!value) return "";
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit"
  }).format(new Date(value));
}

export function shortHash(value: string): string {
  return `${value.slice(0, 12)}...${value.slice(-6)}`;
}

export type SeverityVariant = "critical" | "high" | "low";

export function severityVariant(severity: number): SeverityVariant {
  if (severity >= 8) return "critical";
  if (severity >= 5) return "high";
  return "low";
}

export function confidenceVariant(confidence: number): SeverityVariant {
  if (confidence >= 80) return "critical";
  if (confidence >= 50) return "high";
  return "low";
}

export function isEventRow(value: unknown): value is EventRow {
  if (!value || typeof value !== "object") return false;
  const event = value as Partial<EventRow>;
  return (
    typeof event.id === "string" &&
    typeof event.occurred_at === "string" &&
    typeof event.received_at === "string" &&
    typeof event.event_kind === "string" &&
    typeof event.source_ip === "string" &&
    typeof event.protocol === "string" &&
    typeof event.trap === "string" &&
    typeof event.sensor_id === "string" &&
    typeof event.has_credentials === "boolean" &&
    typeof event.packet_count === "number" &&
    typeof event.byte_count === "number" &&
    typeof event.is_aggregate === "boolean" &&
    typeof event.pcap_available === "boolean" &&
    typeof event.severity === "number" &&
    typeof event.confidence === "number" &&
    Array.isArray(event.confidence_reasons) &&
    Array.isArray(event.tags)
  );
}

export function mergeLiveEvent(events: EventRow[], next: EventRow): EventRow[] {
  const seen = new Set<string>();
  return [next, ...events]
    .filter((event) => {
      if (seen.has(event.id)) return false;
      seen.add(event.id);
      return true;
    })
    .slice(0, 100);
}

export function mergeByKey<T>(current: T[], next: T[], keyOf: (item: T) => string): T[] {
  const seen = new Set<string>();
  return [...current, ...next].filter((item) => {
    const key = keyOf(item);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

