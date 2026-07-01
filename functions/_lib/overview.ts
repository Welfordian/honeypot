import { isOperationalSensorId } from "./sensorStatus";
import {
  maxProfileSeverity,
  sumRollupCounts,
  sumRollupEventTotals,
  sumRollupTimeline,
  topAttackersInWindow
} from "./rollups";

export type OverviewSection =
  | "totals"
  | "sensors"
  | "timeline"
  | "topIps"
  | "topProtocols"
  | "topTraps"
  | "topSeverities";

export const ALL_OVERVIEW_SECTIONS: OverviewSection[] = [
  "totals",
  "sensors",
  "timeline",
  "topIps",
  "topProtocols",
  "topTraps",
  "topSeverities"
];

export const SUMMARY_OVERVIEW_SECTIONS: OverviewSection[] = ["totals", "sensors"];

export const CHART_OVERVIEW_SECTIONS: OverviewSection[] = [
  "timeline",
  "topIps",
  "topProtocols",
  "topTraps",
  "topSeverities"
];

export interface OverviewSensor {
  sensor_id: string;
  last_seen: string;
  last_protocol: string | null;
  last_trap: string | null;
  event_count: number;
}

export interface OverviewPayload {
  totals?: { events: number; unique_ips: number; max_severity: number };
  sensors?: OverviewSensor[];
  timeline?: Array<{ bucket: string; count: number }>;
  topIps?: Array<{ key: string; count: number; max_severity: number }>;
  topProtocols?: Array<{ key: string; count: number }>;
  topTraps?: Array<{ key: string; count: number }>;
  topSeverities?: Array<{ key: string; count: number }>;
}

export function parseOverviewSections(url: URL): OverviewSection[] {
  const raw = url.searchParams.get("sections");
  if (!raw) return ALL_OVERVIEW_SECTIONS;

  const valid = new Set<string>(ALL_OVERVIEW_SECTIONS);
  const sections: OverviewSection[] = [];
  for (const part of raw.split(",")) {
    const trimmed = part.trim();
    if (valid.has(trimmed)) sections.push(trimmed as OverviewSection);
  }
  return sections.length ? sections : ALL_OVERVIEW_SECTIONS;
}

export async function fetchOperationalSensors(
  db: D1Database,
  since: string
): Promise<OverviewSensor[]> {
  const result = await db
    .prepare(
      `SELECT sh.sensor_id,
              sh.last_seen,
              sh.last_protocol,
              sh.last_trap,
              COALESCE(w.event_count, 0) AS event_count
       FROM sensor_health sh
       LEFT JOIN (
         SELECT sensor_id, COUNT(*) AS event_count
         FROM events
         WHERE occurred_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
         GROUP BY sensor_id
       ) w ON w.sensor_id = sh.sensor_id
       ORDER BY sh.last_seen DESC
       LIMIT 50`
    )
    .bind(since)
    .all<OverviewSensor>();

  return result.results.filter(
    (sensor) => typeof sensor.sensor_id === "string" && isOperationalSensorId(sensor.sensor_id)
  );
}

export async function fetchOverview(
  db: D1Database,
  since: string,
  sections: OverviewSection[]
): Promise<OverviewPayload> {
  const needs = new Set(sections);
  const payload: OverviewPayload = {};
  const tasks: Promise<void>[] = [];

  if (needs.has("totals")) {
    tasks.push(
      (async () => {
        const [rollupTotals, maxSeverity] = await Promise.all([
          sumRollupEventTotals(db, since),
          maxProfileSeverity(db, since)
        ]);
        payload.totals = {
          events: rollupTotals.events,
          unique_ips: rollupTotals.unique_ips,
          max_severity: maxSeverity
        };
      })()
    );
  }

  if (needs.has("sensors")) {
    tasks.push(
      (async () => {
        payload.sensors = await fetchOperationalSensors(db, since);
      })()
    );
  }

  if (needs.has("timeline")) {
    tasks.push(
      (async () => {
        payload.timeline = await sumRollupTimeline(db, since);
      })()
    );
  }

  if (needs.has("topIps")) {
    tasks.push(
      (async () => {
        const topIps = await topAttackersInWindow(db, since, 10);
        payload.topIps = topIps.map((row) => ({
          key: row.key,
          count: row.count,
          max_severity: row.max_severity
        }));
      })()
    );
  }

  if (needs.has("topProtocols")) {
    tasks.push(
      (async () => {
        payload.topProtocols = await sumRollupCounts(db, "protocol", since, 10);
      })()
    );
  }

  if (needs.has("topTraps")) {
    tasks.push(
      (async () => {
        payload.topTraps = await sumRollupCounts(db, "trap", since, 10);
      })()
    );
  }

  if (needs.has("topSeverities")) {
    tasks.push(
      (async () => {
        const topSeverities = await sumRollupCounts(db, "severity", since, 20);
        payload.topSeverities = topSeverities.sort((a, b) => Number(b.key) - Number(a.key));
      })()
    );
  }

  await Promise.all(tasks);
  return payload;
}
