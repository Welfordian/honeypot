import { describe, expect, it } from "vitest";
import { onRequestGet as onChartsGet } from "../api/analytics/overview/charts";
import { onRequestGet as onSummaryGet } from "../api/analytics/overview/summary";
import { onRequestGet as onOverviewGet } from "../api/analytics/overview";
import {
  ALL_OVERVIEW_SECTIONS,
  CHART_OVERVIEW_SECTIONS,
  fetchOverview,
  parseOverviewSections,
  SUMMARY_OVERVIEW_SECTIONS
} from "./overview";

function createOverviewMockDb() {
  const calls: string[] = [];
  const db = {
    prepare(sql: string) {
      calls.push(sql);
      const bindValues: unknown[] = [];
      const stmt = {
        bind(...args: unknown[]) {
          bindValues.push(...args);
          return stmt;
        },
        async all<T>() {
          if (sql.includes("FROM sensor_health")) {
            return {
              results: [
                {
                  sensor_id: "web",
                  last_seen: "2026-06-30T18:00:00.000Z",
                  last_protocol: "http",
                  last_trap: "env",
                  event_count: 42
                }
              ] as T[]
            };
          }
          if (sql.includes("dimension = 'attacker_ip'")) {
            return { results: [{ key: "203.0.113.10", count: 5 }] as T[] };
          }
          if (sql.includes("GROUP BY bucket_start")) {
            return { results: [{ bucket: "2026-06-30T18:00:00.000Z", count: 3 }] as T[] };
          }
          if (sql.includes("GROUP BY key") && bindValues[0] === "protocol") {
            return { results: [{ key: "http", count: 8 }] as T[] };
          }
          if (sql.includes("GROUP BY key") && bindValues[0] === "trap") {
            return { results: [{ key: "env", count: 6 }] as T[] };
          }
          if (sql.includes("GROUP BY key") && bindValues[0] === "severity") {
            return { results: [{ key: "9", count: 2 }] as T[] };
          }
          return { results: [] as T[] };
        },
        async first<T>() {
          if (sql.includes("dimension = 'event_kind'") && sql.includes("SUM(count)")) {
            return { events: 100 } as T;
          }
          if (sql.includes("COUNT(DISTINCT source_ip)")) {
            return { unique_ips: 12 } as T;
          }
          if (sql.includes("max_severity")) {
            return { max_severity: 9 } as T;
          }
          if (sql.includes("FROM events") && sql.includes("source_ip IN")) {
            return {
              max_severity: 9,
              max_confidence: 80,
              first_seen: "2026-06-30T10:00:00.000Z",
              last_seen: "2026-06-30T18:00:00.000Z"
            } as T;
          }
          if (sql.includes("dimension = 'attacker_ip'") && sql.includes("SUM(count)")) {
            return { events: 100 } as T;
          }
          return null;
        },
        async run() {
          return { success: true, meta: { changes: 0 } };
        }
      };
      return stmt;
    },
    calls
  };
  return db;
}

function pagesContext(path: string, db: ReturnType<typeof createOverviewMockDb>) {
  return {
    request: new Request(`https://dashboard.example.com${path}`),
    env: { DB: db as never },
    params: {},
    waitUntil: () => {},
    passThroughOnException: () => {},
    next: () => Promise.resolve(new Response()),
    data: {}
  };
}

describe("parseOverviewSections", () => {
  it("returns all sections when sections param is absent", () => {
    expect(parseOverviewSections(new URL("https://x/api/analytics/overview"))).toEqual(ALL_OVERVIEW_SECTIONS);
  });

  it("filters to requested sections", () => {
    expect(
      parseOverviewSections(new URL("https://x/api/analytics/overview?sections=timeline,topProtocols"))
    ).toEqual(["timeline", "topProtocols"]);
  });

  it("falls back to all sections when every token is invalid", () => {
    expect(parseOverviewSections(new URL("https://x/api/analytics/overview?sections=bad"))).toEqual(
      ALL_OVERVIEW_SECTIONS
    );
  });
});

describe("fetchOverview", () => {
  it("loads only summary sections", async () => {
    const db = createOverviewMockDb();
    const payload = await fetchOverview(db as never, "-24 hours", SUMMARY_OVERVIEW_SECTIONS);

    expect(payload.totals).toEqual({ events: 100, unique_ips: 12, max_severity: 9 });
    expect(payload.sensors).toHaveLength(1);
    expect(payload.timeline).toBeUndefined();
    expect(db.calls.some((sql) => sql.includes("GROUP BY bucket_start"))).toBe(false);
  });

  it("loads only chart sections", async () => {
    const db = createOverviewMockDb();
    const payload = await fetchOverview(db as never, "-24 hours", CHART_OVERVIEW_SECTIONS);

    expect(payload.timeline).toHaveLength(1);
    expect(payload.topProtocols).toEqual([{ key: "http", count: 8 }]);
    expect(payload.totals).toBeUndefined();
    expect(db.calls.some((sql) => sql.includes("FROM sensor_health"))).toBe(false);
  });
});

describe("overview API handlers", () => {
  it("summary endpoint returns totals and sensors only", async () => {
    const db = createOverviewMockDb();
    const response = await onSummaryGet(pagesContext("/api/analytics/overview/summary?sinceHours=24", db) as never);
    const body = await response.json();

    expect(body).toEqual({
      totals: { events: 100, unique_ips: 12, max_severity: 9 },
      sensors: [
        {
          sensor_id: "web",
          last_seen: "2026-06-30T18:00:00.000Z",
          last_protocol: "http",
          last_trap: "env",
          event_count: 42
        }
      ]
    });
    expect(response.headers.get("cache-control")).toContain("max-age=120");
  });

  it("charts endpoint returns chart sections only", async () => {
    const db = createOverviewMockDb();
    const response = await onChartsGet(pagesContext("/api/analytics/overview/charts?sinceHours=24", db) as never);
    const body = (await response.json()) as {
      totals?: unknown;
      sensors?: unknown;
      timeline?: unknown[];
      topProtocols?: Array<{ key: string; count: number }>;
    };

    expect(body.totals).toBeUndefined();
    expect(body.sensors).toBeUndefined();
    expect(body.timeline).toHaveLength(1);
    expect(body.topProtocols).toEqual([{ key: "http", count: 8 }]);
  });

  it("overview endpoint honors sections query param", async () => {
    const db = createOverviewMockDb();
    const response = await onOverviewGet(
      pagesContext("/api/analytics/overview?sinceHours=24&sections=totals,sensors", db) as never
    );
    const body = await response.json();

    expect(body).toEqual({
      totals: { events: 100, unique_ips: 12, max_severity: 9 },
      sensors: [
        {
          sensor_id: "web",
          last_seen: "2026-06-30T18:00:00.000Z",
          last_protocol: "http",
          last_trap: "env",
          event_count: 42
        }
      ]
    });
  });
});
