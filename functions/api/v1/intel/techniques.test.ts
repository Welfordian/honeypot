import { describe, expect, it } from "vitest";
import { onRequestGet } from "./techniques";

function createTechniquesMockDb() {
  return {
    prepare(sql: string) {
      const bindValues: unknown[] = [];
      const stmt = {
        bind(...args: unknown[]) {
          bindValues.push(...args);
          return stmt;
        },
        async all<T>() {
          if (sql.includes("analytics_rollups") && bindValues[0] === "attack_technique") {
            return {
              results: [{ key: "T1190", count: 15 }] as T[]
            };
          }
          if (sql.includes("rollup_unique_ips")) {
            return {
              results: [{ source_ip: "203.0.113.10" }, { source_ip: "198.51.100.4" }] as T[]
            };
          }
          if (sql.includes("FROM events") && sql.includes("source_ip IN")) {
            expect(bindValues[0]).toBe("-24 hours");
            expect(bindValues.slice(1)).toEqual(["203.0.113.10", "198.51.100.4"]);
            return {
              results: [
                {
                  id: "evt-match",
                  source_ip: "203.0.113.10",
                  occurred_at: "2026-06-30T18:00:00.000Z",
                  protocol: "http",
                  trap: "env",
                  http_path: "/../../etc/passwd",
                  has_username: 0,
                  has_password: 0,
                  confidence_reasons_json: '["exploit_path"]'
                },
                {
                  id: "evt-no-match",
                  source_ip: "203.0.113.10",
                  occurred_at: "2026-06-30T17:00:00.000Z",
                  protocol: "http",
                  trap: "env",
                  http_path: "/",
                  has_username: 0,
                  has_password: 0,
                  confidence_reasons_json: "[]"
                }
              ] as T[]
            };
          }
          return { results: [] as T[] };
        },
        async first<T>() {
          return null as T | null;
        },
        async run() {
          return { success: true, meta: { changes: 0 } };
        }
      };
      return stmt;
    }
  };
}

function techniquesContext(db: ReturnType<typeof createTechniquesMockDb>) {
  return {
    request: new Request("https://dashboard.example.com/api/v1/intel/techniques?sinceHours=24"),
    env: { DB: db as never },
    params: {},
    waitUntil: () => {},
    passThroughOnException: () => {},
    next: () => Promise.resolve(new Response()),
    data: {}
  };
}

describe("intel techniques example population", () => {
  it("attaches example IPs from rollups and filters example events by technique", async () => {
    const response = await onRequestGet(techniquesContext(createTechniquesMockDb()) as never);
    expect(response.status).toBe(200);

    const body = (await response.json()) as {
      sinceHours: number;
      techniques: Array<{
        id: string;
        count: number;
        example_ips: string[];
        example_events: Array<{ id: string; source_ip: string; occurred_at: string }>;
      }>;
    };

    expect(body.sinceHours).toBe(24);
    expect(body.techniques).toHaveLength(1);
    const technique = body.techniques[0]!;
    expect(technique).toMatchObject({
      id: "T1190",
      count: 15,
      example_ips: ["203.0.113.10", "198.51.100.4"]
    });
    expect(technique.example_events).toEqual([
      {
        id: "evt-match",
        source_ip: "203.0.113.10",
        occurred_at: "2026-06-30T18:00:00.000Z"
      }
    ]);
  });

  it("omits unknown technique rollup keys", async () => {
    const db = {
      prepare(sql: string) {
        const bindValues: unknown[] = [];
        const stmt = {
          bind(...args: unknown[]) {
            bindValues.push(...args);
            return stmt;
          },
          async all<T>() {
            if (sql.includes("analytics_rollups")) {
              return { results: [{ key: "T9999.999", count: 3 }] as T[] };
            }
            return { results: [] as T[] };
          },
          async first<T>() {
            return null as T | null;
          },
          async run() {
            return { success: true, meta: { changes: 0 } };
          }
        };
        return stmt;
      }
    };

    const response = await onRequestGet(techniquesContext(db) as never);
    const body = (await response.json()) as { techniques: unknown[] };
    expect(body.techniques).toEqual([]);
  });
});
