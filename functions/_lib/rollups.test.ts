import { describe, expect, it } from "vitest";
import {
  bucketStart,
  exampleIpsForRollupKey,
  maxProfileSeverity,
  topAttackersInWindow,
  topPayloadCampaigns
} from "./rollups";

function createMockDb(handlers: Record<string, (sql: string, bind: unknown[]) => unknown>) {
  return {
    prepare: (sql: string) => {
      const bindValues: unknown[] = [];
      return {
        bind: (...args: unknown[]) => {
          bindValues.push(...args);
          return {
            all: async () => handlers.all?.(sql, bindValues) ?? { results: [] },
            first: async () => handlers.first?.(sql, bindValues) ?? null,
            run: async () => ({ success: true, meta: { changes: 1 } })
          };
        }
      };
    }
  };
}

describe("bucketStart", () => {
  it("aligns to hour boundaries", () => {
    expect(bucketStart("2026-06-30T18:21:16.067Z", "hour")).toBe("2026-06-30T18:00:00.000Z");
  });

  it("aligns to day boundaries", () => {
    expect(bucketStart("2026-06-30T18:21:16.067Z", "day")).toBe("2026-06-30T00:00:00.000Z");
  });
});

describe("topPayloadCampaigns", () => {
  it("aggregates payload stats from events in the time window", async () => {
    const db = createMockDb({
      all: (sql, bind) => {
        expect(sql).toContain("FROM events");
        expect(sql).toContain("payload_sha256 IS NOT NULL");
        expect(sql).toContain("GROUP BY payload_sha256");
        expect(sql).toContain("HAVING event_count >= 2");
        expect(sql).toContain("COUNT(DISTINCT source_ip)");
        expect(sql).toContain("MAX(confidence)");
        expect(sql).not.toContain("FROM payloads");
        expect(bind).toEqual(["-24 hours", 20]);
        return {
          results: [
            {
              sha256: "a".repeat(64),
              event_count: 12,
              unique_ips: 3,
              max_confidence: 88
            }
          ]
        };
      }
    });

    await expect(topPayloadCampaigns(db as never, "-24 hours", 20)).resolves.toEqual([
      {
        sha256: "a".repeat(64),
        event_count: 12,
        unique_ips: 3,
        max_confidence: 88
      }
    ]);
  });
});

describe("maxProfileSeverity", () => {
  it("reads max severity key from rollups in the window", async () => {
    const db = createMockDb({
      first: (sql) => {
        expect(sql).toContain("dimension = 'severity'");
        expect(sql).not.toContain("ip_profiles");
        return { max_severity: 9 };
      }
    });

    await expect(maxProfileSeverity(db as never, "-24 hours")).resolves.toBe(9);
  });
});

describe("exampleIpsForRollupKey", () => {
  it("returns top source IPs ordered by rollup bucket frequency", async () => {
    const db = createMockDb({
      all: (sql, bind) => {
        expect(sql).toContain("rollup_unique_ips");
        expect(sql).toContain("GROUP BY source_ip");
        expect(sql).toContain("ORDER BY COUNT(*) DESC");
        expect(bind).toEqual(["attack_technique", "T1190", "-24 hours", 5]);
        return { results: [{ source_ip: "203.0.113.10" }, { source_ip: "198.51.100.4" }] };
      }
    });

    await expect(
      exampleIpsForRollupKey(db as never, "attack_technique", "T1190", "-24 hours", 5)
    ).resolves.toEqual(["203.0.113.10", "198.51.100.4"]);
  });
});

function mockRollupTotals(windowEvents: number, attackerEvents: number) {
  return {
    prepare: (sql: string) => {
      const bindValues: unknown[] = [];
      return {
        bind: (...args: unknown[]) => {
          bindValues.push(...args);
          return {
            all: async () => {
              if (sql.includes("dimension = 'attacker_ip'") && sql.includes("GROUP BY key")) {
                return { results: [{ key: "203.0.113.10", count: 42 }] };
              }
              if (sql.includes("GROUP BY source_ip") && sql.includes("LIMIT")) {
                return {
                  results: [
                    {
                      key: "198.51.100.4",
                      count: 7,
                      max_severity: 6,
                      max_confidence: 70,
                      first_seen: "2026-06-30T11:00:00.000Z",
                      last_seen: "2026-06-30T12:00:00.000Z"
                    }
                  ]
                };
              }
              if (sql.includes("source_ip IN")) {
                return {
                  results: [
                    {
                      source_ip: "203.0.113.10",
                      max_severity: 8,
                      max_confidence: 90,
                      first_seen: "2026-06-30T10:00:00.000Z",
                      last_seen: "2026-06-30T18:00:00.000Z"
                    }
                  ]
                };
              }
              return { results: [] };
            },
            first: async () => {
              if (sql.includes("dimension = 'event_kind'")) return { events: windowEvents };
              if (sql.includes("COUNT(DISTINCT source_ip)")) return { unique_ips: 5 };
              if (bindValues[0] === "attacker_ip" && sql.includes("SUM(count)")) {
                return { events: attackerEvents };
              }
              return null;
            },
            run: async () => ({ success: true, meta: { changes: 1 } })
          };
        }
      };
    }
  };
}

describe("topAttackersInWindow", () => {
  it("enriches rollup-ranked IPs when attacker_ip rollups are complete", async () => {
    const db = mockRollupTotals(100, 100);

    await expect(topAttackersInWindow(db as never, "-24 hours", 10)).resolves.toEqual([
      {
        key: "203.0.113.10",
        count: 42,
        max_severity: 8,
        max_confidence: 90,
        first_seen: "2026-06-30T10:00:00.000Z",
        last_seen: "2026-06-30T18:00:00.000Z"
      }
    ]);
  });

  it("falls back to events aggregation when attacker_ip rollups are incomplete", async () => {
    const db = mockRollupTotals(100, 0);

    await expect(topAttackersInWindow(db as never, "-168 hours", 5)).resolves.toEqual([
      {
        key: "198.51.100.4",
        count: 7,
        max_severity: 6,
        max_confidence: 70,
        first_seen: "2026-06-30T11:00:00.000Z",
        last_seen: "2026-06-30T12:00:00.000Z"
      }
    ]);
  });
});
