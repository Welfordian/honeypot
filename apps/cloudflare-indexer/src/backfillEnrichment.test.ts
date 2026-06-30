import { describe, expect, it } from "vitest";
import { backfillEnrichment } from "./backfillEnrichment";
import type { Env } from "./types";

describe("backfillEnrichment", () => {
  it("marks non-enrichable rows as unavailable instead of retrying them forever", async () => {
    const updatedIps: string[] = [];

    const db = {
      prepare(sql: string) {
        return {
          bind(...args: unknown[]) {
            if (sql.startsWith("SELECT")) {
              return {
                all: async () => ({
                  results: [{ source_ip: "10.0.0.1" }, { source_ip: "not-an-ip" }]
                })
              };
            }

            return {
              run: async () => {
                updatedIps.push(String(args[0]));
                return {};
              }
            };
          }
        };
      }
    };

    const result = await backfillEnrichment({ DB: db } as unknown as Env, 500);

    expect(result).toEqual({ processed: 2, enriched: 0, failed: 0 });
    expect(updatedIps).toEqual(["10.0.0.1", "not-an-ip"]);
  });
});
