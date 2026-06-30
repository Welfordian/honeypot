import { describe, expect, it } from "vitest";
import { buildIpIocsQuery, publicIpIoc } from "./ipIocs";

describe("IP IOC feed builder", () => {
  it("maps public-safe IOC fields", () => {
    expect(
      publicIpIoc({
        source_ip: "203.0.113.10",
        first_seen: "2026-06-29T10:00:00.000Z",
        last_seen: "2026-06-30T12:00:00.000Z",
        score: 8,
        confidence: 85,
        confidence_reasons_json: '["credential_attempt"]',
        unique_traps_json: '["env"]',
        protocols_json: '["http"]'
      })
    ).toEqual({
      source_ip: "203.0.113.10",
      first_seen: "2026-06-29T10:00:00.000Z",
      last_seen: "2026-06-30T12:00:00.000Z",
      confidence: 85,
      score: 8,
      confidence_reasons: ["credential_attempt"],
      unique_traps: ["env"],
      protocols: ["http"]
    });
  });

  it("filters by minConfidence and since", () => {
    const query = buildIpIocsQuery(
      new URL("https://dashboard.example.com/api/v1/feeds/ips.json?minConfidence=50&since=2026-06-29T00:00:00.000Z")
    );

    expect(query).not.toBeInstanceOf(Response);
    if (query instanceof Response) return;
    expect(query.sql).toContain("confidence >= ?");
    expect(query.sql).toContain("first_seen >= ?");
    expect(query.params).toContain(50);
    expect(query.params).toContain("2026-06-29T00:00:00.000Z");
  });

  it("rejects invalid minConfidence", () => {
    const query = buildIpIocsQuery(
      new URL("https://dashboard.example.com/api/v1/feeds/ips.json?minConfidence=150")
    );
    expect(query).toBeInstanceOf(Response);
    expect((query as Response).status).toBe(400);
  });
});
