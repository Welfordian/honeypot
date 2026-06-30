import { describe, expect, it } from "vitest";
import { eventSummary } from "./deliverHunts.js";

describe("eventSummary", () => {
  it("redacts payload previews before truncating", () => {
    const summary = eventSummary({
      id: "evt-1",
      occurred_at: "2026-01-01T00:00:00.000Z",
      source_ip: "203.0.113.10",
      protocol: "http",
      trap: "web",
      confidence: 80,
      has_username: 1,
      has_password: 1,
      tags_json: "[]",
      event_kind: "trap",
      http_method: null,
      http_path: null,
      payload_preview: "login attempt [admin/password] with password=secret"
    });

    expect(summary).toContain("[[redacted]/[redacted]]");
    expect(summary).toContain("password=[redacted]");
    expect(summary).not.toContain("admin/password");
    expect(summary).not.toContain("password=secret");
  });
});
