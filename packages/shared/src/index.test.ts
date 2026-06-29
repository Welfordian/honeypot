import { describe, expect, it } from "vitest";
import {
  HONEYPOT_EVENT_SCHEMA,
  confidenceForEvent,
  confidenceForProfile,
  redactHeaders,
  safePreview,
  scoreEvent,
  signBody,
  verifySignature
} from "./index.js";

describe("shared safety helpers", () => {
  it("redacts sensitive headers", () => {
    expect(redactHeaders({ authorization: "Bearer secret-value", "user-agent": "curl" })).toEqual({
      authorization: "Bear...[redacted:19]",
      "user-agent": "curl"
    });
  });

  it("escapes non-printable preview characters", () => {
    expect(safePreview("ok\u0000\u0003\r\n\tend")).toBe("ok\\x00\\x03\r\n\tend");
  });

  it("scores obvious exploit probes higher than passive hits", () => {
    const parsed = HONEYPOT_EVENT_SCHEMA.parse({
      sensorId: "web",
      trap: "env",
      protocol: "http",
      source: { ip: "203.0.113.10" },
      http: { path: "/.env", userAgent: "curl/8" },
      payload: { text: "APP_KEY=abc" }
    });

    expect(scoreEvent(parsed)).toBeGreaterThanOrEqual(6);
  });

  it("verifies HMAC signatures with constant-time comparison", () => {
    const signature = signBody("secret", "2026-06-29T12:00:00.000Z", "{\"ok\":true}");
    expect(verifySignature("secret", "2026-06-29T12:00:00.000Z", "{\"ok\":true}", signature)).toBe(true);
    expect(verifySignature("secret", "2026-06-29T12:00:00.000Z", "{\"ok\":false}", signature)).toBe(false);
  });

  it("assigns confidence reasons for exploit-like probes", () => {
    const result = confidenceForEvent({
      severity: 8,
      protocol: "http",
      httpPath: "/wp-login.php?cmd=id",
      userAgent: "sqlmap",
      hasCredentials: true,
      hasPayload: true
    });

    expect(result.confidence).toBe(100);
    expect(result.reasons).toEqual([
      "credential_attempt",
      "exploit_path",
      "high_severity",
      "payload_present",
      "scanner_user_agent",
      "sensitive_path"
    ]);
  });

  it("adds profile confidence for repeat and diverse activity", () => {
    const result = confidenceForProfile({
      maxEventConfidence: 70,
      eventCount: 12,
      uniqueTraps: ["env", "login", "metadata"],
      protocols: ["http", "ssh"],
      eventReasons: ["payload_present"]
    });

    expect(result.confidence).toBe(92);
    expect(result.reasons).toEqual(["payload_present", "protocol_diversity", "repeat_activity", "trap_diversity"]);
  });
});
