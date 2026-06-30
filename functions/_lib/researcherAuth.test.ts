import { describe, expect, it, vi } from "vitest";
import {
  clientIpFromRequest,
  logResearcherAccess,
  requireResearcherToken,
  researcherTokenFromRequest
} from "./researcherAuth";

describe("researcherTokenFromRequest", () => {
  it("reads Bearer authorization", () => {
    const request = new Request("https://example.com", {
      headers: { Authorization: "Bearer secret-token" }
    });
    expect(researcherTokenFromRequest(request)).toBe("secret-token");
  });

  it("reads x-researcher-token header", () => {
    const request = new Request("https://example.com", {
      headers: { "x-researcher-token": "header-token" }
    });
    expect(researcherTokenFromRequest(request)).toBe("header-token");
  });

  it("returns null when no token is provided", () => {
    expect(researcherTokenFromRequest(new Request("https://example.com"))).toBeNull();
  });
});

describe("requireResearcherToken", () => {
  it("returns 503 when researcher access is not configured", async () => {
    const response = requireResearcherToken(new Request("https://example.com"), { DB: {} as D1Database });
    expect(response?.status).toBe(503);
  });

  it("returns 401 for missing or invalid tokens", async () => {
    const configured = { RESEARCHER_API_TOKEN: "expected-token", DB: {} as D1Database };
    const missing = requireResearcherToken(new Request("https://example.com"), configured);
    expect(missing?.status).toBe(401);

    const wrong = requireResearcherToken(
      new Request("https://example.com", { headers: { Authorization: "Bearer wrong" } }),
      configured
    );
    expect(wrong?.status).toBe(401);
  });

  it("returns null when the token matches", () => {
    const response = requireResearcherToken(
      new Request("https://example.com", { headers: { Authorization: "Bearer expected-token" } }),
      { RESEARCHER_API_TOKEN: "expected-token", DB: {} as D1Database }
    );
    expect(response).toBeNull();
  });
});

describe("clientIpFromRequest", () => {
  it("prefers CF-Connecting-IP", () => {
    const request = new Request("https://example.com", {
      headers: { "CF-Connecting-IP": "203.0.113.10", "X-Forwarded-For": "198.51.100.1" }
    });
    expect(clientIpFromRequest(request)).toBe("203.0.113.10");
  });

  it("omits suppressed source IPs before audit logging", () => {
    const request = new Request("https://example.com", {
      headers: { "CF-Connecting-IP": "::ffff:203.0.113.10" }
    });
    expect(clientIpFromRequest(request, { SUPPRESSED_SOURCE_IPS: "203.0.113.10" })).toBeNull();
  });
});

describe("logResearcherAccess", () => {
  it("inserts an audit row", async () => {
    const run = vi.fn().mockResolvedValue({ success: true });
    const bind = vi.fn().mockReturnValue({ run });
    const prepare = vi.fn().mockReturnValue({ bind });
    const db = { prepare } as unknown as D1Database;

    await logResearcherAccess(db, {
      resource_type: "pcap",
      resource_id: "abc123",
      client_ip: "203.0.113.10",
      user_agent: "curl/8.0"
    });

    expect(prepare).toHaveBeenCalledWith(expect.stringContaining("INSERT INTO researcher_access_log"));
    expect(bind).toHaveBeenCalledWith(
      expect.any(String),
      expect.any(String),
      "pcap",
      "abc123",
      "203.0.113.10",
      "curl/8.0"
    );
    expect(run).toHaveBeenCalled();
  });
});
