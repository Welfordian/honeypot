import { describe, expect, it } from "vitest";
import {
  artifactFromHttpPath,
  artifactFromPayload,
  buildArtifactIocsQuery,
  extractDomainFromPath,
  extractUriFromEvent
} from "./artifactIocs";

describe("artifact IOC extraction", () => {
  it("extracts domains from absolute URLs", () => {
    expect(extractDomainFromPath("https://evil.example.com/shell.php")).toBe("evil.example.com");
    expect(extractDomainFromPath("http://10.0.0.1/admin")).toBeNull();
  });

  it("extracts domains from protocol-relative and embedded URLs", () => {
    expect(extractDomainFromPath("//cdn.evil.example/x")).toBe("cdn.evil.example");
    expect(extractDomainFromPath("/proxy?next=https://evil.example/")).toBe("evil.example");
  });

  it("extracts domains from path segments", () => {
    expect(extractDomainFromPath("/evil.example/c99.php")).toBe("evil.example");
  });

  it("classifies http_path values into url or domain IOCs", () => {
    expect(extractUriFromEvent({ http_path: "https://evil.example/a" })).toEqual({
      type: "url",
      value: "https://evil.example/a"
    });
    expect(extractUriFromEvent({ http_path: "/evil.example/a" })).toEqual({
      type: "domain",
      value: "evil.example"
    });
    expect(extractUriFromEvent({ http_path: "/.env" })).toEqual({
      type: "url",
      value: "/.env"
    });
    expect(extractUriFromEvent({ http_path: null })).toBeNull();
  });

  it("maps payload rows to file artifacts", () => {
    expect(
      artifactFromPayload({
        sha256: "a".repeat(64),
        size_bytes: 128,
        mime_guess: "text/plain",
        first_seen: "2026-06-29T10:00:00.000Z",
        last_seen: "2026-06-30T12:00:00.000Z",
        event_count: 4,
        max_confidence: 80,
        unique_ips: 2,
        source_ips_csv: "203.0.113.10,198.51.100.4"
      })
    ).toEqual({
      type: "file",
      value: "a".repeat(64),
      first_seen: "2026-06-29T10:00:00.000Z",
      last_seen: "2026-06-30T12:00:00.000Z",
      confidence: 80,
      event_count: 4,
      unique_ips: 2,
      source_ips: ["203.0.113.10", "198.51.100.4"],
      size_bytes: 128,
      mime_guess: "text/plain"
    });
  });

  it("maps grouped http paths to uri artifacts", () => {
    expect(
      artifactFromHttpPath({
        http_path: "/wp-login.php",
        first_seen: "2026-06-29T10:00:00.000Z",
        last_seen: "2026-06-30T12:00:00.000Z",
        confidence: 70,
        event_count: 9,
        unique_ips: 3,
        source_ips_csv: "203.0.113.10"
      })
    ).toEqual({
      type: "url",
      value: "/wp-login.php",
      first_seen: "2026-06-29T10:00:00.000Z",
      last_seen: "2026-06-30T12:00:00.000Z",
      confidence: 70,
      event_count: 9,
      unique_ips: 3,
      source_ips: ["203.0.113.10"]
    });
  });

  it("filters by minConfidence and since", () => {
    const query = buildArtifactIocsQuery(
      new URL(
        "https://dashboard.example.com/api/v1/feeds/artifacts.json?minConfidence=50&since=2026-06-29T00:00:00.000Z"
      )
    );

    expect(query).not.toBeInstanceOf(Response);
    if (query instanceof Response) return;
    expect(query.payloadsSql).toContain("p.first_seen >= ?");
    expect(query.payloadsSql).toContain("max_confidence >= ?");
    expect(query.pathsSql).toContain("occurred_at >= ?");
    expect(query.pathsSql).toContain("confidence >= ?");
    expect(query.payloadsParams).toContain(50);
    expect(query.pathsParams).toContain("2026-06-29T00:00:00.000Z");
  });

  it("rejects invalid minConfidence", () => {
    const query = buildArtifactIocsQuery(
      new URL("https://dashboard.example.com/api/v1/feeds/artifacts.json?minConfidence=150")
    );
    expect(query).toBeInstanceOf(Response);
    expect((query as Response).status).toBe(400);
  });
});
