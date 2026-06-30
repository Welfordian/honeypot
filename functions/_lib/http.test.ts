import { describe, expect, it } from "vitest";
import { cachedJson, parseEventCursor, parseSinceIso, publicIp, publicSha256 } from "./http";

describe("public API helpers", () => {
  it("validates public IP and SHA-256 route params", () => {
    expect(publicIp("203.0.113.10")).toBe("203.0.113.10");
    expect(publicIp("bad/ip")).toBeNull();
    expect(publicSha256("A".repeat(64))).toBe("a".repeat(64));
    expect(publicSha256("not-a-hash")).toBeNull();
  });

  it("uses public cache headers for v1 JSON responses", () => {
    const response = cachedJson({ ok: true });
    expect(response.headers.get("cache-control")).toBe("public, max-age=30, stale-while-revalidate=120");
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
  });

  it("parses event cursors safely", () => {
    expect(parseEventCursor("2026-06-29T12:00:00.000Z|event-1")).toEqual({
      occurredAt: "2026-06-29T12:00:00.000Z",
      id: "event-1"
    });
    expect(parseEventCursor("bad|event-1")).toBeInstanceOf(Response);
    expect(parseEventCursor("2026-06-29T12:00:00.000Z|bad id")).toBeInstanceOf(Response);
  });

  it("requires a valid since timestamp for delta feeds", () => {
    expect(parseSinceIso("2026-06-29T12:00:00.000Z")).toBe("2026-06-29T12:00:00.000Z");
    expect(parseSinceIso(null)).toBeInstanceOf(Response);
    expect(parseSinceIso("not-a-date")).toBeInstanceOf(Response);
  });
});
