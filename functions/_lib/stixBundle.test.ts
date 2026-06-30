import { describe, expect, it } from "vitest";
import { buildStixBundle, stixDeterministicId, stixIpPattern } from "./stixBundle";
import type { IpIoc } from "./ipIocs";

describe("STIX bundle builder", () => {
  const sample: IpIoc = {
    source_ip: "203.0.113.10",
    first_seen: "2026-06-29T10:00:00.000Z",
    last_seen: "2026-06-30T12:00:00.000Z",
    confidence: 85,
    score: 8,
    confidence_reasons: ["credential_attempt", "multi_trap"],
    unique_traps: ["env", "admin"],
    protocols: ["http"]
  };

  it("builds a STIX 2.1 bundle with ipv4 indicators", () => {
    const bundle = buildStixBundle([sample], "2026-06-30T15:00:00.000Z");

    expect(bundle.type).toBe("bundle");
    expect(bundle.spec_version).toBe("2.1");
    expect(bundle.id).toMatch(/^bundle--[0-9a-f-]{36}$/);
    expect(bundle.objects).toHaveLength(1);

    const indicator = bundle.objects[0]!;
    expect(indicator.type).toBe("indicator");
    expect(indicator.spec_version).toBe("2.1");
    expect(indicator.pattern).toBe("[ipv4-addr:value = '203.0.113.10']");
    expect(indicator.pattern_type).toBe("stix");
    expect(indicator.valid_from).toBe(sample.first_seen);
    expect(indicator.valid_until).toBe(sample.last_seen);
    expect(indicator.confidence).toBe(85);
    expect(indicator.labels).toEqual([
      "confidence:85",
      "reason:credential_attempt",
      "reason:multi_trap"
    ]);
  });

  it("uses ipv6 patterns for IPv6 addresses", () => {
    expect(stixIpPattern("2001:db8::1")).toBe("[ipv6-addr:value = '2001:db8::1']");
  });

  it("generates stable indicator ids per IP", () => {
    const first = stixDeterministicId("indicator", "203.0.113.10");
    const second = stixDeterministicId("indicator", "203.0.113.10");
    const other = stixDeterministicId("indicator", "198.51.100.4");

    expect(first).toBe(second);
    expect(first).not.toBe(other);
    expect(first).toMatch(/^indicator--[0-9a-f-]{36}$/);
  });
});
