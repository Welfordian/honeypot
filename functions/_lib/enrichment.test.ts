import { describe, expect, it } from "vitest";
import {
  enrichmentFromRow,
  isEnrichablePublicIp,
  isValidIpAddress,
  needsEnrichment
} from "./enrichment";
import { parseIpinfoLiteRecord } from "./ipinfoMmdb";

describe("isValidIpAddress", () => {
  it("accepts public IPv4 and IPv6", () => {
    expect(isValidIpAddress("8.8.8.8")).toBe(true);
    expect(isValidIpAddress("2001:4860:4860::8888")).toBe(true);
  });

  it("rejects malformed addresses", () => {
    expect(isValidIpAddress("999.1.1.1")).toBe(false);
    expect(isValidIpAddress("not-an-ip")).toBe(false);
    expect(isValidIpAddress("")).toBe(false);
  });
});

describe("isEnrichablePublicIp", () => {
  it("skips RFC1918 and loopback ranges", () => {
    expect(isEnrichablePublicIp("10.0.0.1")).toBe(false);
    expect(isEnrichablePublicIp("172.16.0.1")).toBe(false);
    expect(isEnrichablePublicIp("192.168.1.1")).toBe(false);
    expect(isEnrichablePublicIp("127.0.0.1")).toBe(false);
    expect(isEnrichablePublicIp("::1")).toBe(false);
    expect(isEnrichablePublicIp("fe80::1")).toBe(false);
  });

  it("allows routable addresses", () => {
    expect(isEnrichablePublicIp("8.8.8.8")).toBe(true);
    expect(isEnrichablePublicIp("2001:4860:4860::8888")).toBe(true);
  });
});

describe("needsEnrichment", () => {
  it("is true only when all enrichment fields are missing", () => {
    expect(needsEnrichment({})).toBe(true);
    expect(needsEnrichment({ country_code: "US" })).toBe(false);
    expect(needsEnrichment({ asn: 15169 })).toBe(false);
    expect(needsEnrichment({ as_name: "Google LLC" })).toBe(false);
  });
});

describe("parseIpinfoLiteRecord", () => {
  it("maps IPinfo Lite fields to enrichment metadata", () => {
    expect(
      parseIpinfoLiteRecord({
        country_code: "us",
        asn: "AS15169",
        as_name: "Google LLC"
      })
    ).toEqual({
      country_code: "US",
      asn: 15169,
      as_name: "Google LLC"
    });
  });

  it("returns null for empty records", () => {
    expect(parseIpinfoLiteRecord({})).toBeNull();
    expect(parseIpinfoLiteRecord(null)).toBeNull();
  });
});

describe("enrichmentFromRow", () => {
  it("normalizes nullable database fields", () => {
    expect(enrichmentFromRow({ country_code: "DE", asn: 3320, as_name: "DTAG" })).toEqual({
      country_code: "DE",
      asn: 3320,
      as_name: "DTAG"
    });
  });
});
