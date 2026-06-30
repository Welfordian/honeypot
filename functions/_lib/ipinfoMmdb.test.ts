import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Buffer } from "buffer";
import { Reader } from "mmdb-lib";
import { describe, expect, it } from "vitest";
import { lookupIpinfoLite, parseIpinfoLiteRecord, type MmdbReader } from "./ipinfoMmdb";

const fixturePath = join(dirname(fileURLToPath(import.meta.url)), "fixtures", "ipinfo_lite_sample.mmdb");

describe("ipinfo lite sample mmdb", () => {
  const reader = new Reader(Buffer.from(readFileSync(fixturePath))) as MmdbReader;

  it("looks up a known sample IP", () => {
    const result = lookupIpinfoLite(reader, "1.1.1.1");
    expect(result).toEqual({
      country_code: "AU",
      asn: 13335,
      as_name: "Cloudflare, Inc."
    });
  });

  it("returns null for missing records", () => {
    expect(lookupIpinfoLite(reader, "127.0.0.1")).toBeNull();
  });

  it("parses ASN prefix case-insensitively", () => {
    expect(parseIpinfoLiteRecord({ asn: "as13335", country_code: "US", as_name: "Cloudflare" })).toEqual({
      country_code: "US",
      asn: 13335,
      as_name: "Cloudflare"
    });
  });
});
