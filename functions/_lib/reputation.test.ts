import { afterEach, describe, expect, it, vi } from "vitest";
import {
  fetchGreynoiseIp,
  fetchVirusTotalHash,
  getHashReputation,
  getIpReputation,
  type ReputationFetcher
} from "./reputation";

interface CacheRow {
  source_ip: string;
  provider: string;
  classification: string | null;
  tags_json: string;
  raw_json: string | null;
  fetched_at: string;
  expires_at: string;
}

function createMockDb(initial: CacheRow[] = []) {
  const rows = new Map<string, CacheRow>();

  for (const row of initial) {
    rows.set(`${row.source_ip}:${row.provider}`, row);
  }

  return {
    prepare(sql: string) {
      const isSelect = sql.includes("SELECT");
      const bindings: unknown[] = [];
      return {
        bind(...values: unknown[]) {
          bindings.push(...values);
          return this;
        },
        async first<T>(): Promise<T | null> {
          if (!isSelect) return null;
          const [sourceIp, provider] = bindings as [string, string];
          return (rows.get(`${sourceIp}:${provider}`) as T | undefined) ?? null;
        },
        async run() {
          if (!sql.includes("INSERT INTO ip_reputation_cache")) return { success: true };
          const [sourceIp, provider, classification, tagsJson, rawJson, fetchedAt, expiresAt] =
            bindings as [string, string, string | null, string, string, string, string];
          rows.set(`${sourceIp}:${provider}`, {
            source_ip: sourceIp,
            provider,
            classification,
            tags_json: tagsJson,
            raw_json: rawJson,
            fetched_at: fetchedAt,
            expires_at: expiresAt
          });
          return { success: true };
        }
      };
    }
  };
}

function mockFetcher(handlers: Record<string, () => Response | Promise<Response>>): ReputationFetcher {
  return vi.fn(async (input: RequestInfo | URL) => {
    const url = typeof input === "string" ? input : input.toString();
    const handler = Object.entries(handlers).find(([prefix]) => url.startsWith(prefix))?.[1];
    if (!handler) throw new Error(`Unexpected fetch: ${url}`);
    return handler();
  });
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("fetchGreynoiseIp", () => {
  it("maps GreyNoise community fields", async () => {
    const fetcher = mockFetcher({
      "https://api.greynoise.io/v3/community/": () =>
        new Response(
          JSON.stringify({
            classification: "malicious",
            name: "Mirai Scanner",
            tags: ["scanner", "mirai"]
          }),
          { status: 200 }
        )
    });

    await expect(fetchGreynoiseIp("203.0.113.10", "test-key", fetcher)).resolves.toEqual({
      classification: "malicious",
      name: "Mirai Scanner",
      tags: ["scanner", "mirai"]
    });
  });

  it("returns null on non-200 responses", async () => {
    const fetcher = mockFetcher({
      "https://api.greynoise.io/v3/community/": () => new Response("not found", { status: 404 })
    });

    await expect(fetchGreynoiseIp("203.0.113.10", "test-key", fetcher)).resolves.toBeNull();
  });
});

describe("fetchVirusTotalHash", () => {
  const sha256 = "a".repeat(64);

  it("maps VirusTotal analysis stats", async () => {
    const fetcher = mockFetcher({
      "https://www.virustotal.com/api/v3/files/": () =>
        new Response(
          JSON.stringify({
            data: {
              attributes: {
                last_analysis_stats: {
                  malicious: 12,
                  suspicious: 2,
                  harmless: 40,
                  undetected: 16
                }
              }
            }
          }),
          { status: 200 }
        )
    });

    await expect(fetchVirusTotalHash(sha256, "vt-key", fetcher)).resolves.toEqual({
      malicious: 12,
      suspicious: 2,
      harmless: 40,
      undetected: 16
    });
  });
});

describe("getIpReputation", () => {
  const ip = "203.0.113.10";
  const now = Date.parse("2026-06-30T12:00:00.000Z");

  it("returns cached GreyNoise data without refetching", async () => {
    vi.spyOn(Date, "now").mockReturnValue(now);
    const fetcher = mockFetcher({
      "https://api.greynoise.io/v3/community/": () => new Response("should not be called", { status: 500 })
    });
    const db = createMockDb([
      {
        source_ip: ip,
        provider: "greynoise",
        classification: "benign",
        tags_json: '["cdn"]',
        raw_json: JSON.stringify({ classification: "benign", name: "CDN", tags: ["cdn"] }),
        fetched_at: "2026-06-30T10:00:00.000Z",
        expires_at: "2026-07-01T10:00:00.000Z"
      }
    ]);

    await expect(getIpReputation(db as never, ip, { GREYNOISE_API_KEY: "key" }, fetcher)).resolves.toEqual({
      providers: {
        greynoise: {
          classification: "benign",
          name: "CDN",
          tags: ["cdn"]
        }
      }
    });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("fetches and stores GreyNoise data when cache is expired", async () => {
    vi.spyOn(Date, "now").mockReturnValue(now);
    const fetcher = mockFetcher({
      "https://api.greynoise.io/v3/community/": () =>
        new Response(
          JSON.stringify({
            classification: "malicious",
            name: "Scanner",
            tags: ["scanner"]
          }),
          { status: 200 }
        )
    });
    const db = createMockDb([
      {
        source_ip: ip,
        provider: "greynoise",
        classification: "unknown",
        tags_json: "[]",
        raw_json: null,
        fetched_at: "2026-06-28T10:00:00.000Z",
        expires_at: "2026-06-29T10:00:00.000Z"
      }
    ]);

    await expect(getIpReputation(db as never, ip, { GREYNOISE_API_KEY: "key" }, fetcher)).resolves.toEqual({
      providers: {
        greynoise: {
          classification: "malicious",
          name: "Scanner",
          tags: ["scanner"]
        }
      }
    });
    expect(fetcher).toHaveBeenCalledOnce();
  });

  it("returns empty providers when API key is missing", async () => {
    const fetcher = mockFetcher({});
    await expect(getIpReputation(createMockDb() as never, ip, {}, fetcher)).resolves.toEqual({
      providers: {}
    });
  });
});

describe("getHashReputation", () => {
  const sha256 = "b".repeat(64);
  const now = Date.parse("2026-06-30T12:00:00.000Z");

  it("fetches and caches VirusTotal stats", async () => {
    vi.spyOn(Date, "now").mockReturnValue(now);
    const fetcher = mockFetcher({
      "https://www.virustotal.com/api/v3/files/": () =>
        new Response(
          JSON.stringify({
            data: {
              attributes: {
                last_analysis_stats: {
                  malicious: 5,
                  suspicious: 1,
                  harmless: 30,
                  undetected: 10
                }
              }
            }
          }),
          { status: 200 }
        )
    });
    const db = createMockDb();

    await expect(
      getHashReputation(db as never, sha256, { VIRUSTOTAL_API_KEY: "vt-key" }, fetcher)
    ).resolves.toEqual({
      providers: {
        virustotal: {
          malicious: 5,
          suspicious: 1,
          harmless: 30,
          undetected: 10
        }
      }
    });

    const cached = await getHashReputation(db as never, sha256, { VIRUSTOTAL_API_KEY: "vt-key" }, fetcher);
    expect(cached).toEqual({
      providers: {
        virustotal: {
          malicious: 5,
          suspicious: 1,
          harmless: 30,
          undetected: 10
        }
      }
    });
    expect(fetcher).toHaveBeenCalledOnce();
  });
});
