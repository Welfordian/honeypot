import { BookOpen } from "lucide-react";
import { PageHeader } from "@/components/layout/page-header";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow
} from "@/components/ui/table";
import { CONFIDENCE_REASONS } from "@/types/api";

const PRODUCTION_ORIGIN = "https://dashboard.example.com";
const BASE = typeof window === "undefined" ? PRODUCTION_ORIGIN : window.location.origin;
const WS_BASE = BASE.replace(/^http/, "ws");

type HttpMethod = "GET" | "WS";

interface QueryParam {
  name: string;
  type: string;
  default?: string;
  description: string;
}

interface EndpointDoc {
  method: HttpMethod;
  path: string;
  description: string;
  params?: QueryParam[];
  response: string;
  cache?: string;
  example: string;
}

interface Section {
  id: string;
  title: string;
  endpoints: EndpointDoc[];
  notes?: string;
}

const CACHED = "public, max-age=30, stale-while-revalidate=120";
const NO_STORE = "no-store";

const sections: Section[] = [
  {
    id: "overview",
    title: "Overview",
    endpoints: [
      {
        method: "GET",
        path: "/api/analytics/overview",
        description: "Dashboard summary: totals, hourly timeline, top IPs/protocols/traps/severities, and sensor heartbeats.",
        params: [
          { name: "sinceHours", type: "integer", default: "24", description: "Lookback window (1–720 hours)." }
        ],
        response: "{ totals, timeline[], topIps[], topProtocols[], topTraps[], topSeverities[], sensors[] }",
        cache: "public, max-age=10",
        example: `${BASE}/api/analytics/overview?sinceHours=48`
      },
      {
        method: "GET",
        path: "/api/live",
        description: "Polling fallback for recent events when the WebSocket stream is unavailable.",
        params: [{ name: "limit", type: "integer", default: "100", description: "Max events (1–200)." }],
        response: "{ events: EventRow[], polled_at: ISO8601 }",
        cache: NO_STORE,
        example: "/api/live?limit=50"
      }
    ]
  },
  {
    id: "events",
    title: "Events & Search",
    endpoints: [
      {
        method: "GET",
        path: "/api/v1/events",
        description: "Filtered, cursor-paginated event search. Legacy alias: /api/events.",
        params: [
          { name: "ip", type: "string", description: "Filter by source IP (IPv4/IPv6)." },
          { name: "eventType", type: "token", description: "Match protocol, trap, or event_kind." },
          { name: "eventKind", type: "token", description: "Exact event_kind filter." },
          { name: "destinationPort", type: "integer", description: "Destination port (0–65535)." },
          { name: "aggregate", type: "boolean", description: '"true" or "false" for is_aggregate.' },
          { name: "sinceHours", type: "integer", default: "24", description: "Lookback window (1–720 hours)." },
          { name: "minConfidence", type: "integer", description: "Minimum confidence score (0–100)." },
          { name: "hasCredentials", type: "boolean", description: '"true" for credential-attempt events.' },
          { name: "tag", type: "token", description: "Filter by tag value." },
          {
            name: "confidenceReason",
            type: "token",
            description: `Confidence reason (${CONFIDENCE_REASONS.slice(0, 4).join(", ")}, …).`
          },
          { name: "payloadHash", type: "sha256", description: "Filter by payload SHA-256." },
          { name: "trap", type: "token", description: "Filter by trap name." },
          { name: "userAgent", type: "string", description: "Substring match on HTTP user agent (max 120 chars)." },
          { name: "httpPath", type: "string", description: "Substring match on HTTP request path (max 240 chars)." },
          { name: "cursor", type: "string", description: "Pagination cursor: occurred_at|id from next_cursor." },
          { name: "limit", type: "integer", default: "100", description: "Page size (1–500)." }
        ],
        response: "{ events: EventRow[], next_cursor: string | null }",
        cache: CACHED,
        example: `${BASE}/api/v1/events?ip=203.0.113.10&eventType=http&sinceHours=24&limit=50`
      }
    ]
  },
  {
    id: "intel",
    title: "Intelligence",
    endpoints: [
      {
        method: "GET",
        path: "/api/v1/intel/overview",
        description: "Threat intel aggregates: top attackers, confidence reasons, tags, credential attempts, campaigns.",
        params: [
          { name: "sinceHours", type: "integer", default: "24", description: "Lookback window (1–720 hours)." }
        ],
        response:
          "{ topAttackers[], topConfidenceReasons[], topTags[], credentialAttempts, highConfidenceIps, campaigns[] }",
        cache: CACHED,
        example: "/api/v1/intel/overview?sinceHours=72"
      },
      {
        method: "GET",
        path: "/api/v1/intel/techniques",
        description:
          "MITRE ATT&CK techniques observed in honeypot events, ranked by count with example events and source IPs.",
        params: [
          { name: "sinceHours", type: "integer", default: "24", description: "Lookback window (1–720 hours)." }
        ],
        response: "{ sinceHours, techniques[] } where each technique has id, name, tactic, url, count, example_events[], example_ips[]",
        cache: CACHED,
        example: "/api/v1/intel/techniques?sinceHours=24"
      },
      {
        method: "GET",
        path: "/api/v1/intel/http",
        description:
          "HTTP attack surface: top paths, user agents, exploit probe trends, and credential probe paths.",
        params: [
          { name: "sinceHours", type: "integer", default: "24", description: "Lookback window (1–720 hours)." }
        ],
        response: "{ topPaths[], topUserAgents[], probeTrends[], credentialPaths[] }",
        cache: CACHED,
        example: "/api/v1/intel/http?sinceHours=24"
      },
      {
        method: "GET",
        path: "/api/v1/intel/actors",
        description:
          "Top source IPs with trap sequences, protocols, tags, related payloads, and sibling IPs sharing traps and user-agent prefixes.",
        params: [
          { name: "sinceHours", type: "integer", default: "168", description: "Lookback window (1–720 hours)." },
          { name: "limit", type: "integer", default: "20", description: "Max actors (1–50)." }
        ],
        response: "{ actors[] } with actor_id, source_ip, event_count, confidence, trap_sequence[], protocols[], tags[], related_payloads[], related_ips[]",
        cache: CACHED,
        example: "/api/v1/intel/actors?sinceHours=168&limit=20"
      },
      {
        method: "GET",
        path: "/api/v1/intel/campaigns",
        description:
          "Payload-hash campaigns and behavioral campaigns grouped by shared trap fingerprints across IPs.",
        params: [
          { name: "sinceHours", type: "integer", default: "168", description: "Lookback window (1–720 hours)." }
        ],
        response: "{ payload_campaigns[], behavioral_campaigns[] }",
        cache: CACHED,
        example: "/api/v1/intel/campaigns?sinceHours=168"
      }
    ]
  },
  {
    id: "network",
    title: "Network",
    endpoints: [
      {
        method: "GET",
        path: "/api/v1/network",
        description: "Network-layer telemetry: packets, bytes, ports, TCP flags, banner IPs, PCAP chunk stats.",
        params: [
          { name: "sinceHours", type: "integer", default: "24", description: "Lookback window (1–720 hours)." }
        ],
        response: "{ totals, timeline[], topPorts[], topProtocols[], tcpFlags[], eventKinds[], topBannerIps[], pcap }",
        cache: CACHED,
        example: `${BASE}/api/v1/network?sinceHours=24`
      }
    ]
  },
  {
    id: "ips",
    title: "IPs",
    endpoints: [
      {
        method: "GET",
        path: "/api/v1/ips",
        description: "Ranked IP profiles with confidence scores. Legacy alias: /api/ips.",
        params: [
          { name: "limit", type: "integer", default: "100", description: "Page size (1–500)." },
          { name: "offset", type: "integer", default: "0", description: "Offset for pagination; use next_offset." },
          {
            name: "enrichMissing",
            type: "integer",
            description:
              "If set (1–25), enrich up to N list rows missing country/ASN via the IPinfo Lite MMDB in R2."
          }
        ],
        response: "{ ips: IpProfile[], next_offset: number | null }",
        cache: CACHED,
        example: "/api/v1/ips?limit=25&offset=0"
      },
      {
        method: "GET",
        path: "/api/v1/ips/:ip",
        description: "Single IP profile with cursor-paginated events. Legacy alias: /api/ips/:ip.",
        params: [
          { name: "limit", type: "integer", default: "100", description: "Event page size (1–250)." },
          { name: "cursor", type: "string", description: "Pagination cursor from next_cursor." },
          {
            name: "enrich",
            type: "boolean",
            description:
              '"true" to look up missing country/ASN fields on demand via the IPinfo Lite MMDB in R2.'
          },
          {
            name: "reputation",
            type: "boolean",
            description: '"true" to include cached GreyNoise reputation in the response.'
          }
        ],
        response: "{ profile: IpProfile, events: EventRow[], next_cursor: string | null, reputation?: ReputationSummary }",
        cache: CACHED,
        example: `${BASE}/api/v1/ips/203.0.113.10?limit=25`
      },
      {
        method: "GET",
        path: "/api/v1/ips/:ip/timeline",
        description: "Hourly event counts for a single IP.",
        params: [
          { name: "sinceHours", type: "integer", default: "24", description: "Lookback window (1–720 hours)." }
        ],
        response: "{ timeline: [{ bucket, count }] }",
        cache: CACHED,
        example: "/api/v1/ips/203.0.113.10/timeline?sinceHours=168"
      }
    ]
  },
  {
    id: "payloads",
    title: "Payloads",
    endpoints: [
      {
        method: "GET",
        path: "/api/v1/payloads",
        description: "Payload catalog with redacted previews. Legacy alias: /api/payloads.",
        params: [
          { name: "limit", type: "integer", default: "100", description: "Page size (1–500)." },
          { name: "offset", type: "integer", default: "0", description: "Offset for pagination." }
        ],
        response: "{ payloads: PayloadRow[], next_offset: number | null }",
        cache: CACHED,
        example: "/api/v1/payloads?limit=20"
      },
      {
        method: "GET",
        path: "/api/v1/payloads/:sha256",
        description: "Payload detail with related IPs, dimensions, and events.",
        params: [
          { name: "limit", type: "integer", default: "100", description: "Event page size (1–250)." },
          { name: "cursor", type: "string", description: "Pagination cursor from next_cursor." }
        ],
        response:
          "{ payload, related_ips[], protocols[], traps[], events: EventRow[], next_cursor: string | null }",
        cache: CACHED,
        example: `${BASE}/api/v1/payloads/abc123…?limit=25`
      },
      {
        method: "GET",
        path: "/api/v1/payloads/:sha256/timeline",
        description: "Hourly event counts for a payload hash.",
        params: [
          { name: "sinceHours", type: "integer", default: "24", description: "Lookback window (1–720 hours)." }
        ],
        response: "{ timeline: [{ bucket, count }] }",
        cache: CACHED,
        example: "/api/v1/payloads/abc123…/timeline"
      }
    ]
  },
  {
    id: "reputation",
    title: "External Reputation",
    endpoints: [
      {
        method: "GET",
        path: "/api/v1/reputation/ips/:ip",
        description:
          "GreyNoise Community classification for a source IP. Results are cached in D1 for 24 hours.",
        response: "{ ip: string, reputation: ReputationSummary }",
        cache: NO_STORE,
        example: `${BASE}/api/v1/reputation/ips/203.0.113.10`
      },
      {
        method: "GET",
        path: "/api/v1/reputation/payloads/:sha256",
        description:
          "VirusTotal last-analysis stats for a payload SHA-256. Results are cached in D1 for 24 hours.",
        response: "{ sha256: string, reputation: ReputationSummary }",
        cache: NO_STORE,
        example: `${BASE}/api/v1/reputation/payloads/${"a".repeat(64)}`
      }
    ],
    notes:
      "Requires GREYNOISE_API_KEY and VIRUSTOTAL_API_KEY Wrangler secrets. When keys are unset, endpoints return empty provider objects without error. Responses use no-store so CDN edges do not cache reputation overlays."
  },
  {
    id: "hunts",
    title: "Hunts",
    endpoints: [
      {
        method: "GET",
        path: "/api/v1/hunts",
        description: "Public list of enabled hunt rules (name, confidence threshold, trap/protocol/tag filters).",
        response: "{ hunts[] }",
        cache: CACHED,
        example: "/api/v1/hunts"
      },
      {
        method: "GET",
        path: "/api/v1/admin/hunts",
        description:
          "Indexer-proxied admin API for hunt rules. Requires x-indexer-token matching INDEXER_ADMIN_TOKEN.",
        response: "{ hunt_rules[] }",
        cache: NO_STORE,
        example: "/api/v1/admin/hunts"
      },
      {
        method: "GET",
        path: "/api/v1/admin/hunts?webhooks=1",
        description: "Indexer-proxied admin API for webhook subscriptions tied to hunt rules.",
        response: "{ webhook_subscriptions[] }",
        cache: NO_STORE,
        example: "/api/v1/admin/hunts?webhooks=1"
      }
    ],
    notes:
      "POST/DELETE on the admin endpoints create, update, or remove hunt rules and webhooks. Hunt matches are delivered by the indexer worker to subscribed webhook URLs."
  },
  {
    id: "ops",
    title: "Ops",
    endpoints: [
      {
        method: "GET",
        path: "/api/v1/ops/status",
        description: "Operational health: sensor status, ingest timestamps, PCAP capture stats, 24h totals.",
        response: "{ sensors[], ingest, capture, totals24h }",
        cache: CACHED,
        example: "/api/v1/ops/status"
      },
      {
        method: "GET",
        path: "/api/traps/health",
        description: "Sensor heartbeat list (legacy endpoint; prefer /api/v1/ops/status).",
        response: "{ sensors: [{ sensor_id, last_seen, last_protocol, last_trap, event_count }] }",
        cache: NO_STORE,
        example: `${BASE}/api/traps/health`
      }
    ]
  },
  {
    id: "analytics",
    title: "Analytics & Feeds",
    endpoints: [
      {
        method: "GET",
        path: "/api/v1/analytics/rollups",
        description: "Pre-aggregated time-series rollups from the indexer (analytics_rollups table).",
        params: [
          { name: "sinceHours", type: "integer", default: "168", description: "Lookback window (1–720 hours)." },
          { name: "bucketWidth", type: "enum", default: "hour", description: "hour or day bucket size." },
          {
            name: "dimension",
            type: "enum",
            default: "protocol",
            description: "protocol, trap, event_kind, severity, destination_port, or tcp_flags."
          }
        ],
        response: "{ dimension, bucketWidth, sinceHours, series: [{ key, points: [{ bucket, count, unique_ips }] }] }",
        cache: CACHED,
        example: `${BASE}/api/v1/analytics/rollups?sinceHours=168&bucketWidth=hour&dimension=protocol`
      },
      {
        method: "GET",
        path: "/api/v1/analytics/compare",
        description: "Compare event counts for a tag, confidence reason, or trap across two lookback windows.",
        params: [
          { name: "dimension", type: "enum", default: "tag", description: "tag, confidenceReason, or trap." },
          { name: "key", type: "token", description: "Tag value, confidence reason, or trap name." },
          { name: "hoursA", type: "integer", default: "24", description: "Shorter window (1–720 hours)." },
          { name: "hoursB", type: "integer", default: "168", description: "Longer window (1–720 hours)." }
        ],
        response: "{ dimension, key, windowA: { hours, count }, windowB: { hours, count } }",
        cache: CACHED,
        example: `${BASE}/api/v1/analytics/compare?dimension=tag&key=login&hoursA=24&hoursB=168`
      },
      {
        method: "GET",
        path: "/api/v1/feeds/search-export.json",
        description: "Bulk JSON download of the current event search (same filters as /api/v1/events, up to 5000 rows).",
        params: [
          { name: "ip", type: "string", description: "Filter by source IP." },
          { name: "eventType", type: "token", description: "Match protocol, trap, or event_kind." },
          { name: "eventKind", type: "token", description: "Exact event_kind filter." },
          { name: "destinationPort", type: "integer", description: "Destination port (0–65535)." },
          { name: "aggregate", type: "boolean", description: '"true" or "false" for is_aggregate.' },
          { name: "sinceHours", type: "integer", default: "24", description: "Lookback window (1–720 hours)." },
          { name: "minConfidence", type: "integer", description: "Minimum confidence score (0–100)." },
          { name: "hasCredentials", type: "boolean", description: '"true" for credential-attempt events.' },
          { name: "tag", type: "token", description: "Filter by tag value." },
          { name: "confidenceReason", type: "token", description: "Filter by confidence reason." },
          { name: "payloadHash", type: "sha256", description: "Filter by payload SHA-256." }
        ],
        response: 'attachment: { exported_at, limit: 5000, count, events: EventRow[] }',
        cache: NO_STORE,
        example: `${BASE}/api/v1/feeds/search-export.json?tag=login&sinceHours=168`
      },
      {
        method: "GET",
        path: "/api/v1/feeds/new-ips.json",
        description: "IP profiles whose first_seen is on or after the given ISO8601 timestamp.",
        params: [
          { name: "since", type: "ISO8601", description: "Required. Return IPs first seen at or after this time." }
        ],
        response: "{ since, count, ips: IpProfile[] }",
        cache: CACHED,
        example: `${BASE}/api/v1/feeds/new-ips.json?since=2026-06-01T00:00:00.000Z`
      }
    ]
  },
  {
    id: "exports",
    title: "Exports & Feeds",
    endpoints: [
      {
        method: "GET",
        path: "/api/exports/blocklist.txt",
        description: "Plain-text list of source IPs meeting a minimum score threshold.",
        params: [
          { name: "minScore", type: "integer", default: "6", description: "Minimum IP score (1–10)." },
          { name: "limit", type: "integer", default: "10000", description: "Max lines (up to 10000)." }
        ],
        response: "text/plain — one IP per line",
        cache: NO_STORE,
        example: "/api/exports/blocklist.txt?minScore=8"
      },
      {
        method: "GET",
        path: "/api/exports/network.csv",
        description: "CSV export of network-attempt and tcp-banner events.",
        params: [
          { name: "sinceHours", type: "integer", default: "24", description: "Lookback window (1–720 hours)." },
          { name: "limit", type: "integer", default: "5000", description: "Max rows (up to 10000)." }
        ],
        response: "text/csv — occurred_at, source_ip, ports, protocol, event_kind, trap, packet/byte counts, tcp_flags, is_aggregate, pcap_sha256",
        cache: NO_STORE,
        example: `${BASE}/api/exports/network.csv?sinceHours=48`
      },
      {
        method: "GET",
        path: "/api/v1/feeds/events.ndjson",
        description: "Machine-consumable event stream as newline-delimited JSON (one EventRow per line).",
        params: [
          { name: "ip", type: "string", description: "Filter by source IP (IPv4/IPv6)." },
          { name: "eventType", type: "token", description: "Match protocol, trap, or event_kind." },
          { name: "eventKind", type: "token", description: "Exact event_kind filter." },
          { name: "destinationPort", type: "integer", description: "Destination port (0–65535)." },
          { name: "aggregate", type: "boolean", description: '"true" or "false" for is_aggregate.' },
          { name: "sinceHours", type: "integer", default: "24", description: "Lookback window (1–720 hours)." },
          { name: "minConfidence", type: "integer", description: "Minimum confidence score (0–100)." },
          { name: "hasCredentials", type: "boolean", description: '"true" for credential-attempt events.' },
          { name: "tag", type: "token", description: "Filter by tag value." },
          {
            name: "confidenceReason",
            type: "token",
            description: `Confidence reason (${CONFIDENCE_REASONS.slice(0, 4).join(", ")}, …).`
          },
          { name: "payloadHash", type: "sha256", description: "Filter by payload SHA-256." },
          { name: "limit", type: "integer", default: "1000", description: "Max lines (up to 5000)." }
        ],
        response: "application/x-ndjson — one EventRow JSON object per line",
        cache: NO_STORE,
        example: `${BASE}/api/v1/feeds/events.ndjson?minConfidence=70&sinceHours=48&limit=2000`
      },
      {
        method: "GET",
        path: "/api/v1/feeds/ips.json",
        description: "JSON array of IP indicators with confidence metadata for SIEM/TIP ingestion.",
        params: [
          { name: "minConfidence", type: "integer", description: "Minimum confidence score (0–100)." },
          { name: "since", type: "ISO8601", description: "Only IPs first seen at or after this timestamp." },
          { name: "limit", type: "integer", default: "100", description: "Max IOCs (up to 5000)." },
          { name: "offset", type: "integer", default: "0", description: "Pagination offset." }
        ],
        response:
          "[{ source_ip, first_seen, last_seen, confidence, score, confidence_reasons[], unique_traps[], protocols[], country_code?, asn?, as_name? }]",
        cache: CACHED,
        example: "/api/v1/feeds/ips.json?minConfidence=60&limit=250"
      },
      {
        method: "GET",
        path: "/api/v1/feeds/ips.ndjson",
        description: "Same IP IOC records as ips.json, one JSON object per line.",
        params: [
          { name: "minConfidence", type: "integer", description: "Minimum confidence score (0–100)." },
          { name: "since", type: "ISO8601", description: "Only IPs first seen at or after this timestamp." },
          { name: "limit", type: "integer", default: "100", description: "Max IOCs (up to 5000)." },
          { name: "offset", type: "integer", default: "0", description: "Pagination offset." }
        ],
        response: "application/x-ndjson — one IpIoc JSON object per line",
        cache: NO_STORE,
        example: "/api/v1/feeds/ips.ndjson?minConfidence=80&limit=1000"
      },
      {
        method: "GET",
        path: "/api/v1/feeds/ips.stix.json",
        description: "STIX 2.1 bundle of ipv4-addr/ipv6-addr indicators with confidence labels and valid_from/valid_until.",
        params: [
          { name: "minConfidence", type: "integer", description: "Minimum confidence score (0–100)." },
          { name: "since", type: "ISO8601", description: "Only IPs first seen at or after this timestamp." },
          { name: "limit", type: "integer", default: "100", description: "Max indicators (up to 5000)." },
          { name: "offset", type: "integer", default: "0", description: "Pagination offset." }
        ],
        response: "{ type: bundle, spec_version: 2.1, objects: [indicator, …] }",
        cache: CACHED,
        example: `${BASE}/api/v1/feeds/ips.stix.json?minConfidence=70&limit=500`
      },
      {
        method: "GET",
        path: "/api/v1/feeds/artifacts.json",
        description:
          "JSON array of artifact indicators: payload SHA-256 hashes, HTTP paths, and extracted domains/URLs.",
        params: [
          { name: "minConfidence", type: "integer", description: "Minimum confidence score (0–100)." },
          { name: "since", type: "ISO8601", description: "Only artifacts first seen at or after this timestamp." },
          { name: "limit", type: "integer", default: "100", description: "Max IOCs (up to 5000)." },
          { name: "offset", type: "integer", default: "0", description: "Pagination offset." }
        ],
        response:
          "[{ type: file|url|domain, value, first_seen, last_seen, confidence, event_count, unique_ips, source_ips?, size_bytes?, mime_guess? }]",
        cache: CACHED,
        example: "/api/v1/feeds/artifacts.json?minConfidence=60&limit=250"
      },
      {
        method: "GET",
        path: "/api/v1/feeds/artifacts.ndjson",
        description: "Same artifact IOC records as artifacts.json, one JSON object per line.",
        params: [
          { name: "minConfidence", type: "integer", description: "Minimum confidence score (0–100)." },
          { name: "since", type: "ISO8601", description: "Only artifacts first seen at or after this timestamp." },
          { name: "limit", type: "integer", default: "100", description: "Max IOCs (up to 5000)." },
          { name: "offset", type: "integer", default: "0", description: "Pagination offset." }
        ],
        response: "application/x-ndjson — one ArtifactIoc JSON object per line",
        cache: NO_STORE,
        example: "/api/v1/feeds/artifacts.ndjson?minConfidence=80&limit=1000"
      },
      {
        method: "GET",
        path: "/api/v1/feeds/artifacts.stix.json",
        description:
          "STIX 2.1 bundle with IP indicators, file/url/domain artifact indicators, and related-to relationships to observed source IPs.",
        params: [
          { name: "minConfidence", type: "integer", description: "Minimum confidence score (0–100)." },
          { name: "since", type: "ISO8601", description: "Only IOCs first seen at or after this timestamp." },
          { name: "limit", type: "integer", default: "100", description: "Max indicators per feed (up to 5000)." },
          { name: "offset", type: "integer", default: "0", description: "Pagination offset." }
        ],
        response: "{ type: bundle, spec_version: 2.1, objects: [indicator, relationship, …] }",
        cache: CACHED,
        example: `${BASE}/api/v1/feeds/artifacts.stix.json?minConfidence=70&limit=500`
      },
      {
        method: "GET",
        path: "/api/v1/feeds/new.json",
        description:
          "Delta feed of newly observed high-confidence IPs (first_seen) and events (occurred_at) since a timestamp.",
        params: [
          { name: "since", type: "ISO8601", description: "Required. Return records at or after this timestamp." },
          {
            name: "minConfidence",
            type: "integer",
            default: "50",
            description: "Minimum confidence score (0–100)."
          },
          { name: "limit", type: "integer", default: "500", description: "Max IPs and max events each (up to 5000)." }
        ],
        response: "{ since, min_confidence, ips: IpIoc[], events: EventRow[] }",
        cache: CACHED,
        example: `${BASE}/api/v1/feeds/new.json?since=2026-06-29T00:00:00.000Z`
      }
    ]
  },
  {
    id: "websocket",
    title: "WebSocket",
    endpoints: [
      {
        method: "WS",
        path: "/api/live-stream",
        description:
          "Real-time event stream via Cloudflare Durable Object. Upgrade required; returns 426 without WebSocket.",
        response:
          'Messages: { type: "connected", connections, at } on join; { type: "event", event: EventRow, at } per event; send "ping" → { type: "pong" }',
        cache: NO_STORE,
        example: `${WS_BASE}/api/live-stream`
      }
    ],
    notes:
      "The live stream runs on a separate Worker bound to the same hostname. Events match the public EventRow shape."
  },
  {
    id: "researcher",
    title: "Researcher Access",
    notes:
      "Authenticated endpoints for trusted researchers. Requires RESEARCHER_API_TOKEN on the server. Send Authorization: Bearer <token> or x-researcher-token. All access is audit-logged. Responses use no-store caching.",
    endpoints: [
      {
        method: "GET",
        path: "/api/v1/researcher/pcap/:sha256",
        description:
          "Download a PCAP chunk by SHA-256 when the capture is still within retention. Returns application/vnd.tcpdump (gzip-encoded when stored compressed).",
        response: "application/vnd.tcpdump attachment, or { error: not_found }",
        cache: NO_STORE,
        example: `${BASE}/api/v1/researcher/pcap/abc…def`
      },
      {
        method: "GET",
        path: "/api/v1/researcher/payloads/:sha256",
        description:
          "Expanded payload view for a deduplicated hash. Returns full redacted payload bytes from R2 when retained, otherwise the longest stored preview with note: full bytes not retained.",
        response:
          '{ source: "r2", payload: { text?, base64?, mime_guess? } } | { preview, note: "full bytes not retained" }',
        cache: NO_STORE,
        example: `${BASE}/api/v1/researcher/payloads/abc…def`
      },
      {
        method: "GET",
        path: "/api/v1/researcher/events/:id/payload",
        description:
          "Redacted-safe payload for a single event. Prefers the indexed R2 object when available; falls back to the D1 preview.",
        response:
          '{ event_id, payload_sha256, payload_size, source: "r2"|"preview", payload|preview, note? }',
        cache: NO_STORE,
        example: `${BASE}/api/v1/researcher/events/event-uuid/payload`
      }
    ]
  }
];

const METHOD_VARIANT: Record<HttpMethod, "default" | "secondary" | "outline"> = {
  GET: "default",
  WS: "secondary"
};

function MethodBadge({ method }: { method: HttpMethod }) {
  return (
    <Badge variant={METHOD_VARIANT[method]} className="font-mono text-[10px] uppercase">
      {method}
    </Badge>
  );
}

function EndpointCard({ endpoint }: { endpoint: EndpointDoc }) {
  return (
    <div className="space-y-3 border-b border-border pb-4 last:border-0 last:pb-0">
      <div className="flex flex-wrap items-center gap-2">
        <MethodBadge method={endpoint.method} />
        <code className="break-all font-mono text-sm text-primary">{endpoint.path}</code>
      </div>
      <p className="text-sm text-muted-foreground">{endpoint.description}</p>

      {endpoint.params && endpoint.params.length > 0 && (
        <div className="overflow-x-auto rounded-md border border-border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-[120px]">Parameter</TableHead>
                <TableHead className="w-[80px]">Type</TableHead>
                <TableHead className="w-[80px]">Default</TableHead>
                <TableHead>Description</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {endpoint.params.map((param) => (
                <TableRow key={param.name}>
                  <TableCell className="font-mono text-xs">{param.name}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">{param.type}</TableCell>
                  <TableCell className="font-mono text-xs text-muted-foreground">
                    {param.default ?? "—"}
                  </TableCell>
                  <TableCell className="text-xs">{param.description}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      <div className="grid gap-2 text-xs sm:grid-cols-2">
        <div>
          <span className="text-muted-foreground">Response: </span>
          <code className="font-mono text-foreground/90">{endpoint.response}</code>
        </div>
        {endpoint.cache && (
          <div>
            <span className="text-muted-foreground">Cache-Control: </span>
            <code className="font-mono text-foreground/90">{endpoint.cache}</code>
          </div>
        )}
      </div>

      <div className="rounded-md bg-muted/40 px-3 py-2">
        <span className="text-xs text-muted-foreground">Example: </span>
        <code className="break-all font-mono text-xs text-primary">{endpoint.example}</code>
      </div>
    </div>
  );
}

export function DocsPage() {
  return (
    <>
      <PageHeader
        title="API Reference"
        subtitle="Public read-only endpoints served by Cloudflare Pages Functions on the dashboard hostname."
      />
      <div className="flex flex-col gap-6 p-4 sm:p-6">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <BookOpen className="h-4 w-4 text-primary" />
              Public data posture
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-sm text-muted-foreground">
            <p>
              All public endpoints return sanitized D1 metadata only. Raw R2 objects, full PCAP bytes,
              signed URLs, passwords, authorization tokens, cookies, and full payload bodies are never
              exposed without researcher authentication.
            </p>
            <p>
              Events include redacted credential flags (<code className="font-mono text-xs">has_credentials</code>),
              payload hash/size/preview, PCAP availability markers, and packet metadata — not executable content.
            </p>
            <p>
              See{" "}
              <a
                href="https://github.com/Welfordian/honeypot/blob/main/docs/safety.md"
                target="_blank"
                rel="noopener noreferrer"
                className="text-primary underline-offset-4 hover:underline"
              >
                docs/safety.md
              </a>{" "}
              for the full safety model.
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Caching &amp; limits</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-sm text-muted-foreground">
            <p>
              Most <code className="font-mono text-xs">/api/v1/*</code> JSON endpoints use{" "}
              <code className="font-mono text-xs">{CACHED}</code> via <code className="font-mono text-xs">cachedJson</code>.
              Polling (<code className="font-mono text-xs">/api/live</code>), NDJSON feeds, legacy text/CSV exports, and the WebSocket stream use{" "}
              <code className="font-mono text-xs">no-store</code>.
            </p>
            <p>
              No explicit rate limiting is configured. Respect cache headers and use reasonable{" "}
              <code className="font-mono text-xs">limit</code> values. Invalid query parameters return HTTP 400.
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Data sources</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-sm text-muted-foreground">
            <p>
              Country and ASN enrichment uses the{" "}
              <a
                href="https://ipinfo.io/"
                target="_blank"
                rel="noopener noreferrer"
                className="text-primary underline-offset-4 hover:underline"
              >
                IPinfo Lite
              </a>{" "}
              MMDB (CC BY-SA 4.0). The database is stored in R2 at{" "}
              <code className="font-mono text-xs">geo/ipinfo_lite.mmdb</code> and refreshed daily by the
              indexer cron.
            </p>
            <p>
              IP profiles include <code className="font-mono text-xs">country_code</code>,{" "}
              <code className="font-mono text-xs">asn</code>, and{" "}
              <code className="font-mono text-xs">as_name</code> when enrichment is available. Pass{" "}
              <code className="font-mono text-xs">enrich=true</code> on{" "}
              <code className="font-mono text-xs">GET /api/v1/ips/:ip</code> to fill missing fields on
              demand.
            </p>
            <p>
              External reputation overlays use{" "}
              <a
                href="https://www.greynoise.io/"
                target="_blank"
                rel="noopener noreferrer"
                className="text-primary underline-offset-4 hover:underline"
              >
                GreyNoise Community
              </a>{" "}
              for IPs and{" "}
              <a
                href="https://www.virustotal.com/"
                target="_blank"
                rel="noopener noreferrer"
                className="text-primary underline-offset-4 hover:underline"
              >
                VirusTotal
              </a>{" "}
              for payload hashes. Configure Wrangler secrets on the Pages project:
            </p>
            <pre className="overflow-x-auto rounded-md bg-muted/40 p-3 font-mono text-xs leading-relaxed text-foreground/90">
{`npx wrangler pages secret put GREYNOISE_API_KEY --project-name honeypot-sec
npx wrangler pages secret put VIRUSTOTAL_API_KEY --project-name honeypot-sec`}
            </pre>
            <p>
              Cached lookups are stored in D1 (<code className="font-mono text-xs">ip_reputation_cache</code>
              ) with a 24-hour TTL. Reputation endpoints and <code className="font-mono text-xs">GET /api/v1/ips/:ip?reputation=true</code>{" "}
              use <code className="font-mono text-xs">no-store</code> so CDN edges do not cache provider overlays.
            </p>
          </CardContent>
        </Card>

        <nav aria-label="API sections" className="flex flex-wrap gap-2">
          {sections.map((section) => (
            <a
              key={section.id}
              href={`#${section.id}`}
              className="rounded-md border border-border px-2.5 py-1 font-mono text-xs text-muted-foreground transition-colors hover:border-primary/40 hover:text-primary"
            >
              {section.title}
            </a>
          ))}
        </nav>

        {sections.map((section) => (
          <Card key={section.id} id={section.id}>
            <CardHeader>
              <CardTitle className="text-base">{section.title}</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {section.endpoints.map((endpoint) => (
                <EndpointCard key={endpoint.path} endpoint={endpoint} />
              ))}
              {section.notes && <p className="text-xs text-muted-foreground">{section.notes}</p>}
            </CardContent>
          </Card>
        ))}

        <Card>
          <CardHeader>
            <CardTitle className="text-base">EventRow shape</CardTitle>
          </CardHeader>
          <CardContent>
            <pre className="overflow-x-auto rounded-md bg-muted/40 p-3 font-mono text-xs leading-relaxed text-foreground/90">
{`{
  id, occurred_at, received_at, event_kind,
  source_ip, source_port?, destination_port?,
  protocol, trap, sensor_id,
  http_method?, http_path?, http_status?, user_agent?,
  credential_kind?, has_credentials: boolean,
  payload_sha256?, payload_size?, payload_preview?,
  packet_count, byte_count, tcp_flags?,
  is_aggregate, pcap_sha256?, pcap_available,
  severity, confidence, confidence_reasons[], tags[]
}`}
            </pre>
          </CardContent>
        </Card>
      </div>
    </>
  );
}
