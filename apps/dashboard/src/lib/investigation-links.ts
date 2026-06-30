import type { EventFilters } from "@/types/api";

export interface SearchUrlFilters {
  ip?: string;
  tag?: string;
  confidenceReason?: string;
  payloadHash?: string;
  trap?: string;
  eventType?: string;
  eventKind?: string;
  destinationPort?: string;
  minConfidence?: string;
  hasCredentials?: string;
  userAgent?: string;
  httpPath?: string;
  sinceHours?: string;
}

export function buildSearchUrl(filters: SearchUrlFilters): string {
  const params = new URLSearchParams();
  const entries: Array<[keyof SearchUrlFilters, string | undefined]> = [
    ["ip", filters.ip],
    ["tag", filters.tag],
    ["confidenceReason", filters.confidenceReason],
    ["payloadHash", filters.payloadHash],
    ["trap", filters.trap],
    ["eventType", filters.eventType],
    ["eventKind", filters.eventKind],
    ["destinationPort", filters.destinationPort],
    ["minConfidence", filters.minConfidence],
    ["hasCredentials", filters.hasCredentials],
    ["userAgent", filters.userAgent],
    ["httpPath", filters.httpPath],
    ["sinceHours", filters.sinceHours]
  ];

  for (const [key, value] of entries) {
    if (value) params.set(key, value);
  }

  const query = params.toString();
  return query ? `/search?${query}` : "/search";
}

export function filtersFromSearchParams(params: URLSearchParams): EventFilters {
  return {
    ip: params.get("ip") ?? "",
    eventType: params.get("eventType") ?? "",
    eventKind: params.get("eventKind") ?? "",
    destinationPort: params.get("destinationPort") ?? "",
    aggregate: params.get("aggregate") ?? "",
    sinceHours: params.get("sinceHours") ?? "24",
    tag: params.get("tag") ?? "",
    confidenceReason: params.get("confidenceReason") ?? "",
    minConfidence: params.get("minConfidence") ?? "",
    hasCredentials: params.get("hasCredentials") ?? "",
    payloadHash: params.get("payloadHash") ?? "",
    trap: params.get("trap") ?? "",
    userAgent: params.get("userAgent") ?? "",
    httpPath: params.get("httpPath") ?? ""
  };
}

export function searchParamsFromFilters(filters: EventFilters): URLSearchParams {
  const params = new URLSearchParams();
  const entries: Array<[keyof EventFilters, string]> = [
    ["ip", filters.ip],
    ["eventType", filters.eventType],
    ["eventKind", filters.eventKind],
    ["destinationPort", filters.destinationPort],
    ["aggregate", filters.aggregate],
    ["sinceHours", filters.sinceHours],
    ["tag", filters.tag],
    ["confidenceReason", filters.confidenceReason],
    ["minConfidence", filters.minConfidence],
    ["hasCredentials", filters.hasCredentials],
    ["payloadHash", filters.payloadHash],
    ["trap", filters.trap],
    ["userAgent", filters.userAgent],
    ["httpPath", filters.httpPath]
  ];

  for (const [key, value] of entries) {
    if (value) params.set(key, value);
  }

  return params;
}
