import { useInfiniteQuery, useQuery, useQueries } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { mergeByKey } from "@/lib/utils";
import type {
  CompareResponse,
  EventFilters,
  EventRow,
  HttpIntelOverview,
  IntelActor,
  IntelCampaigns,
  IntelOverview,
  IpDetail,
  IpProfile,
  NetworkOverview,
  NewIpsResponse,
  OpsStatus,
  Overview,
  PayloadDetail,
  PayloadRow,
  RollupsResponse,
  TimelinePoint
} from "@/types/api";

export function useOverview() {
  return useQuery({
    queryKey: ["overview"],
    queryFn: () => api.get<Overview>("/api/analytics/overview?sinceHours=24"),
    staleTime: 30_000
  });
}

export function buildEventParams(filters: EventFilters, cursor?: string | null): URLSearchParams {
  const params = new URLSearchParams({ limit: "100", sinceHours: filters.sinceHours });
  if (filters.ip) params.set("ip", filters.ip);
  if (filters.eventType) params.set("eventType", filters.eventType);
  if (filters.eventKind) params.set("eventKind", filters.eventKind);
  if (filters.destinationPort) params.set("destinationPort", filters.destinationPort);
  if (filters.aggregate) params.set("aggregate", filters.aggregate);
  if (filters.tag) params.set("tag", filters.tag);
  if (filters.confidenceReason) params.set("confidenceReason", filters.confidenceReason);
  if (filters.minConfidence) params.set("minConfidence", filters.minConfidence);
  if (filters.hasCredentials) params.set("hasCredentials", filters.hasCredentials);
  if (filters.payloadHash) params.set("payloadHash", filters.payloadHash);
  if (filters.trap) params.set("trap", filters.trap);
  if (filters.userAgent) params.set("userAgent", filters.userAgent);
  if (cursor) params.set("cursor", cursor);
  return params;
}

export function useEvents(filters: EventFilters) {
  return useInfiniteQuery({
    queryKey: ["events", filters],
    queryFn: ({ pageParam }) =>
      api.get<{ events: EventRow[]; next_cursor: string | null }>(
        `/api/v1/events?${buildEventParams(filters, pageParam as string | undefined).toString()}`
      ),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (lastPage) => lastPage.next_cursor ?? undefined,
    select: (data) => ({
      events: data.pages.reduce(
        (acc, page) => mergeByKey(acc, page.events, (event) => event.id),
        [] as EventRow[]
      ),
      nextCursor: data.pages.at(-1)?.next_cursor ?? null
    })
  });
}

export function useNetwork(sinceHours: string) {
  return useQuery({
    queryKey: ["network", sinceHours],
    queryFn: () => api.get<NetworkOverview>(`/api/v1/network?sinceHours=${encodeURIComponent(sinceHours)}`)
  });
}

export function useIps() {
  return useInfiniteQuery({
    queryKey: ["ips"],
    queryFn: ({ pageParam = 0 }) =>
      api.get<{ ips: IpProfile[]; next_offset: number | null }>(
        `/api/v1/ips?limit=100${pageParam ? `&offset=${pageParam}` : ""}`
      ),
    initialPageParam: 0,
    getNextPageParam: (lastPage) => lastPage.next_offset ?? undefined,
    select: (data) => ({
      ips: data.pages.reduce(
        (acc, page) => mergeByKey(acc, page.ips, (ip) => ip.source_ip),
        [] as IpProfile[]
      ),
      nextOffset: data.pages.at(-1)?.next_offset ?? null
    })
  });
}

export function useIpDetailInfinite(ip: string) {
  const timelineQuery = useQuery({
    queryKey: ["ip-timeline", ip],
    queryFn: () =>
      api.get<{ timeline: TimelinePoint[] }>(
        `/api/v1/ips/${encodeURIComponent(ip)}/timeline?sinceHours=168`
      ),
    enabled: Boolean(ip)
  });

  const detailQuery = useInfiniteQuery({
    queryKey: ["ip-detail", ip],
    queryFn: ({ pageParam }) =>
      api.get<IpDetail>(
        `/api/v1/ips/${encodeURIComponent(ip)}?limit=100${
          pageParam ? `&cursor=${encodeURIComponent(pageParam as string)}` : ""
        }`
      ),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (lastPage) => lastPage.next_cursor ?? undefined,
    enabled: Boolean(ip)
  });

  const profile = detailQuery.data?.pages[0]?.profile;
  const events =
    detailQuery.data?.pages.reduce(
      (acc, page) => mergeByKey(acc, page.events, (event) => event.id),
      [] as EventRow[]
    ) ?? [];

  return {
    profile,
    events,
    timeline: timelineQuery.data?.timeline ?? [],
    isLoading: detailQuery.isLoading || timelineQuery.isLoading,
    isFetchingNextPage: detailQuery.isFetchingNextPage,
    fetchNextPage: detailQuery.fetchNextPage,
    hasNextPage: detailQuery.hasNextPage,
    error: detailQuery.error ?? timelineQuery.error
  };
}

export function useIpDetail(ip: string) {
  return useIpDetailInfinite(ip);
}

export function usePayloads() {
  return useInfiniteQuery({
    queryKey: ["payloads"],
    queryFn: ({ pageParam = 0 }) =>
      api.get<{ payloads: PayloadRow[]; next_offset: number | null }>(
        `/api/v1/payloads?limit=100${pageParam ? `&offset=${pageParam}` : ""}`
      ),
    initialPageParam: 0,
    getNextPageParam: (lastPage) => lastPage.next_offset ?? undefined,
    select: (data) => ({
      payloads: data.pages.reduce(
        (acc, page) => mergeByKey(acc, page.payloads, (payload) => payload.sha256),
        [] as PayloadRow[]
      ),
      nextOffset: data.pages.at(-1)?.next_offset ?? null
    })
  });
}

export function usePayloadDetailInfinite(sha256: string) {
  const timelineQuery = useQuery({
    queryKey: ["payload-timeline", sha256],
    queryFn: () =>
      api.get<{ timeline: TimelinePoint[] }>(
        `/api/v1/payloads/${encodeURIComponent(sha256)}/timeline?sinceHours=168`
      ),
    enabled: Boolean(sha256)
  });

  const detailQuery = useInfiniteQuery({
    queryKey: ["payload-detail", sha256],
    queryFn: ({ pageParam }) =>
      api.get<PayloadDetail>(
        `/api/v1/payloads/${encodeURIComponent(sha256)}?limit=100${
          pageParam ? `&cursor=${encodeURIComponent(pageParam as string)}` : ""
        }`
      ),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (lastPage) => lastPage.next_cursor ?? undefined,
    enabled: Boolean(sha256)
  });

  const data = detailQuery.data?.pages[0] ?? null;
  const events =
    detailQuery.data?.pages.reduce(
      (acc, page) => mergeByKey(acc, page.events, (event) => event.id),
      [] as EventRow[]
    ) ?? [];

  return {
    data: data ? { ...data, events } : null,
    timeline: timelineQuery.data?.timeline ?? [],
    isLoading: detailQuery.isLoading || timelineQuery.isLoading,
    isFetchingNextPage: detailQuery.isFetchingNextPage,
    fetchNextPage: detailQuery.fetchNextPage,
    hasNextPage: detailQuery.hasNextPage,
    error: detailQuery.error ?? timelineQuery.error
  };
}

export function usePayloadDetail(sha256: string) {
  return usePayloadDetailInfinite(sha256);
}

export function useIntelOverview(sinceHours: string) {
  return useQuery({
    queryKey: ["intel-overview", sinceHours],
    queryFn: () =>
      api.get<IntelOverview>(`/api/v1/intel/overview?sinceHours=${encodeURIComponent(sinceHours)}`),
    staleTime: 30_000
  });
}

export function useHttpIntel(sinceHours: string) {
  return useQuery({
    queryKey: ["intel-http", sinceHours],
    queryFn: () =>
      api.get<HttpIntelOverview>(`/api/v1/intel/http?sinceHours=${encodeURIComponent(sinceHours)}`),
    staleTime: 30_000
  });
}

export function useActors(sinceHours: string, limit = 20) {
  return useQuery({
    queryKey: ["intel-actors", sinceHours, limit],
    queryFn: () =>
      api.get<{ actors: IntelActor[] }>(
        `/api/v1/intel/actors?sinceHours=${encodeURIComponent(sinceHours)}&limit=${limit}`
      ),
    staleTime: 30_000
  });
}

export function useBehavioralCampaigns(sinceHours: string) {
  return useQuery({
    queryKey: ["intel-campaigns", sinceHours],
    queryFn: () =>
      api.get<IntelCampaigns>(`/api/v1/intel/campaigns?sinceHours=${encodeURIComponent(sinceHours)}`),
    staleTime: 30_000
  });
}

export function useOpsStatus(options?: { refetchInterval?: number }) {
  return useQuery<OpsStatus>({
    queryKey: ["ops-status"],
    queryFn: () => api.get<OpsStatus>("/api/v1/ops/status"),
    staleTime: 30_000,
    ...(options?.refetchInterval !== undefined
      ? { refetchInterval: options.refetchInterval }
      : {})
  });
}

export interface RollupsParams {
  sinceHours?: string;
  bucketWidth?: "hour" | "day";
  dimension?: string;
}

export function useRollups({
  sinceHours = "168",
  bucketWidth = "hour",
  dimension = "protocol"
}: RollupsParams = {}) {
  const params = new URLSearchParams({
    sinceHours,
    bucketWidth,
    dimension
  });
  return useQuery({
    queryKey: ["rollups", sinceHours, bucketWidth, dimension],
    queryFn: () => api.get<RollupsResponse>(`/api/v1/analytics/rollups?${params.toString()}`),
    staleTime: 60_000
  });
}

export interface CompareParams {
  dimension: "tag" | "confidenceReason" | "trap";
  key: string;
  hoursA?: string;
  hoursB?: string;
}

export function useCompare({ dimension, key, hoursA = "24", hoursB = "168" }: CompareParams) {
  const params = new URLSearchParams({
    dimension,
    key,
    hoursA,
    hoursB
  });
  return useQuery({
    queryKey: ["compare", dimension, key, hoursA, hoursB],
    queryFn: () => api.get<CompareResponse>(`/api/v1/analytics/compare?${params.toString()}`),
    enabled: Boolean(key),
    staleTime: 60_000
  });
}

export function useNewIps(since: string) {
  return useQuery({
    queryKey: ["new-ips", since],
    queryFn: () =>
      api.get<NewIpsResponse>(`/api/v1/feeds/new-ips.json?since=${encodeURIComponent(since)}`),
    enabled: Boolean(since),
    staleTime: 60_000
  });
}

export type { EventFilters };
export { DEFAULT_EVENT_FILTERS } from "@/types/api";
