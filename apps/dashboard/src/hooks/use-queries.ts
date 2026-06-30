import { useInfiniteQuery, useQuery, useQueries } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { mergeByKey } from "@/lib/utils";
import type {
  EventFilters,
  EventRow,
  IpDetail,
  IpProfile,
  NetworkOverview,
  Overview,
  PayloadDetail,
  PayloadRow,
  TimelinePoint
} from "@/types/api";

export function useOverview() {
  return useQuery({
    queryKey: ["overview"],
    queryFn: () => api.get<Overview>("/api/analytics/overview?sinceHours=24"),
    staleTime: 30_000
  });
}

function buildEventParams(filters: EventFilters, cursor?: string | null) {
  const params = new URLSearchParams({ limit: "100", sinceHours: filters.sinceHours });
  if (filters.ip) params.set("ip", filters.ip);
  if (filters.eventType) params.set("eventType", filters.eventType);
  if (filters.eventKind) params.set("eventKind", filters.eventKind);
  if (filters.destinationPort) params.set("destinationPort", filters.destinationPort);
  if (filters.aggregate) params.set("aggregate", filters.aggregate);
  if (cursor) params.set("cursor", cursor);
  return params.toString();
}

export function useEvents(filters: EventFilters) {
  return useInfiniteQuery({
    queryKey: ["events", filters],
    queryFn: ({ pageParam }) =>
      api.get<{ events: EventRow[]; next_cursor: string | null }>(
        `/api/v1/events?${buildEventParams(filters, pageParam as string | undefined)}`
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

export function useIpDetail(ip: string) {
  const results = useQueries({
    queries: [
      {
        queryKey: ["ip-detail", ip],
        queryFn: () =>
          api.get<IpDetail>(`/api/v1/ips/${encodeURIComponent(ip)}?limit=100`)
      },
      {
        queryKey: ["ip-timeline", ip],
        queryFn: () =>
          api.get<{ timeline: TimelinePoint[] }>(
            `/api/v1/ips/${encodeURIComponent(ip)}/timeline?sinceHours=168`
          )
      }
    ]
  });

  const [detailQuery, timelineQuery] = results;

  return {
    profile: detailQuery.data?.profile,
    events: detailQuery.data?.events ?? [],
    nextCursor: detailQuery.data?.next_cursor ?? null,
    timeline: timelineQuery.data?.timeline ?? [],
    isLoading: detailQuery.isLoading || timelineQuery.isLoading,
    error: detailQuery.error ?? timelineQuery.error
  };
}

export function useIpDetailMore(ip: string, cursor: string | null) {
  return useQuery({
    queryKey: ["ip-detail-more", ip, cursor],
    queryFn: () =>
      api.get<IpDetail>(
        `/api/v1/ips/${encodeURIComponent(ip)}?limit=100&cursor=${encodeURIComponent(cursor!)}`
      ),
    enabled: false
  });
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

export function usePayloadDetail(sha256: string) {
  const results = useQueries({
    queries: [
      {
        queryKey: ["payload-detail", sha256],
        queryFn: () =>
          api.get<PayloadDetail>(`/api/v1/payloads/${encodeURIComponent(sha256)}?limit=100`)
      },
      {
        queryKey: ["payload-timeline", sha256],
        queryFn: () =>
          api.get<{ timeline: TimelinePoint[] }>(
            `/api/v1/payloads/${encodeURIComponent(sha256)}/timeline?sinceHours=168`
          )
      }
    ]
  });

  const [detailQuery, timelineQuery] = results;

  return {
    data: detailQuery.data,
    timeline: timelineQuery.data?.timeline ?? [],
    isLoading: detailQuery.isLoading || timelineQuery.isLoading,
    error: detailQuery.error ?? timelineQuery.error
  };
}

export type { EventFilters };
export { DEFAULT_EVENT_FILTERS } from "@/types/api";
