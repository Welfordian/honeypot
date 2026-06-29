import { type MouseEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  Download,
  FileWarning,
  Filter,
  ListFilter,
  Network,
  RefreshCcw,
  Search,
  ShieldAlert,
  Signal
} from "lucide-react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from "recharts";
import { createApiClient, liveStreamUrl } from "./api.js";

type Tab = "overview" | "live" | "events" | "network" | "ips" | "payloads" | "exports";
type Route = { kind: "tab"; tab: Tab } | { kind: "ip"; ip: string } | { kind: "payload"; sha256: string };

interface EventRow {
  id: string;
  occurred_at: string;
  received_at: string;
  event_kind: string;
  source_ip: string;
  source_port?: number | null;
  destination_port?: number | null;
  protocol: string;
  trap: string;
  sensor_id: string;
  http_method?: string | null;
  http_path?: string | null;
  http_status?: number | null;
  user_agent?: string | null;
  credential_kind?: string | null;
  has_credentials: boolean;
  payload_sha256?: string | null;
  payload_size?: number;
  payload_preview?: string;
  packet_count: number;
  byte_count: number;
  tcp_flags?: string | null;
  is_aggregate: boolean;
  pcap_sha256?: string | null;
  pcap_available: boolean;
  severity: number;
  confidence: number;
  confidence_reasons: string[];
  tags: string[];
}

interface IpProfile {
  source_ip: string;
  first_seen: string;
  last_seen: string;
  event_count: number;
  unique_traps: string[];
  protocols: string[];
  score: number;
  confidence: number;
  confidence_reasons: string[];
  last_trap?: string | null;
  last_protocol?: string | null;
}

interface Overview {
  totals: { events: number; unique_ips: number; max_severity: number };
  timeline: Array<{ bucket: string; count: number }>;
  topIps: Array<{ key: string; count: number; max_severity: number }>;
  topProtocols: Array<{ key: string; count: number }>;
  topTraps: Array<{ key: string; count: number }>;
  topSeverities: Array<{ key: string | number; count: number }>;
  sensors: Array<{ sensor_id: string; last_seen: string; last_protocol: string; last_trap: string; event_count: number }>;
}

interface PayloadRow {
  sha256: string;
  size_bytes: number;
  mime_guess: string;
  preview: string;
  first_seen: string;
  last_seen: string;
  event_count: number;
  max_confidence: number;
  unique_ips: number;
}

interface TimelinePoint {
  bucket: string;
  count: number;
  unique_ips?: number;
  max_severity?: number;
  max_confidence?: number;
}

interface RelatedIp {
  source_ip: string;
  event_count: number;
  max_confidence: number;
  last_seen: string;
}

interface DimensionCount {
  key: string;
  count: number;
}

interface NetworkOverview {
  totals: {
    events: number;
    unique_ips: number;
    packets: number;
    bytes: number;
    aggregate_events: number;
  };
  timeline: Array<{ bucket: string; count: number; unique_ips: number }>;
  topPorts: DimensionCount[];
  topProtocols: DimensionCount[];
  tcpFlags: DimensionCount[];
  eventKinds: DimensionCount[];
  topBannerIps: DimensionCount[];
  pcap: {
    chunks: number;
    bytes: number;
    packets: number;
  };
}

interface PayloadDetail {
  payload: PayloadRow;
  related_ips: RelatedIp[];
  protocols: DimensionCount[];
  traps: DimensionCount[];
  events: EventRow[];
  next_cursor: string | null;
}

const api = createApiClient();
type LiveStatus = "connecting" | "live" | "reconnecting" | "offline";

const LIVE_STATUS_LABELS: Record<LiveStatus, string> = {
  connecting: "Connecting to Durable Object stream",
  live: "Durable Object stream",
  reconnecting: "Reconnecting stream",
  offline: "Stream offline"
};

function isEventRow(value: unknown): value is EventRow {
  if (!value || typeof value !== "object") return false;
  const event = value as Partial<EventRow>;
  return (
    typeof event.id === "string" &&
    typeof event.occurred_at === "string" &&
    typeof event.received_at === "string" &&
    typeof event.event_kind === "string" &&
    typeof event.source_ip === "string" &&
    typeof event.protocol === "string" &&
    typeof event.trap === "string" &&
    typeof event.sensor_id === "string" &&
    typeof event.has_credentials === "boolean" &&
    typeof event.packet_count === "number" &&
    typeof event.byte_count === "number" &&
    typeof event.is_aggregate === "boolean" &&
    typeof event.pcap_available === "boolean" &&
    typeof event.severity === "number" &&
    typeof event.confidence === "number" &&
    Array.isArray(event.confidence_reasons) &&
    Array.isArray(event.tags)
  );
}

function mergeLiveEvent(events: EventRow[], next: EventRow): EventRow[] {
  const seen = new Set<string>();
  return [next, ...events].filter((event) => {
    if (seen.has(event.id)) return false;
    seen.add(event.id);
    return true;
  }).slice(0, 100);
}

function mergeByKey<T>(current: T[], next: T[], keyOf: (item: T) => string): T[] {
  const seen = new Set<string>();
  return [...current, ...next].filter((item) => {
    const key = keyOf(item);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function formatTime(value?: string): string {
  if (!value) return "";
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit"
  }).format(new Date(value));
}

function severityClass(severity: number): string {
  if (severity >= 8) return "severity critical";
  if (severity >= 5) return "severity high";
  return "severity low";
}

function confidenceClass(confidence: number): string {
  if (confidence >= 80) return "severity critical";
  if (confidence >= 50) return "severity high";
  return "severity low";
}

function shortHash(value: string): string {
  return `${value.slice(0, 12)}...${value.slice(-6)}`;
}

function safeDecode(value: string): string | null {
  try {
    return decodeURIComponent(value);
  } catch {
    return null;
  }
}

function parseRoute(pathname = window.location.pathname, search = window.location.search): Route {
  const parts = pathname.split("/").filter(Boolean).map(safeDecode);
  if (parts[0] === "ips" && parts[1]) return { kind: "ip", ip: parts[1] };
  if (parts[0] === "payloads" && parts[1]) return { kind: "payload", sha256: parts[1].toLowerCase() };
  const tab = new URLSearchParams(search).get("view");
  if (tab === "live" || tab === "events" || tab === "network" || tab === "ips" || tab === "payloads" || tab === "exports") return { kind: "tab", tab };
  return { kind: "tab", tab: "overview" };
}

function routePath(route: Route): string {
  if (route.kind === "ip") return `/ips/${encodeURIComponent(route.ip)}`;
  if (route.kind === "payload") return `/payloads/${encodeURIComponent(route.sha256)}`;
  if (route.tab !== "overview") return `/?view=${route.tab}`;
  return "/";
}

function routeTab(route: Route): Tab {
  if (route.kind === "ip") return "ips";
  if (route.kind === "payload") return "payloads";
  return route.tab;
}

function routeTitle(route: Route): string {
  if (route.kind === "ip") return route.ip;
  if (route.kind === "payload") return shortHash(route.sha256);
  return `${route.tab.charAt(0).toUpperCase()}${route.tab.slice(1)}`;
}

function useMediaQuery(query: string): boolean {
  const [matches, setMatches] = useState(() => (typeof window === "undefined" ? false : window.matchMedia(query).matches));

  useEffect(() => {
    const media = window.matchMedia(query);
    const update = () => setMatches(media.matches);
    update();
    media.addEventListener("change", update);
    return () => media.removeEventListener("change", update);
  }, [query]);

  return matches;
}

function Metric({ label, value, icon: Icon }: { label: string; value: string | number; icon: typeof Activity }) {
  return (
    <section className="metric">
      <Icon size={18} />
      <div>
        <span>{label}</span>
        <strong>{value}</strong>
      </div>
    </section>
  );
}

function ChartPanel({ title, data, height = 220, compact = false }: { title: string; data: Array<{ key: string | number; count: number }>; height?: number; compact?: boolean }) {
  return (
    <section className="panel">
      <div className="panel-heading">
        <h2>{title}</h2>
      </div>
      <ResponsiveContainer width="100%" height={height}>
        <BarChart data={data} margin={{ top: 8, right: 12, left: 4, bottom: 8 }}>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis dataKey="key" minTickGap={8} {...(compact ? { tick: false } : {})} />
          <YAxis allowDecimals={false} width={compact ? 44 : 48} />
          <Tooltip />
          <Bar dataKey="count" fill="#2d7d9a" />
        </BarChart>
      </ResponsiveContainer>
    </section>
  );
}

function TimelinePanel({ title, data, height = 220 }: { title: string; data: TimelinePoint[]; height?: number }) {
  const compact = useMediaQuery("(max-width: 700px)");
  const timeline = data.map((row) => ({ ...row, label: formatTime(row.bucket) }));
  return (
    <section className="panel wide">
      <div className="panel-heading">
        <h2>{title}</h2>
      </div>
      {timeline.length ? (
        <ResponsiveContainer width="100%" height={compact ? 180 : height}>
          <LineChart data={timeline} margin={{ top: 8, right: 12, left: 4, bottom: 8 }}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="label" minTickGap={28} {...(compact ? { tick: false } : {})} />
            <YAxis allowDecimals={false} width={compact ? 44 : 48} />
            <Tooltip />
            <Line type="monotone" dataKey="count" stroke="#16815f" strokeWidth={2} dot={false} />
          </LineChart>
        </ResponsiveContainer>
      ) : (
        <div className="empty">No timeline data.</div>
      )}
    </section>
  );
}

function InfiniteLoader({ hasMore, loading, onLoadMore }: { hasMore: boolean; loading: boolean; onLoadMore: () => void }) {
  const ref = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!hasMore || loading) return;
    const node = ref.current;
    if (!node) return;

    const observer = new IntersectionObserver(
      (entries) => {
        if (entries.some((entry) => entry.isIntersecting)) {
          observer.disconnect();
          onLoadMore();
        }
      },
      { rootMargin: "360px 0px" }
    );
    observer.observe(node);
    return () => observer.disconnect();
  }, [hasMore, loading, onLoadMore]);

  return (
    <div className="infinite-loader" ref={ref}>
      {loading ? "Loading more..." : hasMore ? "Scroll for more" : "End of results"}
    </div>
  );
}

function OverviewView({ data }: { data: Overview | null }) {
  const compact = useMediaQuery("(max-width: 700px)");
  if (!data) return <div className="empty">No overview data loaded.</div>;
  const timeline = data.timeline.map((row) => ({ ...row, label: formatTime(row.bucket) }));
  return (
    <div className="stack">
      <div className="metrics">
        <Metric label="Events" value={data.totals.events} icon={Activity} />
        <Metric label="Unique IPs" value={data.totals.unique_ips} icon={Network} />
        <Metric label="Max severity" value={data.totals.max_severity ?? 0} icon={ShieldAlert} />
        <Metric label="Sensors" value={data.sensors.length} icon={Signal} />
      </div>

      <section className="panel wide">
        <div className="panel-heading">
          <h2>Attack Timeline</h2>
        </div>
        <ResponsiveContainer width="100%" height={compact ? 180 : 240}>
          <LineChart data={timeline} margin={{ top: 8, right: 12, left: 4, bottom: 8 }}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="label" minTickGap={28} {...(compact ? { tick: false } : {})} />
            <YAxis allowDecimals={false} width={compact ? 44 : 48} />
            <Tooltip />
            <Line type="monotone" dataKey="count" stroke="#16815f" strokeWidth={2} dot={false} />
          </LineChart>
        </ResponsiveContainer>
      </section>

      <div className="grid two">
        <ChartPanel title="Top Protocols" data={data.topProtocols} height={compact ? 180 : 220} compact={compact} />
        <ChartPanel title="Top Traps" data={data.topTraps} height={compact ? 180 : 220} compact={compact} />
      </div>

      <div className="grid two">
        <ChartPanel title="Severity Spread" data={data.topSeverities} height={compact ? 180 : 220} compact={compact} />
        <section className="panel sensor-health">
          <div className="panel-heading">
            <h2>Sensor Health</h2>
          </div>
          <table className="responsive-table">
            <thead>
              <tr><th>Sensor</th><th>Last Seen</th><th>Last Trap</th><th>Events</th></tr>
            </thead>
            <tbody>
              {data.sensors.map((sensor) => (
                <tr key={sensor.sensor_id}>
                  <td data-label="Sensor">{sensor.sensor_id}</td>
                  <td data-label="Last Seen">{formatTime(sensor.last_seen)}</td>
                  <td data-label="Last Trap">{sensor.last_protocol}/{sensor.last_trap}</td>
                  <td data-label="Events">{sensor.event_count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      </div>
    </div>
  );
}

function EventsTable({
  events,
  embedded = false,
  onNavigate
}: {
  events: EventRow[];
  embedded?: boolean;
  onNavigate?: (route: Route) => void;
}) {
  const navigate = (event: MouseEvent<HTMLAnchorElement>, route: Route) => {
    if (!onNavigate) return;
    event.preventDefault();
    onNavigate(route);
  };

  const table = (
    <table className="responsive-table">
      <thead>
        <tr><th>Time</th><th>IP</th><th>Protocol</th><th>Trap</th><th>Target</th><th>Severity</th><th>Confidence</th><th>Payload</th></tr>
      </thead>
      <tbody>
        {events.map((event) => (
          <tr key={event.id}>
            <td data-label="Time">{formatTime(event.occurred_at)}</td>
            <td data-label="IP" className="mono">
              <a className="inline-link" href={`/ips/${event.source_ip}`} onClick={(click) => navigate(click, { kind: "ip", ip: event.source_ip })}>{event.source_ip}</a>
            </td>
            <td data-label="Protocol">{event.protocol}</td>
            <td data-label="Trap">
              {event.trap}
              {event.event_kind !== "trap" && <span className="subtle block">{event.event_kind}{event.is_aggregate ? " aggregate" : ""}</span>}
            </td>
            <td data-label="Target" className="clip">{event.http_path || event.destination_port || ""}</td>
            <td data-label="Severity"><span className={severityClass(event.severity)}>{event.severity}</span></td>
            <td data-label="Confidence"><span className={confidenceClass(event.confidence)}>{event.confidence}</span></td>
            <td data-label="Payload" className="clip">
              {event.payload_sha256 ? (
                <>
                  {event.payload_preview || "payload"}{" "}
                  <a className="inline-link mono" href={`/payloads/${event.payload_sha256}`} onClick={(click) => navigate(click, { kind: "payload", sha256: event.payload_sha256 ?? "" })}>{shortHash(event.payload_sha256)}</a>
                </>
              ) : (
                event.payload_preview || (event.pcap_available ? `pcap ${event.pcap_sha256 ? shortHash(event.pcap_sha256) : "captured"}` : event.has_credentials ? "credential attempt" : "")
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );

  if (embedded) {
    return <div className="embedded-table">{events.length ? table : <div className="empty">No events found.</div>}</div>;
  }

  return (
    <section className="panel wide table-panel">
      {events.length ? table : <div className="empty">No events found.</div>}
    </section>
  );
}

function LiveView({ onNavigate }: { onNavigate: (route: Route) => void }) {
  const [events, setEvents] = useState<EventRow[]>([]);
  const [lastUpdate, setLastUpdate] = useState("");
  const [status, setStatus] = useState<LiveStatus>("connecting");
  const reconnectAttempt = useRef(0);

  useEffect(() => {
    let cancelled = false;
    let socket: WebSocket | null = null;
    let reconnectTimer: number | undefined;
    let pingTimer: number | undefined;

    const clearPing = () => {
      if (pingTimer !== undefined) window.clearInterval(pingTimer);
      pingTimer = undefined;
    };

    const scheduleReconnect = () => {
      clearPing();
      if (cancelled) return;
      setStatus("reconnecting");
      const delay = Math.min(30000, 1000 * 2 ** reconnectAttempt.current);
      reconnectAttempt.current += 1;
      reconnectTimer = window.setTimeout(connect, delay);
    };

    const connect = () => {
      if (cancelled) return;
      setStatus(reconnectAttempt.current ? "reconnecting" : "connecting");
      socket = new WebSocket(liveStreamUrl());

      socket.addEventListener("open", () => {
        reconnectAttempt.current = 0;
        setStatus("live");
        setLastUpdate(new Date().toISOString());
        clearPing();
        pingTimer = window.setInterval(() => {
          if (socket?.readyState === WebSocket.OPEN) socket.send("ping");
        }, 25000);
      });

      socket.addEventListener("message", (event) => {
        if (typeof event.data !== "string") return;
        let message: { type?: string; event?: unknown; at?: string };
        try {
          message = JSON.parse(event.data) as { type?: string; event?: unknown; at?: string };
        } catch {
          return;
        }

        if (message.type === "event" && isEventRow(message.event)) {
          const streamedEvent = message.event;
          setEvents((current) => mergeLiveEvent(current, streamedEvent));
          setLastUpdate(message.at ?? streamedEvent.received_at);
          setStatus("live");
          return;
        }

        if (message.type === "connected" || message.type === "pong") {
          setLastUpdate(message.at ?? new Date().toISOString());
          setStatus("live");
        }
      });

      socket.addEventListener("close", scheduleReconnect);
      socket.addEventListener("error", () => socket?.close());
    };

    api
      .get<{ events: EventRow[]; polled_at: string }>("/api/live?limit=100")
      .then((response) => {
        if (cancelled) return;
        setEvents(response.events);
        setLastUpdate(response.polled_at);
      })
      .catch(console.error)
      .finally(connect);

    return () => {
      cancelled = true;
      if (reconnectTimer !== undefined) window.clearTimeout(reconnectTimer);
      clearPing();
      socket?.close(1000, "unmounted");
    };
  }, []);

  return (
    <div className="stack">
      <section className={`toolbar live-toolbar ${status}`}>
        <Signal size={16} />
        <span className="live-status">{LIVE_STATUS_LABELS[status]}</span>
        <span className="subtle">Last update {formatTime(lastUpdate)}</span>
      </section>
      <EventsTable events={events} onNavigate={onNavigate} />
    </div>
  );
}

function EventsView({ onNavigate }: { onNavigate: (route: Route) => void }) {
  const [events, setEvents] = useState<EventRow[]>([]);
  const [filters, setFilters] = useState({ ip: "", eventType: "", eventKind: "", destinationPort: "", aggregate: "", sinceHours: "24" });
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const requestId = useRef(0);

  const eventParams = useCallback((cursor?: string | null) => {
    const params = new URLSearchParams({ limit: "100", sinceHours: filters.sinceHours });
    if (filters.ip) params.set("ip", filters.ip);
    if (filters.eventType) params.set("eventType", filters.eventType);
    if (filters.eventKind) params.set("eventKind", filters.eventKind);
    if (filters.destinationPort) params.set("destinationPort", filters.destinationPort);
    if (filters.aggregate) params.set("aggregate", filters.aggregate);
    if (cursor) params.set("cursor", cursor);
    return params;
  }, [filters]);

  const load = useCallback(async () => {
    const currentRequest = requestId.current + 1;
    requestId.current = currentRequest;
    setLoading(true);
    try {
      const response = await api.get<{ events: EventRow[]; next_cursor: string | null }>(`/api/v1/events?${eventParams()}`);
      if (requestId.current !== currentRequest) return;
      setEvents(response.events);
      setNextCursor(response.next_cursor);
    } finally {
      if (requestId.current === currentRequest) setLoading(false);
    }
  }, [eventParams]);

  const loadMore = useCallback(async () => {
    if (!nextCursor || loadingMore) return;
    setLoadingMore(true);
    try {
      const response = await api.get<{ events: EventRow[]; next_cursor: string | null }>(`/api/v1/events?${eventParams(nextCursor)}`);
      setEvents((current) => mergeByKey(current, response.events, (event) => event.id));
      setNextCursor(response.next_cursor);
    } finally {
      setLoadingMore(false);
    }
  }, [eventParams, loadingMore, nextCursor]);

  useEffect(() => {
    void load();
  }, [load]);

  return (
    <div className="stack">
      <section className="toolbar">
        <Filter size={16} />
        <input aria-label="IP address" placeholder="IP address" value={filters.ip} onChange={(event) => setFilters({ ...filters, ip: event.target.value })} />
        <input aria-label="Event type, protocol, or trap" placeholder="Event type, protocol, or trap" value={filters.eventType} onChange={(event) => setFilters({ ...filters, eventType: event.target.value })} />
        <select aria-label="Event kind" value={filters.eventKind} onChange={(event) => setFilters({ ...filters, eventKind: event.target.value })}>
          <option value="">Any kind</option>
          <option value="trap">Trap</option>
          <option value="network-attempt">Network attempt</option>
          <option value="tcp-banner">TCP banner</option>
        </select>
        <input aria-label="Destination port" placeholder="Port" value={filters.destinationPort} onChange={(event) => setFilters({ ...filters, destinationPort: event.target.value })} />
        <select aria-label="Aggregate state" value={filters.aggregate} onChange={(event) => setFilters({ ...filters, aggregate: event.target.value })}>
          <option value="">Detail + aggregate</option>
          <option value="false">Detail only</option>
          <option value="true">Aggregates only</option>
        </select>
        <input aria-label="Hours" placeholder="Hours" value={filters.sinceHours} onChange={(event) => setFilters({ ...filters, sinceHours: event.target.value })} />
        <button onClick={() => void load()}><Search size={16} />Search</button>
      </section>
      <EventsTable events={events} onNavigate={onNavigate} />
      <InfiniteLoader hasMore={Boolean(nextCursor)} loading={loading || loadingMore} onLoadMore={loadMore} />
    </div>
  );
}

function NetworkView() {
  const [data, setData] = useState<NetworkOverview | null>(null);
  const [sinceHours, setSinceHours] = useState("24");
  const [loading, setLoading] = useState(false);
  const compact = useMediaQuery("(max-width: 700px)");

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setData(await api.get<NetworkOverview>(`/api/v1/network?sinceHours=${encodeURIComponent(sinceHours)}`));
    } finally {
      setLoading(false);
    }
  }, [sinceHours]);

  useEffect(() => {
    void load();
  }, [load]);

  if (!data) return <div className="empty">Loading network capture analytics.</div>;

  return (
    <div className="stack">
      <section className="toolbar">
        <Filter size={16} />
        <input aria-label="Hours" placeholder="Hours" value={sinceHours} onChange={(event) => setSinceHours(event.target.value)} />
        <button onClick={() => void load()}><Search size={16} />Refresh</button>
        {loading && <span className="subtle">Loading...</span>}
      </section>

      <div className="metrics">
        <Metric label="Network events" value={data.totals.events} icon={Activity} />
        <Metric label="Unique IPs" value={data.totals.unique_ips} icon={Network} />
        <Metric label="Packets" value={data.totals.packets} icon={Signal} />
        <Metric label="Private PCAP chunks" value={data.pcap.chunks} icon={FileWarning} />
      </div>

      <TimelinePanel title="Network Timeline" data={data.timeline} />
      <div className="grid two">
        <ChartPanel title="Top Destination Ports" data={data.topPorts} height={compact ? 180 : 220} compact={compact} />
        <ChartPanel title="Network Event Kinds" data={data.eventKinds} height={compact ? 180 : 220} compact={compact} />
      </div>
      <div className="grid two">
        <ChartPanel title="Network Protocols" data={data.topProtocols} height={compact ? 180 : 220} compact={compact} />
        <ChartPanel title="TCP Flags" data={data.tcpFlags} height={compact ? 180 : 220} compact={compact} />
      </div>
      <div className="grid two">
        <ChartPanel title="Banner Hit IPs" data={data.topBannerIps} height={compact ? 180 : 220} compact={compact} />
        <section className="panel">
          <div className="panel-heading">
            <h2>Private Capture Storage</h2>
          </div>
          <div className="detail-grid capture-storage">
            <div><span>Chunks</span><strong>{data.pcap.chunks}</strong></div>
            <div><span>Packets</span><strong>{data.pcap.packets}</strong></div>
            <div><span>Bytes</span><strong>{data.pcap.bytes}</strong></div>
            <div><span>Aggregates</span><strong>{data.totals.aggregate_events}</strong></div>
          </div>
        </section>
      </div>
    </div>
  );
}

function IpsView({ onNavigate }: { onNavigate: (route: Route) => void }) {
  const [ips, setIps] = useState<IpProfile[]>([]);
  const [nextOffset, setNextOffset] = useState<number | null>(null);
  const [loading, setLoading] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);

  useEffect(() => {
    setLoading(true);
    api
      .get<{ ips: IpProfile[]; next_offset: number | null }>("/api/v1/ips?limit=100")
      .then((response) => {
        setIps(response.ips);
        setNextOffset(response.next_offset);
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  const loadMore = useCallback(async () => {
    if (nextOffset === null || loadingMore) return;
    setLoadingMore(true);
    try {
      const response = await api.get<{ ips: IpProfile[]; next_offset: number | null }>(`/api/v1/ips?limit=100&offset=${nextOffset}`);
      setIps((current) => mergeByKey(current, response.ips, (ip) => ip.source_ip));
      setNextOffset(response.next_offset);
    } finally {
      setLoadingMore(false);
    }
  }, [loadingMore, nextOffset]);

  return (
    <div className="stack">
      <section className="panel wide table-panel">
        <table className="responsive-table">
          <thead>
            <tr><th>IP</th><th>Confidence</th><th>Score</th><th>Events</th><th>Last Type</th></tr>
          </thead>
          <tbody>
            {ips.map((ip) => (
              <tr key={ip.source_ip}>
                <td data-label="IP" className="mono">
                  <a
                    className="inline-link"
                    href={`/ips/${ip.source_ip}`}
                    onClick={(event) => {
                      event.preventDefault();
                      onNavigate({ kind: "ip", ip: ip.source_ip });
                    }}
                  >
                    {ip.source_ip}
                  </a>
                </td>
                <td data-label="Confidence"><span className={confidenceClass(ip.confidence)}>{ip.confidence}</span></td>
                <td data-label="Score"><span className={severityClass(ip.score)}>{ip.score}</span></td>
                <td data-label="Events">{ip.event_count}</td>
                <td data-label="Last Type">{ip.last_protocol}/{ip.last_trap}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
      <InfiniteLoader hasMore={nextOffset !== null} loading={loading || loadingMore} onLoadMore={loadMore} />
    </div>
  );
}

function PayloadsView({ onNavigate }: { onNavigate: (route: Route) => void }) {
  const [payloads, setPayloads] = useState<PayloadRow[]>([]);
  const [nextOffset, setNextOffset] = useState<number | null>(null);
  const [loading, setLoading] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);

  useEffect(() => {
    setLoading(true);
    api
      .get<{ payloads: PayloadRow[]; next_offset: number | null }>("/api/v1/payloads?limit=100")
      .then((response) => {
        setPayloads(response.payloads);
        setNextOffset(response.next_offset);
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  const loadMore = useCallback(async () => {
    if (nextOffset === null || loadingMore) return;
    setLoadingMore(true);
    try {
      const response = await api.get<{ payloads: PayloadRow[]; next_offset: number | null }>(`/api/v1/payloads?limit=100&offset=${nextOffset}`);
      setPayloads((current) => mergeByKey(current, response.payloads, (payload) => payload.sha256));
      setNextOffset(response.next_offset);
    } finally {
      setLoadingMore(false);
    }
  }, [loadingMore, nextOffset]);

  return (
    <div className="stack">
      <section className="panel wide table-panel">
        <table className="responsive-table">
          <thead>
            <tr><th>SHA-256</th><th>Events</th><th>IPs</th><th>Confidence</th><th>Size</th><th>MIME</th><th>Preview</th></tr>
          </thead>
          <tbody>
            {payloads.map((payload) => (
              <tr key={payload.sha256}>
                <td data-label="SHA-256" className="mono">
                  <a
                    className="inline-link"
                    href={`/payloads/${payload.sha256}`}
                    onClick={(event) => {
                      event.preventDefault();
                      onNavigate({ kind: "payload", sha256: payload.sha256 });
                    }}
                  >
                    {shortHash(payload.sha256)}
                  </a>
                </td>
                <td data-label="Events">{payload.event_count}</td>
                <td data-label="IPs">{payload.unique_ips}</td>
                <td data-label="Confidence"><span className={confidenceClass(payload.max_confidence)}>{payload.max_confidence}</span></td>
                <td data-label="Size">{payload.size_bytes}</td>
                <td data-label="MIME">{payload.mime_guess}</td>
                <td data-label="Preview" className="clip">{payload.preview}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
      <InfiniteLoader hasMore={nextOffset !== null} loading={loading || loadingMore} onLoadMore={loadMore} />
    </div>
  );
}

function ReasonChips({ reasons }: { reasons: string[] }) {
  if (!reasons.length) return <div className="empty">No confidence reasons recorded.</div>;
  return (
    <div className="chips">
      {reasons.map((reason) => <span key={reason}>{reason.replaceAll("_", " ")}</span>)}
    </div>
  );
}

function IpDetailView({ ip, onNavigate }: { ip: string; onNavigate: (route: Route) => void }) {
  const [data, setData] = useState<{ profile: IpProfile; events: EventRow[] } | null>(null);
  const [timeline, setTimeline] = useState<TimelinePoint[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    setData(null);
    setTimeline([]);
    setNextCursor(null);
    setError("");
    Promise.all([
      api.get<{ profile: IpProfile; events: EventRow[]; next_cursor: string | null }>(`/api/v1/ips/${encodeURIComponent(ip)}?limit=100`),
      api.get<{ timeline: TimelinePoint[] }>(`/api/v1/ips/${encodeURIComponent(ip)}/timeline?sinceHours=168`)
    ])
      .then(([detail, timelineResponse]) => {
        if (cancelled) return;
        setData(detail);
        setNextCursor(detail.next_cursor);
        setTimeline(timelineResponse.timeline);
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load IP detail.");
      });

    return () => {
      cancelled = true;
    };
  }, [ip]);

  const loadMore = useCallback(async () => {
    if (!nextCursor || loadingMore) return;
    setLoadingMore(true);
    try {
      const response = await api.get<{ profile: IpProfile; events: EventRow[]; next_cursor: string | null }>(
        `/api/v1/ips/${encodeURIComponent(ip)}?limit=100&cursor=${encodeURIComponent(nextCursor)}`
      );
      setData((current) => current ? { ...current, events: mergeByKey(current.events, response.events, (event) => event.id) } : current);
      setNextCursor(response.next_cursor);
    } finally {
      setLoadingMore(false);
    }
  }, [ip, loadingMore, nextCursor]);

  if (error) return <div className="error">{error}</div>;
  if (!data) return <div className="empty">Loading IP detail.</div>;

  return (
    <div className="stack">
      <section className="toolbar">
        <button onClick={() => onNavigate({ kind: "tab", tab: "ips" })}>Back to IPs</button>
        <span className="mono">{data.profile.source_ip}</span>
      </section>
      <div className="metrics">
        <Metric label="Confidence" value={data.profile.confidence} icon={ShieldAlert} />
        <Metric label="Score" value={data.profile.score} icon={Activity} />
        <Metric label="Events" value={data.profile.event_count} icon={Signal} />
        <Metric label="Protocols" value={data.profile.protocols.length} icon={Network} />
      </div>
      <section className="panel">
        <div className="panel-heading">
          <h2>Profile</h2>
        </div>
        <div className="detail-grid">
          <div><span>First seen</span><strong>{formatTime(data.profile.first_seen)}</strong></div>
          <div><span>Last seen</span><strong>{formatTime(data.profile.last_seen)}</strong></div>
          <div><span>Last protocol</span><strong>{data.profile.last_protocol || ""}</strong></div>
          <div><span>Last trap</span><strong>{data.profile.last_trap || ""}</strong></div>
        </div>
        <div className="detail-block">
          <h3>Confidence Reasons</h3>
          <ReasonChips reasons={data.profile.confidence_reasons} />
        </div>
        <div className="detail-block">
          <h3>Traps and Protocols</h3>
          <div className="chips">
            {data.profile.unique_traps.map((trap) => <span key={trap}>{trap}</span>)}
            {data.profile.protocols.map((protocol) => <span key={protocol}>{protocol}</span>)}
          </div>
        </div>
      </section>
      <TimelinePanel title="IP Timeline" data={timeline} />
      <EventsTable events={data.events} onNavigate={onNavigate} />
      <InfiniteLoader hasMore={Boolean(nextCursor)} loading={loadingMore} onLoadMore={loadMore} />
    </div>
  );
}

function PayloadDetailView({ sha256, onNavigate }: { sha256: string; onNavigate: (route: Route) => void }) {
  const [data, setData] = useState<PayloadDetail | null>(null);
  const [timeline, setTimeline] = useState<TimelinePoint[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState("");
  const compact = useMediaQuery("(max-width: 700px)");

  useEffect(() => {
    let cancelled = false;
    setData(null);
    setTimeline([]);
    setNextCursor(null);
    setError("");
    Promise.all([
      api.get<PayloadDetail>(`/api/v1/payloads/${encodeURIComponent(sha256)}?limit=100`),
      api.get<{ timeline: TimelinePoint[] }>(`/api/v1/payloads/${encodeURIComponent(sha256)}/timeline?sinceHours=168`)
    ])
      .then(([detail, timelineResponse]) => {
        if (cancelled) return;
        setData(detail);
        setNextCursor(detail.next_cursor);
        setTimeline(timelineResponse.timeline);
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load payload detail.");
      });

    return () => {
      cancelled = true;
    };
  }, [sha256]);

  const loadMore = useCallback(async () => {
    if (!nextCursor || loadingMore) return;
    setLoadingMore(true);
    try {
      const response = await api.get<PayloadDetail>(
        `/api/v1/payloads/${encodeURIComponent(sha256)}?limit=100&cursor=${encodeURIComponent(nextCursor)}`
      );
      setData((current) => current ? { ...current, events: mergeByKey(current.events, response.events, (event) => event.id) } : current);
      setNextCursor(response.next_cursor);
    } finally {
      setLoadingMore(false);
    }
  }, [loadingMore, nextCursor, sha256]);

  if (error) return <div className="error">{error}</div>;
  if (!data) return <div className="empty">Loading payload detail.</div>;

  return (
    <div className="stack">
      <section className="toolbar">
        <button onClick={() => onNavigate({ kind: "tab", tab: "payloads" })}>Back to Payloads</button>
        <span className="mono">{shortHash(data.payload.sha256)}</span>
      </section>
      <div className="metrics">
        <Metric label="Max confidence" value={data.payload.max_confidence} icon={ShieldAlert} />
        <Metric label="Events" value={data.payload.event_count} icon={Signal} />
        <Metric label="Unique IPs" value={data.payload.unique_ips} icon={Network} />
        <Metric label="Bytes" value={data.payload.size_bytes} icon={FileWarning} />
      </div>
      <section className="panel">
        <div className="panel-heading">
          <h2>Payload Hash</h2>
        </div>
        <div className="detail-grid">
          <div><span>SHA-256</span><strong className="mono wrap">{data.payload.sha256}</strong></div>
          <div><span>MIME</span><strong>{data.payload.mime_guess}</strong></div>
          <div><span>First seen</span><strong>{formatTime(data.payload.first_seen)}</strong></div>
          <div><span>Last seen</span><strong>{formatTime(data.payload.last_seen)}</strong></div>
        </div>
        <div className="detail-block">
          <h3>Redacted Preview</h3>
          <p className="payload-preview">{data.payload.preview || "No preview stored."}</p>
        </div>
      </section>
      <TimelinePanel title="Payload Timeline" data={timeline} />
      <div className="grid two">
        <ChartPanel title="Protocols" data={data.protocols} height={180} compact={compact} />
        <ChartPanel title="Traps" data={data.traps} height={180} compact={compact} />
      </div>
      <section className="panel table-panel">
        <div className="panel-heading">
          <h2>Related IPs</h2>
        </div>
        <table className="responsive-table">
          <thead>
            <tr><th>IP</th><th>Events</th><th>Confidence</th><th>Last Seen</th></tr>
          </thead>
          <tbody>
            {data.related_ips.map((ip) => (
              <tr key={ip.source_ip}>
                <td data-label="IP" className="mono">
                  <a
                    className="inline-link"
                    href={`/ips/${ip.source_ip}`}
                    onClick={(event) => {
                      event.preventDefault();
                      onNavigate({ kind: "ip", ip: ip.source_ip });
                    }}
                  >
                    {ip.source_ip}
                  </a>
                </td>
                <td data-label="Events">{ip.event_count}</td>
                <td data-label="Confidence"><span className={confidenceClass(ip.max_confidence)}>{ip.max_confidence}</span></td>
                <td data-label="Last Seen">{formatTime(ip.last_seen)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
      <EventsTable events={data.events} onNavigate={onNavigate} />
      <InfiniteLoader hasMore={Boolean(nextCursor)} loading={loadingMore} onLoadMore={loadMore} />
    </div>
  );
}

function ExportsView() {
  return (
    <section className="panel compact">
      <div className="action-list">
        <button onClick={() => void api.download("/api/exports/blocklist.txt", "honeypot-blocklist.txt")}><Download size={16} />Public IP Blocklist</button>
        <button onClick={() => void api.download("/api/exports/blocklist.txt?minScore=8", "honeypot-high-confidence-blocklist.txt")}><Download size={16} />High Confidence Blocklist</button>
        <button onClick={() => void api.download("/api/exports/network.csv", "honeypot-network-metadata.csv")}><Download size={16} />Network Metadata CSV</button>
      </div>
    </section>
  );
}

export function App() {
  const [route, setRoute] = useState<Route>(() => parseRoute());
  const [overview, setOverview] = useState<Overview | null>(null);
  const [error, setError] = useState("");
  const tab = routeTab(route);
  const title = useMemo(() => routeTitle(route), [route]);

  const navigate = useCallback((nextRoute: Route) => {
    const path = routePath(nextRoute);
    window.history.pushState(null, "", path);
    setRoute(nextRoute);
  }, []);

  const loadOverview = useCallback(async () => {
    try {
      setError("");
      setOverview(await api.get<Overview>("/api/analytics/overview?sinceHours=24"));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load dashboard.");
    }
  }, []);

  useEffect(() => {
    void loadOverview();
  }, [loadOverview]);

  useEffect(() => {
    const onPopState = () => setRoute(parseRoute());
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand"><ShieldAlert size={22} /><span>dashboard.example.com</span></div>
        <nav aria-label="Dashboard views">
          <button className={tab === "overview" ? "active" : ""} onClick={() => navigate({ kind: "tab", tab: "overview" })}><Activity size={16} />Overview</button>
          <button className={tab === "live" ? "active" : ""} onClick={() => navigate({ kind: "tab", tab: "live" })}><Signal size={16} />Live</button>
          <button className={tab === "events" ? "active" : ""} onClick={() => navigate({ kind: "tab", tab: "events" })}><ListFilter size={16} />Search</button>
          <button className={tab === "network" ? "active" : ""} onClick={() => navigate({ kind: "tab", tab: "network" })}><Network size={16} />Network</button>
          <button className={tab === "ips" ? "active" : ""} onClick={() => navigate({ kind: "tab", tab: "ips" })}><Network size={16} />IPs</button>
          <button className={tab === "payloads" ? "active" : ""} onClick={() => navigate({ kind: "tab", tab: "payloads" })}><FileWarning size={16} />Payloads</button>
          <button className={tab === "exports" ? "active" : ""} onClick={() => navigate({ kind: "tab", tab: "exports" })}><Download size={16} />Exports</button>
        </nav>
      </aside>
      <main className="content">
        <header>
          <div>
            <h1>{title}</h1>
            <p>Public honeypot telemetry from decoy systems. Raw payloads and secrets are redacted.</p>
          </div>
          <button className="refresh-action" onClick={() => void loadOverview()} title="Refresh"><RefreshCcw size={16} /><span>Refresh</span></button>
        </header>
        {error && <div className="error">{error}</div>}
        {route.kind === "ip" && <IpDetailView ip={route.ip} onNavigate={navigate} />}
        {route.kind === "payload" && <PayloadDetailView sha256={route.sha256} onNavigate={navigate} />}
        {route.kind === "tab" && tab === "overview" && <OverviewView data={overview} />}
        {route.kind === "tab" && tab === "live" && <LiveView onNavigate={navigate} />}
        {route.kind === "tab" && tab === "events" && <EventsView onNavigate={navigate} />}
        {route.kind === "tab" && tab === "network" && <NetworkView />}
        {route.kind === "tab" && tab === "ips" && <IpsView onNavigate={navigate} />}
        {route.kind === "tab" && tab === "payloads" && <PayloadsView onNavigate={navigate} />}
        {route.kind === "tab" && tab === "exports" && <ExportsView />}
      </main>
    </div>
  );
}
