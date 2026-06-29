import { DurableObject } from "cloudflare:workers";

export interface LiveEvent {
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

export interface Env {
  LIVE_EVENTS: DurableObjectNamespace<LiveEvents>;
}

interface PublishRequest {
  event?: unknown;
}

const LIVE_ROOM = "public-live";

function json(body: unknown, init?: ResponseInit): Response {
  const headers = new Headers(init?.headers);
  headers.set("cache-control", headers.get("cache-control") ?? "no-store");
  return Response.json(body, { ...init, headers });
}

function isLiveEvent(value: unknown): value is LiveEvent {
  if (!value || typeof value !== "object") return false;
  const event = value as Partial<LiveEvent>;
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

function liveRoom(env: Env): DurableObjectStub<LiveEvents> {
  return env.LIVE_EVENTS.getByName(LIVE_ROOM);
}

export class LiveEvents extends DurableObject<Env> {
  async fetch(request: Request): Promise<Response> {
    if (request.headers.get("upgrade")?.toLowerCase() !== "websocket") {
      return json({ error: "websocket_required" }, { status: 426 });
    }

    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    if (!client || !server) return json({ error: "websocket_pair_failed" }, { status: 500 });
    this.ctx.acceptWebSocket(server);
    server.send(JSON.stringify({ type: "connected", connections: this.ctx.getWebSockets().length, at: new Date().toISOString() }));
    return new Response(null, { status: 101, webSocket: client });
  }

  publish(event: LiveEvent): { delivered: number } {
    const message = JSON.stringify({ type: "event", event, at: new Date().toISOString() });
    let delivered = 0;

    for (const socket of this.ctx.getWebSockets()) {
      try {
        socket.send(message);
        delivered += 1;
      } catch (error) {
        console.warn("failed to send live event", { eventId: event.id, error });
      }
    }

    return { delivered };
  }

  webSocketMessage(socket: WebSocket, message: ArrayBuffer | string): void {
    if (message === "ping") {
      socket.send(JSON.stringify({ type: "pong", at: new Date().toISOString() }));
    }
  }

  webSocketClose(socket: WebSocket, code: number, reason: string, wasClean: boolean): void {
    socket.close(code, reason || (wasClean ? "closed" : "aborted"));
  }

  webSocketError(socket: WebSocket): void {
    socket.close(1011, "socket_error");
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/health") return json({ ok: true });

    if (url.pathname === "/api/live-stream") {
      return liveRoom(env).fetch(request);
    }

    if (url.pathname === "/internal/publish" && request.method === "POST") {
      const body = (await request.json().catch(() => null)) as PublishRequest | null;
      if (!isLiveEvent(body?.event)) return json({ error: "invalid_event" }, { status: 400 });
      return json(await liveRoom(env).publish(body.event));
    }

    return json({ error: "not_found" }, { status: 404 });
  }
};
