import { parseEventCursor, parseLimit, parseSinceHours, publicIp, publicSha256, token } from "./http";

export interface EventsQuery {
  sql: string;
  params: unknown[];
  limit: number;
}

export function buildEventsQuery(url: URL): EventsQuery | Response {
  const where: string[] = [];
  const params: unknown[] = [];
  const ip = publicIp(url.searchParams.get("ip"));
  const protocol = token(url.searchParams.get("protocol"), 24);
  const trap = token(url.searchParams.get("trap"), 120);
  const eventType = token(url.searchParams.get("eventType"), 120);
  const eventKind = token(url.searchParams.get("eventKind"), 48);
  const payloadHash = publicSha256(url.searchParams.get("payloadHash"));
  const rawDestinationPort = url.searchParams.get("destinationPort");
  const destinationPort = rawDestinationPort ? Number(rawDestinationPort) : null;
  const aggregate = url.searchParams.get("aggregate");
  const sinceHours = parseSinceHours(url);
  const limit = parseLimit(url, 100, 500);
  const cursor = parseEventCursor(url.searchParams.get("cursor"));

  where.push(`occurred_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)`);
  params.push(`-${sinceHours} hours`);

  if (url.searchParams.get("ip") && !ip) return new Response("invalid ip", { status: 400 });
  if (url.searchParams.get("payloadHash") && !payloadHash) return new Response("invalid payload hash", { status: 400 });
  if (destinationPort !== null && (!Number.isInteger(destinationPort) || destinationPort < 0 || destinationPort > 65535)) {
    return new Response("invalid destination port", { status: 400 });
  }
  if (cursor instanceof Response) return cursor;
  if (ip) {
    where.push("source_ip = ?");
    params.push(ip);
  }
  if (protocol) {
    where.push("protocol = ?");
    params.push(protocol);
  }
  if (trap) {
    where.push("trap = ?");
    params.push(trap);
  }
  if (eventType) {
    where.push("(protocol = ? OR trap = ? OR event_kind = ?)");
    params.push(eventType, eventType, eventType);
  }
  if (eventKind) {
    where.push("event_kind = ?");
    params.push(eventKind);
  }
  if (destinationPort !== null) {
    where.push("destination_port = ?");
    params.push(destinationPort);
  }
  if (aggregate === "true" || aggregate === "false") {
    where.push("is_aggregate = ?");
    params.push(aggregate === "true" ? 1 : 0);
  }
  if (payloadHash) {
    where.push("payload_sha256 = ?");
    params.push(payloadHash);
  }
  if (cursor) {
    where.push("(occurred_at < ? OR (occurred_at = ? AND id < ?))");
    params.push(cursor.occurredAt, cursor.occurredAt, cursor.id);
  }

  params.push(limit + 1);
  return {
    sql: `SELECT id, occurred_at, received_at, event_kind, source_ip, source_port, destination_port, protocol, trap, sensor_id,
      http_method, http_path, http_status, user_agent, credential_kind, has_username, has_password,
      payload_sha256, payload_size, payload_preview, packet_count, byte_count, tcp_flags, is_aggregate,
      pcap_sha256, pcap_available, severity, confidence, confidence_reasons_json, tags_json
      FROM events
      WHERE ${where.join(" AND ")}
      ORDER BY occurred_at DESC, id DESC
      LIMIT ?`,
    params,
    limit
  };
}
