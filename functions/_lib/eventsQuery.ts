import { likeSubstring, parseEventCursor, parseLimit, parseSinceHours, publicIp, publicSha256, token } from "./http";

export interface EventsQuery {
  sql: string;
  params: unknown[];
  limit: number;
}

export interface EventsQueryOptions {
  defaultLimit?: number;
  maxLimit?: number;
}

export function buildEventsQuery(url: URL, options?: EventsQueryOptions): EventsQuery | Response {
  const where: string[] = [];
  const params: unknown[] = [];
  const ip = publicIp(url.searchParams.get("ip"));
  const protocol = token(url.searchParams.get("protocol"), 24);
  const trap = token(url.searchParams.get("trap"), 120);
  const eventType = token(url.searchParams.get("eventType"), 120);
  const eventKind = token(url.searchParams.get("eventKind"), 48);
  const payloadHash = publicSha256(url.searchParams.get("payloadHash"));
  const tag = token(url.searchParams.get("tag"), 80);
  const userAgent = likeSubstring(url.searchParams.get("userAgent"), 120);
  const confidenceReason = token(url.searchParams.get("confidenceReason"), 48);
  const rawMinConfidence = url.searchParams.get("minConfidence");
  const minConfidence = rawMinConfidence ? Number(rawMinConfidence) : null;
  const hasCredentials = url.searchParams.get("hasCredentials");
  const rawDestinationPort = url.searchParams.get("destinationPort");
  const destinationPort = rawDestinationPort ? Number(rawDestinationPort) : null;
  const aggregate = url.searchParams.get("aggregate");
  const sinceHours = parseSinceHours(url);
  const limit = parseLimit(url, options?.defaultLimit ?? 100, options?.maxLimit ?? 500);
  const cursor = parseEventCursor(url.searchParams.get("cursor"));

  where.push(`occurred_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)`);
  params.push(`-${sinceHours} hours`);

  if (url.searchParams.get("ip") && !ip) return new Response("invalid ip", { status: 400 });
  if (url.searchParams.get("payloadHash") && !payloadHash) return new Response("invalid payload hash", { status: 400 });
  if (destinationPort !== null && (!Number.isInteger(destinationPort) || destinationPort < 0 || destinationPort > 65535)) {
    return new Response("invalid destination port", { status: 400 });
  }
  if (url.searchParams.get("tag") && !tag) return new Response("invalid tag", { status: 400 });
  if (url.searchParams.get("userAgent") && !userAgent) {
    return new Response("invalid user agent", { status: 400 });
  }
  if (url.searchParams.get("confidenceReason") && !confidenceReason) {
    return new Response("invalid confidence reason", { status: 400 });
  }
  if (
    minConfidence !== null &&
    (!Number.isInteger(minConfidence) || minConfidence < 0 || minConfidence > 100)
  ) {
    return new Response("invalid minConfidence", { status: 400 });
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
  if (tag) {
    where.push("EXISTS (SELECT 1 FROM json_each(tags_json) WHERE value = ?)");
    params.push(tag);
  }
  if (userAgent) {
    where.push("user_agent LIKE ? ESCAPE '\\'");
    params.push(userAgent);
  }
  if (confidenceReason) {
    where.push("EXISTS (SELECT 1 FROM json_each(confidence_reasons_json) WHERE value = ?)");
    params.push(confidenceReason);
  }
  if (minConfidence !== null) {
    where.push("confidence >= ?");
    params.push(minConfidence);
  }
  if (hasCredentials === "true") {
    where.push("(has_username = 1 OR has_password = 1)");
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
