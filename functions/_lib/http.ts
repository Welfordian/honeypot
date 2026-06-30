export function json(body: unknown, init: ResponseInit = {}): Response {
  const headers = new Headers(init.headers);
  headers.set("content-type", "application/json; charset=utf-8");
  headers.set("cache-control", headers.get("cache-control") ?? "no-store");
  headers.set("x-content-type-options", "nosniff");
  return new Response(JSON.stringify(body), { ...init, headers });
}

export function cachedJson(body: unknown, init: ResponseInit = {}): Response {
  const headers = new Headers(init.headers);
  headers.set("cache-control", "public, max-age=30, stale-while-revalidate=120");
  return json(body, { ...init, headers });
}

export function text(body: string, contentType = "text/plain; charset=utf-8", init: ResponseInit = {}): Response {
  const headers = new Headers(init.headers);
  headers.set("content-type", contentType);
  headers.set("cache-control", headers.get("cache-control") ?? "no-store");
  headers.set("x-content-type-options", "nosniff");
  return new Response(body, { ...init, headers });
}

export function badRequest(message: string): Response {
  return json({ error: "bad_request", message }, { status: 400 });
}

export function urlOf(request: Request): URL {
  return new URL(request.url);
}

export function parseLimit(url: URL, fallback = 100, max = 500): number {
  const raw = Number(url.searchParams.get("limit") ?? fallback);
  if (!Number.isFinite(raw)) return fallback;
  return Math.max(1, Math.min(max, Math.trunc(raw)));
}

export function parseOffset(url: URL): number {
  const raw = Number(url.searchParams.get("offset") ?? 0);
  if (!Number.isFinite(raw)) return 0;
  return Math.max(0, Math.trunc(raw));
}

export function parseSinceHours(url: URL, fallback = 24, max = 24 * 30): number {
  const raw = Number(url.searchParams.get("sinceHours") ?? fallback);
  if (!Number.isFinite(raw)) return fallback;
  return Math.max(1, Math.min(max, Math.trunc(raw)));
}

export function publicIp(value: string | null): string | null {
  if (!value) return null;
  const trimmed = value.trim();
  if (trimmed.length > 64) return null;
  return /^[0-9a-fA-F:.]+$/.test(trimmed) ? trimmed : null;
}

export function publicSha256(value: string | null): string | null {
  if (!value) return null;
  const trimmed = value.trim().toLowerCase();
  return /^[a-f0-9]{64}$/.test(trimmed) ? trimmed : null;
}

export interface EventCursor {
  occurredAt: string;
  id: string;
}

export function parseEventCursor(value: string | null): EventCursor | Response | null {
  if (!value) return null;
  const [occurredAt, id, extra] = value.split("|");
  if (extra !== undefined || !occurredAt || !id) return badRequest("Invalid cursor.");
  if (!Number.isFinite(Date.parse(occurredAt))) return badRequest("Invalid cursor.");
  if (!/^[A-Za-z0-9_.:-]{1,120}$/.test(id)) return badRequest("Invalid cursor.");
  return { occurredAt, id };
}

export function token(value: string | null, max = 120): string | null {
  if (!value) return null;
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > max) return null;
  return /^[A-Za-z0-9_.-]+$/.test(trimmed) ? trimmed : null;
}
