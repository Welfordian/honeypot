import { json } from "./http";

const BLOCKED_HOSTS = new Set([
  "localhost",
  "127.0.0.1",
  "0.0.0.0",
  "::1",
  "metadata.google.internal",
  "metadata.goog"
]);

function parseIpv4(host: string): number[] | null {
  const parts = host.split(".");
  if (parts.length !== 4) return null;
  const octets = parts.map((part) => Number(part));
  if (octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)) return null;
  return octets;
}

function isPrivateOrReservedIpv4(octets: number[]): boolean {
  const [a, b] = octets as [number, number, number, number];
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 0) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  return false;
}

function isPrivateOrReservedIpv6(host: string): boolean {
  const lower = host.toLowerCase();
  return (
    lower === "::1" ||
    lower.startsWith("fe80:") ||
    lower.startsWith("fc") ||
    lower.startsWith("fd") ||
    lower.startsWith("::ffff:127.") ||
    lower.startsWith("::ffff:10.") ||
    lower.startsWith("::ffff:192.168.")
  );
}

export function isBlockedWebhookHost(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (BLOCKED_HOSTS.has(host)) return true;
  if (host.endsWith(".localhost") || host.endsWith(".local")) return true;

  const ipv4 = parseIpv4(host);
  if (ipv4) return isPrivateOrReservedIpv4(ipv4);

  if (host.includes(":")) return isPrivateOrReservedIpv6(host);
  return false;
}

export function validateWebhookUrl(raw: string): URL | Response {
  const trimmed = raw.trim();
  if (!trimmed || trimmed.length > 2048) {
    return json({ error: "invalid_url" }, { status: 400 });
  }

  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return json({ error: "invalid_url" }, { status: 400 });
  }

  if (parsed.protocol !== "https:") {
    return json({ error: "invalid_url", message: "Webhook URLs must use HTTPS." }, { status: 400 });
  }

  if (isBlockedWebhookHost(parsed.hostname)) {
    return json({ error: "invalid_url", message: "Webhook host is not allowed." }, { status: 400 });
  }

  return parsed;
}

export async function postWebhook(
  url: string,
  init: { headers?: Record<string, string>; body: string; timeoutMs?: number }
): Promise<void> {
  const validated = validateWebhookUrl(url);
  if (validated instanceof Response) {
    throw new Error("webhook URL rejected");
  }

  const response = await fetch(validated.toString(), {
    method: "POST",
    ...(init.headers ? { headers: init.headers } : {}),
    body: init.body,
    redirect: "manual",
    signal: AbortSignal.timeout(init.timeoutMs ?? 10_000)
  });

  if (response.status >= 300 && response.status < 400) {
    throw new Error(`webhook redirect blocked: ${response.status}`);
  }
  if (!response.ok) {
    const detail = await response.text().catch(() => "");
    throw new Error(`webhook ${response.status}${detail ? `: ${detail.slice(0, 200)}` : ""}`);
  }
}
