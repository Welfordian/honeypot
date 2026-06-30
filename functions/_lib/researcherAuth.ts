import type { D1Database } from "@cloudflare/workers-types";
import { json } from "./http";

export interface ResearcherEnv {
  RESEARCHER_API_TOKEN?: string;
  SUPPRESSED_SOURCE_IPS?: string;
  DB: D1Database;
}

export function researcherTokenFromRequest(request: Request): string | null {
  const auth = request.headers.get("authorization");
  if (auth?.startsWith("Bearer ")) {
    const token = auth.slice("Bearer ".length).trim();
    if (token) return token;
  }
  const header = request.headers.get("x-researcher-token");
  return header?.trim() || null;
}

export function requireResearcherToken(request: Request, env: ResearcherEnv): Response | null {
  if (!env.RESEARCHER_API_TOKEN) {
    return json({ error: "researcher_access_disabled" }, { status: 503 });
  }
  const token = researcherTokenFromRequest(request);
  if (!token || token !== env.RESEARCHER_API_TOKEN) {
    return json({ error: "unauthorized" }, { status: 401 });
  }
  return null;
}

function normalizeIp(ip: string): string {
  return ip.startsWith("::ffff:") ? ip.slice(7) : ip;
}

function suppressedSourceIps(env?: Pick<ResearcherEnv, "SUPPRESSED_SOURCE_IPS">): Set<string> {
  return new Set(
    (env?.SUPPRESSED_SOURCE_IPS ?? "")
      .split(",")
      .map((ip) => normalizeIp(ip.trim()))
      .filter(Boolean)
  );
}

export function clientIpFromRequest(
  request: Request,
  env?: Pick<ResearcherEnv, "SUPPRESSED_SOURCE_IPS">
): string | null {
  const ip =
    request.headers.get("CF-Connecting-IP") ??
    request.headers.get("X-Forwarded-For")?.split(",")[0]?.trim() ??
    null;
  if (!ip) return null;

  const normalized = normalizeIp(ip);
  return suppressedSourceIps(env).has(normalized) ? null : normalized;
}

export async function logResearcherAccess(
  db: D1Database,
  entry: {
    resource_type: string;
    resource_id: string;
    client_ip?: string | null;
    user_agent?: string | null;
  }
): Promise<void> {
  const id = crypto.randomUUID();
  await db
    .prepare(
      "INSERT INTO researcher_access_log (id, accessed_at, resource_type, resource_id, client_ip, user_agent) VALUES (?, ?, ?, ?, ?, ?)"
    )
    .bind(
      id,
      new Date().toISOString(),
      entry.resource_type,
      entry.resource_id,
      entry.client_ip ?? null,
      entry.user_agent ?? null
    )
    .run();
}
