import type { IncomingHttpHeaders } from "node:http";
import type { ServerOptions as HttpsOptions } from "node:https";
import Fastify from "fastify";
import type { HoneypotEvent } from "@honeypot/shared";
import { normalizeIp, parseForwardedIp, safePreview } from "@honeypot/shared";
import type { TrapConfig } from "./config.js";
import { classifyPath } from "./decoys.js";
import { sendEvent } from "./ingest.js";

function headerRecord(headers: IncomingHttpHeaders): Record<string, string | string[]> {
  const result: Record<string, string | string[]> = {};
  for (const [key, value] of Object.entries(headers)) {
    if (value === undefined) continue;
    result[key] = Array.isArray(value) ? value : String(value);
  }
  return result;
}

function queryRecord(query: unknown): Record<string, string | string[]> {
  if (!query || typeof query !== "object") return {};
  const result: Record<string, string | string[]> = {};
  for (const [key, value] of Object.entries(query as Record<string, unknown>)) {
    if (Array.isArray(value)) result[key] = value.map(String);
    else if (value !== undefined) result[key] = String(value);
  }
  return result;
}

function bodyText(body: unknown, maxBytes: number): string | undefined {
  if (body === undefined || body === null) return undefined;
  if (Buffer.isBuffer(body)) return safePreview(body.subarray(0, maxBytes).toString("utf8"), maxBytes);
  if (typeof body === "string") return safePreview(body, maxBytes);
  return safePreview(JSON.stringify(body), maxBytes);
}

function parseBasicAuth(value: string | string[] | undefined): { username?: string; password?: string; kind: string } | undefined {
  const header = Array.isArray(value) ? value[0] : value;
  if (!header?.toLowerCase().startsWith("basic ")) return undefined;
  const decoded = Buffer.from(header.slice(6), "base64").toString("utf8");
  const [username, ...passwordParts] = decoded.split(":");
  const credentials: { username?: string; password?: string; kind: string } = { kind: "basic" };
  if (username) credentials.username = username;
  const password = passwordParts.join(":");
  if (password) credentials.password = password;
  return credentials;
}

function extractCredentials(body: unknown, headers: IncomingHttpHeaders): HoneypotEvent["credentials"] {
  const basic = parseBasicAuth(headers.authorization);
  if (basic) return basic;
  if (!body || typeof body !== "object" || Buffer.isBuffer(body)) return undefined;
  const record = body as Record<string, unknown>;
  const username = record.username ?? record.user ?? record.email ?? record.log ?? record.pma_username;
  const password = record.password ?? record.pass ?? record.pwd ?? record.pma_password;
  const token = record.token ?? record.api_key ?? record.access_token;
  if (!username && !password && !token) return undefined;
  return {
    username: username === undefined ? undefined : String(username),
    password: password === undefined ? undefined : String(password),
    token: token === undefined ? undefined : String(token),
    kind: "form"
  };
}

interface TrapRequest {
  url: string;
  method: string;
  headers: IncomingHttpHeaders;
  body: unknown;
  query: unknown;
  ip?: string | undefined;
  socket: {
    remoteAddress: string | undefined;
    remotePort: number | undefined;
  };
  log: {
    warn(payload: unknown, message?: string): void;
  };
}

interface TrapReply {
  code(status: number): TrapReply;
  header(key: string, value: string): TrapReply;
  send(body: string): Promise<unknown> | unknown;
}

function sourceIp(request: TrapRequest): string {
  const forwarded = parseForwardedIp(request.headers["x-forwarded-for"]);
  return normalizeIp(forwarded || request.ip || request.socket.remoteAddress || "0.0.0.0");
}

export function createTrapServer(config: TrapConfig, mode: "http" | "https" = "http", httpsOptions?: HttpsOptions) {
  const app = Fastify({
    logger: true,
    bodyLimit: config.MAX_PAYLOAD_BYTES,
    trustProxy: false,
    ...(httpsOptions ? { https: httpsOptions } : {})
  } as never);

  app.addContentTypeParser("application/x-www-form-urlencoded", { parseAs: "string" }, (_request, body, done) => {
    const params = new URLSearchParams(Buffer.isBuffer(body) ? body.toString("utf8") : body);
    const parsed: Record<string, string> = {};
    for (const [key, value] of params.entries()) parsed[key] = value;
    done(null, parsed);
  });

  app.addContentTypeParser("*", { parseAs: "buffer" }, (_request, body, done) => {
    done(null, body);
  });

  app.all("/", async (request, reply) => handler(request, reply));
  app.all("/*", async (request, reply) => handler(request, reply));

  async function handler(request: TrapRequest, reply: TrapReply) {
    const tls = mode === "https";
    const url = new URL(request.url, `${tls ? "https" : "http"}://honeypot.invalid`);
    const decoy = classifyPath(url.pathname);
    const text = bodyText(request.body, config.MAX_PAYLOAD_BYTES);
    const event: HoneypotEvent = {
      sensorId: config.SENSOR_ID,
      trap: decoy.trap,
      protocol: tls ? "https" : "http",
      source: {
        ip: sourceIp(request),
        port: request.socket.remotePort
      },
      destination: {
        port: tls ? 443 : 80
      },
      http: {
        method: request.method,
        path: url.pathname,
        status: decoy.status,
        headers: headerRecord(request.headers),
        query: queryRecord(request.query),
        userAgent: request.headers["user-agent"] ? String(request.headers["user-agent"]) : undefined
      },
      credentials: extractCredentials(request.body, request.headers),
      payload: text ? { text, mimeGuess: String(request.headers["content-type"] ?? "text/plain") } : undefined,
      tags: decoy.tags,
      raw: {
        url: request.url,
        tls,
        host: request.headers.host
      }
    };

    sendEvent(config, event).catch((error) => {
      request.log.warn({ error }, "failed to send honeypot event");
    });

    return reply
      .code(decoy.status)
      .header("content-type", decoy.contentType)
      .header("x-robots-tag", "noindex")
      .send(decoy.body);
  }

  return app;
}
