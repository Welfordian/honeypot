import Fastify from "fastify";
import { signBody } from "@honeypot/shared";
import type { R2WriterConfig } from "./config.js";
import { verifyIngestRequest } from "./signature.js";

async function forwardToCloudflare(config: R2WriterConfig, rawBody: Buffer): Promise<{ key?: string; status: number }> {
  const timestamp = new Date().toISOString();
  const signature = signBody(config.INGEST_HMAC_SECRET, timestamp, rawBody);
  const response = await fetch(config.CLOUDFLARE_INGEST_URL, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-hp-timestamp": timestamp,
      "x-hp-signature": signature
    },
    body: rawBody.toString("utf8"),
    signal: AbortSignal.timeout(config.UPSTREAM_TIMEOUT_MS)
  });

  const text = await response.text();
  if (!response.ok) throw new Error(`cloudflare_ingest_${response.status}:${text.slice(0, 300)}`);

  try {
    const parsed = JSON.parse(text) as { key?: string };
    const result: { key?: string; status: number } = { status: response.status };
    if (parsed.key) result.key = parsed.key;
    return result;
  } catch {
    return { status: response.status };
  }
}

export function createServer(config: R2WriterConfig) {
  const app = Fastify({
    logger: true,
    bodyLimit: Math.max(config.MAX_PAYLOAD_BYTES * 2, 65536),
    trustProxy: false
  });

  app.addContentTypeParser("application/json", { parseAs: "buffer" }, (request, body, done) => {
    const rawBody = Buffer.isBuffer(body) ? body : Buffer.from(body);
    (request as typeof request & { rawBody?: Buffer }).rawBody = rawBody;
    try {
      done(null, JSON.parse(rawBody.toString("utf8")));
    } catch (error) {
      done(error as Error);
    }
  });

  app.get("/health", async () => ({ ok: true }));

  app.post("/internal/ingest/events", async (request, reply) => {
    const auth = verifyIngestRequest(config, request);
    if (!auth.ok) return reply.code(401).send({ error: auth.error });

    const rawBody = (request as typeof request & { rawBody?: Buffer }).rawBody;
    if (!rawBody) return reply.code(400).send({ error: "missing_body" });

    const result = await forwardToCloudflare(config, rawBody);
    return reply.code(202).send({ accepted: true, key: result.key, upstreamStatus: result.status });
  });

  return app;
}
