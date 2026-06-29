import type { FastifyRequest } from "fastify";
import { verifySignature } from "@honeypot/shared";
import type { R2WriterConfig } from "./config.js";

const MAX_CLOCK_SKEW_MS = 10 * 60 * 1000;

export function verifyIngestRequest(config: R2WriterConfig, request: FastifyRequest): { ok: true } | { ok: false; error: string } {
  const timestamp = String(request.headers["x-hp-timestamp"] ?? "");
  const signature = String(request.headers["x-hp-signature"] ?? "");
  const rawBody = (request as FastifyRequest & { rawBody?: Buffer }).rawBody;

  if (!timestamp || !signature || !rawBody) return { ok: false, error: "missing_signature" };
  const parsedTimestamp = Date.parse(timestamp);
  if (!Number.isFinite(parsedTimestamp)) return { ok: false, error: "invalid_timestamp" };
  if (Math.abs(Date.now() - parsedTimestamp) > MAX_CLOCK_SKEW_MS) return { ok: false, error: "timestamp_outside_window" };
  if (!verifySignature(config.INGEST_HMAC_SECRET, timestamp, rawBody, signature)) return { ok: false, error: "invalid_signature" };
  return { ok: true };
}
