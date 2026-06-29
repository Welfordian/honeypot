import { z } from "zod";

const R2_WRITER_CONFIG_SCHEMA = z.object({
  NODE_ENV: z.string().default("development"),
  WRITER_HOST: z.string().default("0.0.0.0"),
  WRITER_PORT: z.coerce.number().int().min(1).max(65535).default(3100),
  INGEST_HMAC_SECRET: z.string().min(16).default("dev-only-change-this-ingest-secret"),
  CLOUDFLARE_INGEST_URL: z.string().url().default("http://127.0.0.1:8787/internal/ingest/events"),
  UPSTREAM_TIMEOUT_MS: z.coerce.number().int().min(1000).max(30000).default(10000),
  MAX_PAYLOAD_BYTES: z.coerce.number().int().min(1024).max(1024 * 1024).default(32768)
});

export type R2WriterConfig = z.infer<typeof R2_WRITER_CONFIG_SCHEMA>;

export function loadConfig(): R2WriterConfig {
  const config = R2_WRITER_CONFIG_SCHEMA.parse(process.env);
  if (config.NODE_ENV === "production" && config.INGEST_HMAC_SECRET === "dev-only-change-this-ingest-secret") {
    throw new Error("Production requires a unique INGEST_HMAC_SECRET.");
  }
  return config;
}
