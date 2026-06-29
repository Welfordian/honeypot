import { z } from "zod";

const TRAP_CONFIG_SCHEMA = z.object({
  SENSOR_ID: z.string().default("web-trap-1"),
  COLLECTOR_URL: z.string().url().default("http://127.0.0.1:3100/internal/ingest/events"),
  INGEST_HMAC_SECRET: z.string().min(16).default("dev-only-change-this-ingest-secret"),
  TRAP_HTTP_HOST: z.string().default("0.0.0.0"),
  TRAP_HTTP_PORT: z.coerce.number().int().min(1).max(65535).default(8080),
  TRAP_HTTPS_PORT: z.coerce.number().int().min(1).max(65535).default(8443),
  TRAP_TLS_KEY_PATH: z.string().optional(),
  TRAP_TLS_CERT_PATH: z.string().optional(),
  MAX_PAYLOAD_BYTES: z.coerce.number().int().min(1024).max(1024 * 1024).default(32768)
});

export type TrapConfig = z.infer<typeof TRAP_CONFIG_SCHEMA>;

export function loadTrapConfig(): TrapConfig {
  return TRAP_CONFIG_SCHEMA.parse(process.env);
}
