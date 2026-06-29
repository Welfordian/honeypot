import { z } from "zod";

const TCP_TRAPS_CONFIG_SCHEMA = z.object({
  SENSOR_ID: z.string().default("tcp-traps-1"),
  COLLECTOR_URL: z.string().url().default("http://127.0.0.1:3100/internal/ingest/events"),
  INGEST_HMAC_SECRET: z.string().min(16).default("dev-only-change-this-ingest-secret"),
  TCP_TRAP_HOST: z.string().default("0.0.0.0"),
  MAX_PAYLOAD_BYTES: z.coerce.number().int().min(256).max(65536).default(4096)
});

export type TcpTrapsConfig = z.infer<typeof TCP_TRAPS_CONFIG_SCHEMA>;

export function loadTcpTrapsConfig(): TcpTrapsConfig {
  return TCP_TRAPS_CONFIG_SCHEMA.parse(process.env);
}
