import { z } from "zod";

const LOG_SHIPPER_CONFIG_SCHEMA = z.object({
  SENSOR_ID: z.string().default("cowrie-1"),
  COLLECTOR_URL: z.string().url().default("http://r2-writer:3100/internal/ingest/events"),
  INGEST_HMAC_SECRET: z.string().min(16).default("dev-only-change-this-ingest-secret"),
  LOG_FILE: z.string().default("/cowrie/var/log/cowrie/cowrie.json"),
  START_AT_BEGINNING: z.coerce.boolean().default(false),
  MAX_PAYLOAD_BYTES: z.coerce.number().int().min(256).max(65536).default(4096)
});

export type LogShipperConfig = z.infer<typeof LOG_SHIPPER_CONFIG_SCHEMA>;

export function loadLogShipperConfig(): LogShipperConfig {
  return LOG_SHIPPER_CONFIG_SCHEMA.parse(process.env);
}
