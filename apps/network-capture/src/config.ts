import { z } from "zod";

function csv(value: string): string[] {
  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

const NETWORK_CAPTURE_CONFIG_SCHEMA = z.object({
  SENSOR_ID: z.string().default("desktopc-network-1"),
  INGEST_HMAC_SECRET: z.string().min(16).default("dev-only-change-this-ingest-secret"),
  COLLECTOR_URL: z.string().url().default("http://127.0.0.1:3100/internal/ingest/events"),
  CLOUDFLARE_PCAP_INGEST_URL: z.string().url().default("http://127.0.0.1:8787/internal/ingest/pcap"),
  CAPTURE_INTERFACE: z.string().default("enp1s0"),
  PUBLIC_IP: z.string().default("203.0.113.20"),
  SUPPRESSED_SOURCE_IPS: z.string().default("203.0.113.10").transform(csv),
  ADMIN_SSH_PORT: z.coerce.number().int().min(1).max(65535).default(22222),
  GENERIC_BANNER_PORT: z.coerce.number().int().min(1024).max(65535).default(65000),
  PCAP_SPOOL_DIR: z.string().default("/var/spool/honeypot-capture"),
  PCAP_ROTATE_SECONDS: z.coerce.number().int().min(15).max(3600).default(60),
  PCAP_MAX_MB: z.coerce.number().int().min(1).max(100).default(8),
  PCAP_UPLOAD_MIN_AGE_MS: z.coerce.number().int().min(1000).max(120000).default(7000),
  PCAP_MAX_SPOOL_BYTES: z.coerce.number().int().min(1024 * 1024).max(1024 * 1024 * 1024).default(256 * 1024 * 1024),
  INGEST_TIMEOUT_MS: z.coerce.number().int().min(1000).max(60000).default(8000),
  INGEST_CONCURRENCY: z.coerce.number().int().min(1).max(32).default(4),
  INGEST_QUEUE_MAX: z.coerce.number().int().min(10).max(50000).default(5000),
  METADATA_DETAIL_LIMIT_PER_KEY: z.coerce.number().int().min(1).max(1000).default(25),
  METADATA_AGGREGATE_FLUSH_MS: z.coerce.number().int().min(5000).max(300000).default(30000),
  MAX_BANNER_BYTES: z.coerce.number().int().min(16).max(4096).default(512),
  BANNER_CLOSE_AFTER_MS: z.coerce.number().int().min(250).max(30000).default(5000)
});

export type NetworkCaptureConfig = z.infer<typeof NETWORK_CAPTURE_CONFIG_SCHEMA>;

export function loadNetworkCaptureConfig(): NetworkCaptureConfig {
  const config = NETWORK_CAPTURE_CONFIG_SCHEMA.parse(process.env);
  if (config.SUPPRESSED_SOURCE_IPS.length === 0) {
    throw new Error("At least one SUPPRESSED_SOURCE_IPS value is required.");
  }
  if (config.SUPPRESSED_SOURCE_IPS.includes(config.PUBLIC_IP)) {
    throw new Error("PUBLIC_IP must not be in SUPPRESSED_SOURCE_IPS.");
  }
  return config;
}
