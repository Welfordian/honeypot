export interface Env {
  DB: D1Database;
  EVENTS_BUCKET: R2Bucket;
  PUBLIC_SITE_ORIGIN?: string;
  GREYNOISE_API_KEY?: string;
  VIRUSTOTAL_API_KEY?: string;
  INDEXER_URL?: string;
  INDEXER_ADMIN_TOKEN?: string;
  RESEARCHER_API_TOKEN?: string;
  SUPPRESSED_SOURCE_IPS?: string;
}

export type PagesCtx = EventContext<Env, string, Record<string, string | string[]>>;
