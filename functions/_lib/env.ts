export interface Env {
  DB: D1Database;
  EVENTS_BUCKET: R2Bucket;
  PUBLIC_SITE_ORIGIN?: string;
}

export type PagesCtx = EventContext<Env, string, Record<string, string | string[]>>;
