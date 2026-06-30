import type { PagesCtx } from "../../../_lib/env";
import { buildEventsQuery } from "../../../_lib/eventsQuery";
import { json, urlOf } from "../../../_lib/http";
import { publicEvent, type EventRow } from "../../../_lib/rows";

const EXPORT_LIMIT = 5000;

export const onRequestGet: PagesFunction<PagesCtx["env"]> = async (ctx) => {
  const url = urlOf(ctx.request);
  url.searchParams.delete("cursor");
  url.searchParams.set("limit", String(EXPORT_LIMIT));

  const query = buildEventsQuery(url);
  if (query instanceof Response) return query;

  const result = await ctx.env.DB.prepare(query.sql).bind(...query.params).all<EventRow>();
  const events = result.results.slice(0, EXPORT_LIMIT).map(publicEvent);
  const exportedAt = new Date().toISOString();

  const headers = new Headers();
  headers.set("content-type", "application/json; charset=utf-8");
  headers.set("content-disposition", 'attachment; filename="honeypot-search-export.json"');
  headers.set("cache-control", "no-store");
  headers.set("x-content-type-options", "nosniff");

  return json(
    {
      exported_at: exportedAt,
      limit: EXPORT_LIMIT,
      count: events.length,
      events
    },
    { headers }
  );
};
