import type { PagesCtx } from "../../../_lib/env";
import { buildEventsQuery } from "../../../_lib/eventsQuery";
import { ndjson, urlOf } from "../../../_lib/http";
import { publicEvent, type EventRow } from "../../../_lib/rows";

export const onRequestGet: PagesFunction<PagesCtx["env"]> = async (ctx) => {
  const query = buildEventsQuery(urlOf(ctx.request), { defaultLimit: 1000, maxLimit: 5000 });
  if (query instanceof Response) return query;
  const result = await ctx.env.DB.prepare(query.sql).bind(...query.params).all<EventRow>();
  const lines = result.results.slice(0, query.limit).map((row) => JSON.stringify(publicEvent(row)));
  return ndjson(lines);
};
