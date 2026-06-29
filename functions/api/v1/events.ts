import type { PagesCtx } from "../../_lib/env";
import { cachedJson, urlOf } from "../../_lib/http";
import { buildEventsQuery } from "../../_lib/eventsQuery";
import { publicEventPage, type EventRow } from "../../_lib/rows";

export const onRequestGet: PagesFunction<PagesCtx["env"]> = async (ctx) => {
  const query = buildEventsQuery(urlOf(ctx.request));
  if (query instanceof Response) return query;
  const result = await ctx.env.DB.prepare(query.sql).bind(...query.params).all<EventRow>();
  return cachedJson(publicEventPage(result.results, query.limit));
};
