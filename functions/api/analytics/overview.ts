import type { PagesCtx } from "../../_lib/env";
import { json, parseSinceHours, urlOf } from "../../_lib/http";
import { fetchOverview, parseOverviewSections } from "../../_lib/overview";
import { FAST_CACHE } from "../../_lib/rollups";

export const onRequestGet: PagesFunction<PagesCtx["env"]> = async (ctx) => {
  const url = urlOf(ctx.request);
  const sinceHours = parseSinceHours(url, 24, 24 * 30);
  const since = `-${sinceHours} hours`;
  const sections = parseOverviewSections(url);

  const payload = await fetchOverview(ctx.env.DB, since, sections);

  return json(payload, FAST_CACHE);
};
