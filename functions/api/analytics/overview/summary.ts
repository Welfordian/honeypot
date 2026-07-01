import type { PagesCtx } from "../../../_lib/env";
import { json, parseSinceHours, urlOf } from "../../../_lib/http";
import { FAST_CACHE } from "../../../_lib/rollups";
import { fetchOverview, SUMMARY_OVERVIEW_SECTIONS } from "../../../_lib/overview";

export const onRequestGet: PagesFunction<PagesCtx["env"]> = async (ctx) => {
  const url = urlOf(ctx.request);
  const sinceHours = parseSinceHours(url, 24, 24 * 30);
  const since = `-${sinceHours} hours`;

  const payload = await fetchOverview(ctx.env.DB, since, SUMMARY_OVERVIEW_SECTIONS);

  return json(
    {
      totals: payload.totals,
      sensors: payload.sensors
    },
    FAST_CACHE
  );
};
