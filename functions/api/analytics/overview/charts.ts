import type { PagesCtx } from "../../../_lib/env";
import { json, parseSinceHours, urlOf } from "../../../_lib/http";
import { FAST_CACHE } from "../../../_lib/rollups";
import { CHART_OVERVIEW_SECTIONS, fetchOverview } from "../../../_lib/overview";

export const onRequestGet: PagesFunction<PagesCtx["env"]> = async (ctx) => {
  const url = urlOf(ctx.request);
  const sinceHours = parseSinceHours(url, 24, 24 * 30);
  const since = `-${sinceHours} hours`;

  const payload = await fetchOverview(ctx.env.DB, since, CHART_OVERVIEW_SECTIONS);

  return json(
    {
      timeline: payload.timeline,
      topIps: payload.topIps,
      topProtocols: payload.topProtocols,
      topTraps: payload.topTraps,
      topSeverities: payload.topSeverities
    },
    FAST_CACHE
  );
};
