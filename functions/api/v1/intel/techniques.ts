import type { PagesCtx } from "../../../_lib/env";
import { techniqueById } from "../../../_lib/attackMapping";
import { cachedJson, parseSinceHours, urlOf } from "../../../_lib/http";
import { FAST_CACHE, sumRollupCounts } from "../../../_lib/rollups";

export const onRequestGet: PagesFunction<PagesCtx["env"]> = async (ctx) => {
  const url = urlOf(ctx.request);
  const sinceHours = parseSinceHours(url, 24, 24 * 30);
  const since = `-${sinceHours} hours`;

  const counts = await sumRollupCounts(ctx.env.DB, "attack_technique", since, 50);
  const techniques = counts
    .map((row) => {
      const technique = techniqueById(row.key);
      if (!technique) return null;
      return {
        id: technique.id,
        name: technique.name,
        tactic: technique.tactic,
        url: technique.url,
        count: row.count,
        example_events: [] as Array<{ id: string; source_ip: string; occurred_at: string }>,
        example_ips: [] as string[]
      };
    })
    .filter((row): row is NonNullable<typeof row> => row !== null);

  return cachedJson({ sinceHours, techniques }, FAST_CACHE);
};
