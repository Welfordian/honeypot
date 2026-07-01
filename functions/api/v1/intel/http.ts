import type { PagesCtx } from "../../../_lib/env";
import { cachedJson, parseSinceHours, urlOf } from "../../../_lib/http";
import {
  FAST_CACHE,
  sumRollupCountsWithUniqueIps,
  sumRollupCounts,
  sumRollupTimelineForKeys
} from "../../../_lib/rollups";

interface TrendRow {
  key: string;
  bucket: string;
  count: number;
}

const UA_TRUNCATE = 120;

function truncateUserAgent(value: string): string {
  if (value.length <= UA_TRUNCATE) return value;
  return `${value.slice(0, UA_TRUNCATE - 1)}…`;
}

function groupProbeTrends(rows: TrendRow[]) {
  const byPath = new Map<string, Array<{ bucket: string; count: number }>>();
  for (const row of rows) {
    const timeline = byPath.get(row.key) ?? [];
    timeline.push({ bucket: row.bucket, count: row.count });
    byPath.set(row.key, timeline);
  }
  return Array.from(byPath.entries()).map(([key, timeline]) => ({
    key,
    timeline: timeline.sort((a, b) => a.bucket.localeCompare(b.bucket))
  }));
}

export const onRequestGet: PagesFunction<PagesCtx["env"]> = async (ctx) => {
  const url = urlOf(ctx.request);
  const sinceHours = parseSinceHours(url, 24, 24 * 30);
  const since = `-${sinceHours} hours`;

  const [topPaths, topUserAgents, topExploitPaths, credentialPaths] = await Promise.all([
    sumRollupCountsWithUniqueIps(ctx.env.DB, "http_path", since, 20),
    sumRollupCountsWithUniqueIps(ctx.env.DB, "http_user_agent", since, 20),
    sumRollupCounts(ctx.env.DB, "http_exploit_path", since, 5),
    sumRollupCountsWithUniqueIps(ctx.env.DB, "http_credential_path", since, 20)
  ]);

  const exploitPathKeys = topExploitPaths.map((row) => row.key);
  const trendRows =
    exploitPathKeys.length > 0
      ? await sumRollupTimelineForKeys(ctx.env.DB, "http_exploit_path", exploitPathKeys, since)
      : [];
  const probeTrends = groupProbeTrends(trendRows);

  return cachedJson(
    {
      topPaths,
      topUserAgents: topUserAgents.map((row) => ({
        ...row,
        key: truncateUserAgent(row.key)
      })),
      probeTrends,
      credentialPaths
    },
    FAST_CACHE
  );
};
