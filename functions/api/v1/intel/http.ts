import type { PagesCtx } from "../../../_lib/env";
import { cachedJson, parseSinceHours, urlOf } from "../../../_lib/http";

interface PathRow {
  key: string;
  count: number;
  unique_ips: number;
}

interface TrendRow {
  key: string;
  bucket: string;
  count: number;
}

const HTTP_WHERE = `protocol IN ('http', 'https')
  AND http_path IS NOT NULL
  AND http_path != ''`;

const EXPLOIT_PATH_WHERE = `(
  http_path LIKE '%../%' ESCAPE '\\'
  OR http_path LIKE '%2e%2e%' ESCAPE '\\'
  OR http_path LIKE '%cgi-bin%' ESCAPE '\\'
  OR http_path LIKE '%eval(%' ESCAPE '\\'
  OR http_path LIKE '%base64_decode%' ESCAPE '\\'
  OR lower(http_path) LIKE '%select%from%' ESCAPE '\\'
  OR lower(http_path) LIKE '%union%select%' ESCAPE '\\'
  OR http_path LIKE '%cmd=%' ESCAPE '\\'
  OR http_path LIKE '%exec=%' ESCAPE '\\'
  OR http_path LIKE '%shell%' ESCAPE '\\'
  OR http_path LIKE '%jndi:%' ESCAPE '\\'
  OR http_path LIKE '%struts%' ESCAPE '\\'
  OR http_path LIKE '%thinkphp%' ESCAPE '\\'
  OR http_path LIKE '%boaform%' ESCAPE '\\'
  OR http_path LIKE '%vendor/phpunit%' ESCAPE '\\'
)`;

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
  const timeWhere = `occurred_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)`;

  const [topPaths, topUserAgents, topExploitPaths, credentialPaths] = await Promise.all([
    ctx.env.DB.prepare(
      `SELECT http_path AS key, COUNT(*) AS count, COUNT(DISTINCT source_ip) AS unique_ips
       FROM events
       WHERE ${timeWhere}
         AND ${HTTP_WHERE}
       GROUP BY http_path
       ORDER BY count DESC
       LIMIT 20`
    ).bind(since).all<PathRow>(),
    ctx.env.DB.prepare(
      `SELECT user_agent AS key, COUNT(*) AS count, COUNT(DISTINCT source_ip) AS unique_ips
       FROM events
       WHERE ${timeWhere}
         AND ${HTTP_WHERE}
         AND user_agent IS NOT NULL
         AND user_agent != ''
       GROUP BY user_agent
       ORDER BY count DESC
       LIMIT 20`
    ).bind(since).all<PathRow>(),
    ctx.env.DB.prepare(
      `SELECT http_path AS key, COUNT(*) AS count
       FROM events
       WHERE ${timeWhere}
         AND ${HTTP_WHERE}
         AND ${EXPLOIT_PATH_WHERE}
       GROUP BY http_path
       ORDER BY count DESC
       LIMIT 5`
    ).bind(since).all<{ key: string; count: number }>(),
    ctx.env.DB.prepare(
      `SELECT http_path AS key, COUNT(*) AS count, COUNT(DISTINCT source_ip) AS unique_ips
       FROM events
       WHERE ${timeWhere}
         AND ${HTTP_WHERE}
         AND (has_username = 1 OR has_password = 1)
       GROUP BY http_path
       ORDER BY count DESC
       LIMIT 20`
    ).bind(since).all<PathRow>()
  ]);

  const exploitPathKeys = topExploitPaths.results.map((row) => row.key);
  let probeTrends: ReturnType<typeof groupProbeTrends> = [];

  if (exploitPathKeys.length > 0) {
    const placeholders = exploitPathKeys.map(() => "?").join(", ");
    const trendRows = await ctx.env.DB.prepare(
      `SELECT http_path AS key,
              substr(occurred_at, 1, 13) || ':00:00.000Z' AS bucket,
              COUNT(*) AS count
       FROM events
       WHERE ${timeWhere}
         AND ${HTTP_WHERE}
         AND http_path IN (${placeholders})
       GROUP BY http_path, bucket
       ORDER BY bucket ASC`
    ).bind(since, ...exploitPathKeys).all<TrendRow>();
    probeTrends = groupProbeTrends(trendRows.results);
  }

  return cachedJson({
    topPaths: topPaths.results,
    topUserAgents: topUserAgents.results.map((row) => ({
      ...row,
      key: truncateUserAgent(row.key)
    })),
    probeTrends,
    credentialPaths: credentialPaths.results
  });
};
