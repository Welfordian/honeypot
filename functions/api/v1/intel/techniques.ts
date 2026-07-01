import type { PagesCtx } from "../../../_lib/env";
import { attackTechniqueIds, techniqueById } from "../../../_lib/attackMapping";
import { cachedJson, parseSinceHours, urlOf } from "../../../_lib/http";
import { parseJsonList } from "../../../_lib/rows";
import { exampleIpsForRollupKey, FAST_CACHE, sumRollupCounts } from "../../../_lib/rollups";

const MAX_EXAMPLE_EVENTS = 3;
const MAX_EXAMPLE_IPS = 5;

interface TechniqueEventRow {
  id: string;
  source_ip: string;
  occurred_at: string;
  protocol: string;
  trap: string;
  http_path: string | null;
  has_username: number;
  has_password: number;
  confidence_reasons_json: string;
}

function eventMatchesTechnique(row: TechniqueEventRow, techniqueId: string): boolean {
  return attackTechniqueIds({
    protocol: row.protocol,
    trap: row.trap,
    http_path: row.http_path,
    has_credentials: Boolean(row.has_username || row.has_password),
    confidence_reasons: parseJsonList(row.confidence_reasons_json)
  }).includes(techniqueId);
}

async function exampleEventsForTechnique(
  db: D1Database,
  techniqueId: string,
  since: string,
  exampleIps: string[]
): Promise<Array<{ id: string; source_ip: string; occurred_at: string }>> {
  if (!exampleIps.length) return [];

  const placeholders = exampleIps.map(() => "?").join(", ");
  const result = await db
    .prepare(
      `SELECT id, source_ip, occurred_at, protocol, trap, http_path,
              has_username, has_password, confidence_reasons_json
       FROM events
       WHERE occurred_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
         AND source_ip IN (${placeholders})
       ORDER BY occurred_at DESC
       LIMIT 50`
    )
    .bind(since, ...exampleIps)
    .all<TechniqueEventRow>();

  const examples: Array<{ id: string; source_ip: string; occurred_at: string }> = [];
  for (const row of result.results) {
    if (!eventMatchesTechnique(row, techniqueId)) continue;
    examples.push({ id: row.id, source_ip: row.source_ip, occurred_at: row.occurred_at });
    if (examples.length >= MAX_EXAMPLE_EVENTS) break;
  }
  return examples;
}

export const onRequestGet: PagesFunction<PagesCtx["env"]> = async (ctx) => {
  const url = urlOf(ctx.request);
  const sinceHours = parseSinceHours(url, 24, 24 * 30);
  const since = `-${sinceHours} hours`;

  const counts = await sumRollupCounts(ctx.env.DB, "attack_technique", since, 50);
  const techniques = await Promise.all(
    counts.map(async (row) => {
      const technique = techniqueById(row.key);
      if (!technique) return null;

      const example_ips = await exampleIpsForRollupKey(
        ctx.env.DB,
        "attack_technique",
        row.key,
        since,
        MAX_EXAMPLE_IPS
      );
      const example_events = await exampleEventsForTechnique(
        ctx.env.DB,
        row.key,
        since,
        example_ips
      );

      return {
        id: technique.id,
        name: technique.name,
        tactic: technique.tactic,
        url: technique.url,
        count: row.count,
        example_events,
        example_ips
      };
    })
  );

  return cachedJson(
    {
      sinceHours,
      techniques: techniques.filter((row): row is NonNullable<typeof row> => row !== null)
    },
    FAST_CACHE
  );
};
