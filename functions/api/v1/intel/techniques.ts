import type { PagesCtx } from "../../../_lib/env";
import { mapEventToTechniques, type AttackTechnique } from "../../../_lib/attackMapping";
import { parseJsonList } from "../../../_lib/rows";
import { cachedJson, parseSinceHours, urlOf } from "../../../_lib/http";

interface EventMappingRow {
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

interface TechniqueExampleEvent {
  id: string;
  source_ip: string;
  occurred_at: string;
}

export interface TechniqueAggregate {
  id: string;
  name: string;
  tactic: string;
  url: string;
  count: number;
  example_events: TechniqueExampleEvent[];
  example_ips: string[];
}

const MAX_EXAMPLE_EVENTS = 3;
const MAX_EXAMPLE_IPS = 5;

function eventInput(row: EventMappingRow) {
  return {
    protocol: row.protocol,
    trap: row.trap,
    http_path: row.http_path,
    has_credentials: Boolean(row.has_username || row.has_password),
    confidence_reasons: parseJsonList(row.confidence_reasons_json)
  };
}

function aggregateTechniques(rows: EventMappingRow[]): TechniqueAggregate[] {
  const byId = new Map<
    string,
    {
      technique: AttackTechnique;
      count: number;
      example_events: TechniqueExampleEvent[];
      ipCounts: Map<string, number>;
    }
  >();

  for (const row of rows) {
    const techniques = mapEventToTechniques(eventInput(row));
    for (const technique of techniques) {
      let bucket = byId.get(technique.id);
      if (!bucket) {
        bucket = {
          technique,
          count: 0,
          example_events: [],
          ipCounts: new Map()
        };
        byId.set(technique.id, bucket);
      }

      bucket.count += 1;
      bucket.ipCounts.set(row.source_ip, (bucket.ipCounts.get(row.source_ip) ?? 0) + 1);

      if (bucket.example_events.length < MAX_EXAMPLE_EVENTS) {
        bucket.example_events.push({
          id: row.id,
          source_ip: row.source_ip,
          occurred_at: row.occurred_at
        });
      }
    }
  }

  return [...byId.values()]
    .map(({ technique, count, example_events, ipCounts }) => ({
      id: technique.id,
      name: technique.name,
      tactic: technique.tactic,
      url: technique.url,
      count,
      example_events,
      example_ips: [...ipCounts.entries()]
        .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
        .slice(0, MAX_EXAMPLE_IPS)
        .map(([ip]) => ip)
    }))
    .sort((a, b) => b.count - a.count || a.id.localeCompare(b.id));
}

export const onRequestGet: PagesFunction<PagesCtx["env"]> = async (ctx) => {
  const url = urlOf(ctx.request);
  const sinceHours = parseSinceHours(url, 24, 24 * 30);
  const since = `-${sinceHours} hours`;

  const result = await ctx.env.DB.prepare(
    `SELECT id, source_ip, occurred_at, protocol, trap, http_path,
            has_username, has_password, confidence_reasons_json
     FROM events
     WHERE occurred_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
     ORDER BY occurred_at DESC
     LIMIT 5000`
  ).bind(since).all<EventMappingRow>();

  const techniques = aggregateTechniques(result.results);

  return cachedJson({
    sinceHours,
    techniques
  });
};
