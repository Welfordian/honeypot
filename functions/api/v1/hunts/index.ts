import type { PagesCtx } from "../../../_lib/env";
import { cachedJson } from "../../../_lib/http";

interface HuntRuleRow {
  id: string;
  name: string;
  enabled: number;
  min_confidence: number;
  trap: string | null;
  protocol: string | null;
  tag: string | null;
  has_credentials: number | null;
  created_at: string;
  updated_at: string;
}

export const onRequestGet: PagesFunction<PagesCtx["env"]> = async (ctx) => {
  const rows = await ctx.env.DB.prepare(
    "SELECT id, name, enabled, min_confidence, trap, protocol, tag, has_credentials, created_at, updated_at FROM hunt_rules WHERE enabled = 1 ORDER BY name ASC"
  ).all<HuntRuleRow>();

  return cachedJson({
    hunts: rows.results.map((row) => ({
      id: row.id,
      name: row.name,
      min_confidence: row.min_confidence,
      trap: row.trap,
      protocol: row.protocol,
      tag: row.tag,
      has_credentials: row.has_credentials === null ? null : Boolean(row.has_credentials),
      created_at: row.created_at,
      updated_at: row.updated_at
    }))
  });
};
