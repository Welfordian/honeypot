import type { PagesCtx } from "../../../_lib/env";
import { badRequest, cachedJson, token, urlOf } from "../../../_lib/http";

const DIMENSIONS = new Set(["tag", "confidenceReason", "trap"]);

function parseHours(url: URL, name: string, fallback: number): number | Response {
  const raw = Number(url.searchParams.get(name) ?? fallback);
  if (!Number.isFinite(raw)) return badRequest(`Invalid ${name}.`);
  return Math.max(1, Math.min(24 * 30, Math.trunc(raw)));
}

async function countForWindow(
  db: D1Database,
  dimension: string,
  key: string,
  hours: number
): Promise<number> {
  const since = `-${hours} hours`;
  if (dimension === "trap") {
    const row = await db
      .prepare(
        `SELECT COUNT(*) AS count
         FROM events
         WHERE trap = ?
           AND occurred_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)`
      )
      .bind(key, since)
      .first<{ count: number }>();
    return row?.count ?? 0;
  }

  const column = dimension === "tag" ? "tags_json" : "confidence_reasons_json";
  const row = await db
    .prepare(
      `SELECT COUNT(*) AS count
       FROM events, json_each(${column})
       WHERE value = ?
         AND occurred_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)`
    )
    .bind(key, since)
    .first<{ count: number }>();
  return row?.count ?? 0;
}

export const onRequestGet: PagesFunction<PagesCtx["env"]> = async (ctx) => {
  const url = urlOf(ctx.request);
  const dimension = url.searchParams.get("dimension") ?? "tag";
  const key =
    dimension === "trap"
      ? token(url.searchParams.get("key"), 120)
      : token(url.searchParams.get("key"), dimension === "tag" ? 80 : 48);

  if (!DIMENSIONS.has(dimension)) {
    return badRequest("dimension must be tag, confidenceReason, or trap.");
  }
  if (!key) return badRequest("key is required.");

  const hoursA = parseHours(url, "hoursA", 24);
  if (hoursA instanceof Response) return hoursA;
  const hoursB = parseHours(url, "hoursB", 168);
  if (hoursB instanceof Response) return hoursB;

  const [countA, countB] = await Promise.all([
    countForWindow(ctx.env.DB, dimension, key, hoursA),
    countForWindow(ctx.env.DB, dimension, key, hoursB)
  ]);

  return cachedJson({
    dimension,
    key,
    windowA: { hours: hoursA, count: countA },
    windowB: { hours: hoursB, count: countB }
  });
};
