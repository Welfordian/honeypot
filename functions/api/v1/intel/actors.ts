import type { PagesCtx } from "../../../_lib/env";
import { relatedIpsAmongActors } from "../../../_lib/actorRelated";
import { cachedJson, parseLimit, parseSinceHours, urlOf } from "../../../_lib/http";
import { FAST_CACHE, topAttackersInWindow } from "../../../_lib/rollups";

const SINCE_CLAUSE = `occurred_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)`;
const UA_PREFIX_LEN = 32;

interface ActorBase {
  source_ip: string;
  event_count: number;
  confidence: number;
  first_seen: string;
  last_seen: string;
}

interface TrapSeqRow {
  source_ip: string;
  trap: string;
}

interface ProtocolRow {
  source_ip: string;
  protocol: string;
}

interface TagRow {
  source_ip: string;
  tag: string;
}

interface PayloadRow {
  source_ip: string;
  payload_sha256: string;
  cnt: number;
}

interface UaRow {
  source_ip: string;
  ua_prefix: string;
}

function groupBy<T>(rows: T[], keyFn: (row: T) => string): Map<string, T[]> {
  const map = new Map<string, T[]>();
  for (const row of rows) {
    const key = keyFn(row);
    const list = map.get(key);
    if (list) list.push(row);
    else map.set(key, [row]);
  }
  return map;
}

export const onRequestGet: PagesFunction<PagesCtx["env"]> = async (ctx) => {
  const url = urlOf(ctx.request);
  const sinceHours = parseSinceHours(url, 168, 24 * 30);
  const limit = parseLimit(url, 20, 50);
  const since = `-${sinceHours} hours`;

  const topProfiles = await topAttackersInWindow(ctx.env.DB, since, limit);
  const bases: ActorBase[] = topProfiles.map((row) => ({
    source_ip: row.key,
    event_count: row.count,
    confidence: row.max_confidence,
    first_seen: row.first_seen,
    last_seen: row.last_seen
  }));

  if (bases.length === 0) {
    return cachedJson({ actors: [] }, FAST_CACHE);
  }

  const ips = bases.map((row) => row.source_ip);
  const placeholders = ips.map(() => "?").join(",");

  const [trapSeq, protocols, tags, payloads, uaPrefixes] = await Promise.all([
    ctx.env.DB.prepare(
      `SELECT source_ip, trap
       FROM events
       WHERE ${SINCE_CLAUSE} AND source_ip IN (${placeholders})
       GROUP BY source_ip, trap
       ORDER BY source_ip, MIN(occurred_at) ASC`
    )
      .bind(since, ...ips)
      .all<TrapSeqRow>(),
    ctx.env.DB.prepare(
      `SELECT source_ip, protocol
       FROM events
       WHERE ${SINCE_CLAUSE} AND source_ip IN (${placeholders})
       GROUP BY source_ip, protocol
       ORDER BY source_ip, protocol ASC`
    )
      .bind(since, ...ips)
      .all<ProtocolRow>(),
    ctx.env.DB.prepare(
      `SELECT e.source_ip, j.value AS tag
       FROM events e, json_each(e.tags_json) j
       WHERE e.${SINCE_CLAUSE} AND e.source_ip IN (${placeholders})
       GROUP BY e.source_ip, j.value
       ORDER BY e.source_ip, j.value ASC`
    )
      .bind(since, ...ips)
      .all<TagRow>(),
    ctx.env.DB.prepare(
      `SELECT source_ip, payload_sha256, COUNT(*) AS cnt
       FROM events
       WHERE ${SINCE_CLAUSE} AND source_ip IN (${placeholders})
         AND payload_sha256 IS NOT NULL
       GROUP BY source_ip, payload_sha256
       ORDER BY source_ip, cnt DESC`
    )
      .bind(since, ...ips)
      .all<PayloadRow>(),
    ctx.env.DB.prepare(
      `SELECT source_ip, substr(COALESCE(user_agent, ''), 1, ${UA_PREFIX_LEN}) AS ua_prefix, COUNT(*) AS cnt
       FROM events
       WHERE ${SINCE_CLAUSE} AND source_ip IN (${placeholders})
         AND user_agent IS NOT NULL AND user_agent != ''
       GROUP BY source_ip, ua_prefix
       ORDER BY source_ip, cnt DESC`
    )
      .bind(since, ...ips)
      .all<UaRow>()
  ]);

  const trapSeqByIp = groupBy(trapSeq.results, (row) => row.source_ip);
  const protocolsByIp = groupBy(protocols.results, (row) => row.source_ip);
  const tagsByIp = groupBy(tags.results, (row) => row.source_ip);
  const payloadsByIp = groupBy(payloads.results, (row) => row.source_ip);

  const uaByIp = new Map<string, string>();
  for (const row of uaPrefixes.results) {
    if (!uaByIp.has(row.source_ip) && row.ua_prefix) {
      uaByIp.set(row.source_ip, row.ua_prefix);
    }
  }

  const siblingsByIp = relatedIpsAmongActors(
    ips,
    new Map(
      ips.map((ip) => [ip, (trapSeqByIp.get(ip) ?? []).map((row) => row.trap)])
    ),
    uaByIp
  );

  const actors = bases.map((base) => {
    const trapSequence = (trapSeqByIp.get(base.source_ip) ?? []).map((row) => row.trap);
    const protocolList = (protocolsByIp.get(base.source_ip) ?? []).map((row) => row.protocol);
    const tagList = (tagsByIp.get(base.source_ip) ?? []).map((row) => row.tag);
    const relatedPayloads = (payloadsByIp.get(base.source_ip) ?? [])
      .slice(0, 5)
      .map((row) => row.payload_sha256);
    const relatedIps = [...(siblingsByIp.get(base.source_ip) ?? [])].slice(0, 5);

    return {
      actor_id: base.source_ip,
      source_ip: base.source_ip,
      event_count: base.event_count,
      confidence: base.confidence,
      first_seen: base.first_seen,
      last_seen: base.last_seen,
      trap_sequence: trapSequence,
      protocols: protocolList,
      tags: tagList,
      related_payloads: relatedPayloads,
      related_ips: relatedIps
    };
  });

  return cachedJson({ actors }, FAST_CACHE);
};
