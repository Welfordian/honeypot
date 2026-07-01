import type { PagesCtx } from "../../../_lib/env";
import { cachedJson, parseSinceHours, urlOf } from "../../../_lib/http";
import {
  countRollupDistinctIps,
  FAST_CACHE,
  sumRollupCountForKey,
  sumRollupCounts,
  topAttackersInWindow,
  topPayloadCampaigns
} from "../../../_lib/rollups";

export const onRequestGet: PagesFunction<PagesCtx["env"]> = async (ctx) => {
  const url = urlOf(ctx.request);
  const sinceHours = parseSinceHours(url, 24, 24 * 30);
  const since = `-${sinceHours} hours`;

  const [topAttackers, topConfidenceReasons, topTags, credentialAttempts, highConfidenceIps, campaigns] =
    await Promise.all([
      topAttackersInWindow(ctx.env.DB, since, 10),
      sumRollupCounts(ctx.env.DB, "confidence_reason", since, 15),
      sumRollupCounts(ctx.env.DB, "tag", since, 15),
      sumRollupCountForKey(ctx.env.DB, "has_credentials", "1", since),
      countRollupDistinctIps(ctx.env.DB, "high_confidence_ip", since),
      topPayloadCampaigns(ctx.env.DB, since, 20)
    ]);

  return cachedJson(
    {
      topAttackers,
      topConfidenceReasons,
      topTags,
      credentialAttempts,
      highConfidenceIps,
      campaigns
    },
    FAST_CACHE
  );
};
