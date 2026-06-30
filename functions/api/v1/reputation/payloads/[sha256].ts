import type { PagesCtx } from "../../../../_lib/env";
import { badRequest, json, publicSha256 } from "../../../../_lib/http";
import { getHashReputation } from "../../../../_lib/reputation";

export const onRequestGet: PagesFunction<PagesCtx["env"]> = async (ctx) => {
  const raw = Array.isArray(ctx.params.sha256) ? ctx.params.sha256[0] : ctx.params.sha256;
  const sha256 = publicSha256(raw ?? null);
  if (!sha256) return badRequest("Invalid SHA-256 hash.");

  const reputation = await getHashReputation(ctx.env.DB, sha256, ctx.env);
  return json({ sha256, reputation });
};
