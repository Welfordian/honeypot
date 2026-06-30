import type { PagesCtx } from "../../../../_lib/env";
import { badRequest, json, publicIp } from "../../../../_lib/http";
import { getIpReputation } from "../../../../_lib/reputation";

export const onRequestGet: PagesFunction<PagesCtx["env"]> = async (ctx) => {
  const raw = Array.isArray(ctx.params.ip) ? ctx.params.ip[0] : ctx.params.ip;
  const ip = publicIp(raw ?? null);
  if (!ip) return badRequest("Invalid IP address.");

  const reputation = await getIpReputation(ctx.env.DB, ip, ctx.env);
  return json({ ip, reputation });
};
