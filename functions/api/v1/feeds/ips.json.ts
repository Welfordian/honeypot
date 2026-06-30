import type { PagesCtx } from "../../../_lib/env";
import { cachedJson } from "../../../_lib/http";
import { ipIocsFromRequest, publicIpIoc, type IpProfileRow } from "../../../_lib/ipIocs";

export const onRequestGet: PagesFunction<PagesCtx["env"]> = async (ctx) => {
  const query = ipIocsFromRequest(ctx.request);
  if (query instanceof Response) return query;
  const result = await ctx.env.DB.prepare(query.sql).bind(...query.params).all<IpProfileRow>();
  return cachedJson(result.results.map(publicIpIoc));
};
