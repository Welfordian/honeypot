import type { PagesCtx } from "../../../_lib/env";
import { artifactIocsFromRequest, fetchArtifactIocs } from "../../../_lib/artifactIocs";
import { cachedJson } from "../../../_lib/http";
import { ipIocsFromRequest, publicIpIoc, type IpProfileRow } from "../../../_lib/ipIocs";
import { buildRichStixBundle } from "../../../_lib/stixBundle";

export const onRequestGet: PagesFunction<PagesCtx["env"]> = async (ctx) => {
  const ipQuery = ipIocsFromRequest(ctx.request);
  if (ipQuery instanceof Response) return ipQuery;
  const artifactQuery = artifactIocsFromRequest(ctx.request);
  if (artifactQuery instanceof Response) return artifactQuery;

  const [ipResult, artifacts] = await Promise.all([
    ctx.env.DB.prepare(ipQuery.sql).bind(...ipQuery.params).all<IpProfileRow>(),
    fetchArtifactIocs(ctx.env.DB, artifactQuery)
  ]);

  return cachedJson(
    buildRichStixBundle({
      ips: ipResult.results.map(publicIpIoc),
      artifacts
    })
  );
};
