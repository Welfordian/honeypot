import type { PagesCtx } from "../../../_lib/env";
import { artifactIocsFromRequest, fetchArtifactIocs } from "../../../_lib/artifactIocs";
import { ndjson } from "../../../_lib/http";

export const onRequestGet: PagesFunction<PagesCtx["env"]> = async (ctx) => {
  const query = artifactIocsFromRequest(ctx.request);
  if (query instanceof Response) return query;
  const artifacts = await fetchArtifactIocs(ctx.env.DB, query);
  const lines = artifacts.map((artifact) => JSON.stringify(artifact));
  return ndjson(lines);
};
