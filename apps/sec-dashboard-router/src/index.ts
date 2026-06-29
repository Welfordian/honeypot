interface Env {
  UPSTREAM_ORIGIN: string;
}

const CANONICAL_HOST = "dashboard.example.com";
const LEGACY_HOST = "legacy-dashboard.example.com";

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const upstreamUrl = new URL(request.url);
    if (upstreamUrl.hostname === LEGACY_HOST) {
      upstreamUrl.hostname = CANONICAL_HOST;
      return Response.redirect(upstreamUrl.toString(), 308);
    }

    const upstreamOrigin = new URL(env.UPSTREAM_ORIGIN);
    upstreamUrl.protocol = upstreamOrigin.protocol;
    upstreamUrl.hostname = upstreamOrigin.hostname;
    upstreamUrl.port = upstreamOrigin.port;

    const upstreamRequest = new Request(upstreamUrl.toString(), request);
    const response = await fetch(upstreamRequest, {
      cf: {
        cacheTtl: 0,
        cacheEverything: false
      }
    });

    const headers = new Headers(response.headers);
    if ((headers.get("content-type") || "").includes("text/html")) {
      headers.set("cache-control", "no-cache, no-store, must-revalidate");
      headers.set("pragma", "no-cache");
      headers.set("expires", "0");
    }

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers
    });
  }
};
