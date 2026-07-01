import type { Env } from "./types.js";

const WARM_PATHS = [
  "/api/analytics/overview/summary?sinceHours=24",
  "/api/analytics/overview/charts?sinceHours=24",
  "/api/analytics/overview?sinceHours=24"
] as const;

/** Hits public overview endpoints so CDN edge cache stays warm (120s TTL). */
export async function warmOverviewCache(env: Env): Promise<void> {
  const origin = env.PUBLIC_SITE_ORIGIN?.replace(/\/$/, "");
  if (!origin) return;

  await Promise.all(
    WARM_PATHS.map(async (path) => {
      const response = await fetch(`${origin}${path}`, {
        headers: { "user-agent": "honeypot-cache-warmer" }
      });
      if (!response.ok) {
        console.warn("overview cache warm failed", path, response.status);
      }
    })
  );
}
