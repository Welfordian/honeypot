import type { Env, LiveEvent } from "./types.js";

export async function publishLiveEvent(env: Env, event: LiveEvent | null): Promise<void> {
  if (!event || !env.LIVE_STREAM) return;

  try {
    const response = await env.LIVE_STREAM.fetch("https://live.internal/internal/publish", {
      method: "POST",
      headers: {
        "content-type": "application/json"
      },
      body: JSON.stringify({ event })
    });

    if (!response.ok) {
      console.warn("live event publish failed", { eventId: event.id, status: response.status });
    }
  } catch (error) {
    console.warn("live event publish failed", { eventId: event.id, error });
  }
}
