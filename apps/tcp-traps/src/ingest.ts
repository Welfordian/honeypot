import type { HoneypotEvent } from "@honeypot/shared";
import { signBody } from "@honeypot/shared";
import type { TcpTrapsConfig } from "./config.js";

export async function sendEvent(config: TcpTrapsConfig, event: HoneypotEvent): Promise<void> {
  const raw = JSON.stringify(event);
  const timestamp = new Date().toISOString();
  const signature = signBody(config.INGEST_HMAC_SECRET, timestamp, raw);
  const response = await fetch(config.COLLECTOR_URL, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-hp-timestamp": timestamp,
      "x-hp-signature": signature
    },
    body: raw
  });
  if (!response.ok) throw new Error(`collector rejected event with ${response.status}`);
}
