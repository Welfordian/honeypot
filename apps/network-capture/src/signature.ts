import { signBody } from "@honeypot/shared";

export function signedHeaders(secret: string, body: string | Buffer): Record<string, string> {
  const timestamp = new Date().toISOString();
  return {
    "x-hp-timestamp": timestamp,
    "x-hp-signature": signBody(secret, timestamp, body)
  };
}
