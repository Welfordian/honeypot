import type { HoneypotEvent } from "@honeypot/shared";
import { safePreview } from "@honeypot/shared";

interface CowrieRecord {
  eventid?: string;
  timestamp?: string;
  src_ip?: string;
  src_port?: number;
  dst_port?: number;
  username?: string;
  password?: string;
  input?: string;
  message?: string;
  protocol?: string;
  session?: string;
  [key: string]: unknown;
}

function trapName(eventId: string | undefined): string {
  if (!eventId) return "cowrie-event";
  if (eventId.includes("login")) return "cowrie-login";
  if (eventId.includes("command")) return "cowrie-command";
  if (eventId.includes("client")) return "cowrie-client";
  if (eventId.includes("session")) return "cowrie-session";
  return eventId.replaceAll(".", "-");
}

function severity(record: CowrieRecord): number {
  if (record.eventid?.includes("command")) return 8;
  if (record.eventid?.includes("login.success")) return 8;
  if (record.eventid?.includes("login.failed")) return 6;
  return 4;
}

export function cowrieRecordToEvent(record: CowrieRecord, sensorId: string, maxPayloadBytes: number): HoneypotEvent | null {
  if (!record.src_ip) return null;
  const payloadText = record.input ?? record.message;
  return {
    occurredAt: record.timestamp,
    sensorId,
    trap: trapName(record.eventid),
    protocol: record.protocol || (record.dst_port === 23 ? "telnet" : "ssh"),
    source: {
      ip: record.src_ip,
      port: record.src_port
    },
    destination: {
      port: record.dst_port
    },
    credentials: record.username || record.password
      ? {
          username: record.username,
          password: record.password,
          kind: "cowrie"
        }
      : undefined,
    payload: payloadText
      ? {
          text: safePreview(String(payloadText), maxPayloadBytes),
          mimeGuess: "text/plain"
        }
      : undefined,
    severity: severity(record),
    tags: ["cowrie", record.protocol || "ssh"].filter(Boolean),
    raw: {
      eventid: record.eventid,
      session: record.session
    }
  };
}
