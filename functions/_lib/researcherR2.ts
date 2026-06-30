import { redactPreview } from "./redaction";

export interface StoredR2Event {
  eventId?: string;
  payload?: {
    text?: string;
    base64?: string;
    mimeGuess?: string;
  };
  payloadMeta?: {
    sha256?: string;
    sizeBytes?: number;
    mimeGuess?: string;
    preview?: string;
  };
  credentials?: {
    username?: string;
    password?: string;
    token?: string;
    kind?: string;
  };
}

export async function fetchStoredEvent(bucket: R2Bucket, r2Key: string): Promise<StoredR2Event | null> {
  const object = await bucket.get(r2Key);
  if (!object) return null;
  const text = await object.text();
  const trimmed = text.trimEnd();
  try {
    return JSON.parse(trimmed) as StoredR2Event;
  } catch {
    return null;
  }
}

const BASE64_PREVIEW_BYTES = 8 * 1024;

function decodeBase64(encoded: string): string | null {
  try {
    return atob(encoded);
  } catch {
    return null;
  }
}

export function redactedEventPayload(stored: StoredR2Event) {
  const text = stored.payload?.text ? redactPreview(stored.payload.text) : null;
  const rawBase64 = stored.payload?.base64;

  const payload: {
    text: string | null;
    base64_redacted_preview?: string;
    base64_size?: number;
    mime_guess: string | null;
    sha256: string | null;
    size_bytes: number | null;
    has_credentials: boolean;
    credential_kind: string | null;
  } = {
    text,
    mime_guess: stored.payload?.mimeGuess ?? stored.payloadMeta?.mimeGuess ?? null,
    sha256: stored.payloadMeta?.sha256 ?? null,
    size_bytes: stored.payloadMeta?.sizeBytes ?? null,
    has_credentials: Boolean(
      stored.credentials?.username || stored.credentials?.password || stored.credentials?.token
    ),
    credential_kind: stored.credentials?.kind ?? null
  };

  if (rawBase64) {
    payload.base64_size = rawBase64.length;
    const decoded = decodeBase64(rawBase64);
    if (decoded !== null) {
      const preview = redactPreview(decoded.slice(0, BASE64_PREVIEW_BYTES));
      payload.base64_redacted_preview = btoa(preview);
    }
  }

  return payload;
}
