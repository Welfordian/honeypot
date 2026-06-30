function escapeControlCharacters(value: string): string {
  return value.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, (char) => `\\x${char.charCodeAt(0).toString(16).padStart(2, "0")}`);
}

export function redactPreview(value: string | null | undefined): string {
  if (!value) return "";
  let redacted = value.replace(/([A-Za-z0-9_ -]{0,32}(?:password|passwd|secret|token|key)[A-Za-z0-9_ -]{0,32})=([^&\s]+)/gi, "$1=[redacted]");
  redacted = redacted.replace(/Authorization:\s*Bearer\s+[^\s'"]+/gi, "Authorization: Bearer [redacted]");
  redacted = redacted.replace(/Authorization:\s*Basic\s+[^\s'"]+/gi, "Authorization: Basic [redacted]");
  redacted = redacted.replace(/\bBearer\s+[^\s'"]+/gi, "Bearer [redacted]");
  redacted = redacted.replace(/\bBasic\s+[A-Za-z0-9+/=]{8,}\b/g, "Basic [redacted]");

  const marker = "login attempt [";
  let lower = redacted.toLowerCase();
  let markerIndex = lower.indexOf(marker);

  while (markerIndex >= 0) {
    const valueStart = markerIndex + marker.length;
    const valueEnd = redacted.indexOf("]", valueStart);
    if (valueEnd < 0) break;

    const bracketValue = redacted.slice(valueStart, valueEnd);
    if (bracketValue.includes("/")) {
      redacted = `${redacted.slice(0, valueStart)}[redacted]/[redacted]${redacted.slice(valueEnd)}`;
      lower = redacted.toLowerCase();
      markerIndex = lower.indexOf(marker, valueStart + "[redacted]/[redacted]".length);
    } else {
      redacted = `${redacted.slice(0, valueStart)}[redacted]${redacted.slice(valueEnd)}`;
      lower = redacted.toLowerCase();
      markerIndex = lower.indexOf(marker, valueStart + "[redacted]".length);
    }
  }

  return escapeControlCharacters(redacted);
}
