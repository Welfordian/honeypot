import { describe, expect, it } from "vitest";
import { redactedEventPayload } from "./researcherR2";

describe("redactedEventPayload", () => {
  it("returns redacted text without raw base64", () => {
    const secret = "super-secret-token-value";
    const encoded = btoa(`hello Authorization: Bearer ${secret}`);
    const result = redactedEventPayload({
      payload: {
        text: "password=abc",
        base64: encoded
      }
    });

    expect(result.text).toBe("password=[redacted]");
    expect(result).not.toHaveProperty("base64");
    expect(result.base64_size).toBe(encoded.length);
    expect(result.base64_redacted_preview).toBeDefined();
    const preview = atob(result.base64_redacted_preview!);
    expect(preview).toContain("Authorization: Bearer [redacted]");
    expect(preview).not.toContain(secret);
  });

  it("omits base64 preview when payload is not valid base64", () => {
    const result = redactedEventPayload({
      payload: {
        base64: "not!!!valid"
      }
    });

    expect(result.base64_size).toBe("not!!!valid".length);
    expect(result.base64_redacted_preview).toBeUndefined();
  });

  it("truncates decoded base64 previews to 8KB", () => {
    const encoded = btoa("x".repeat(10_000));
    const result = redactedEventPayload({
      payload: { base64: encoded }
    });

    const preview = atob(result.base64_redacted_preview!);
    expect(preview.length).toBe(8 * 1024);
  });
});
