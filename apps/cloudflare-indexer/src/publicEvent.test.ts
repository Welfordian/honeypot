import { describe, expect, it } from "vitest";
import { redactPreview } from "./publicEvent.js";

describe("public event redaction", () => {
  it("redacts key-value secrets in previews", () => {
    expect(redactPreview("APP_KEY=test DB_PASSWORD=secret")).toBe("APP_KEY=[redacted] DB_PASSWORD=[redacted]");
  });

  it("redacts Cowrie login credential previews", () => {
    expect(redactPreview("login attempt [admin/password] succeeded")).toBe("login attempt [[redacted]/[redacted]] succeeded");
  });
});
