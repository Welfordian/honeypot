import { describe, expect, it } from "vitest";
import { redactPreview } from "./redaction";

describe("redactPreview", () => {
  it("redacts key-value secrets in previews", () => {
    expect(redactPreview("APP_KEY=test DB_PASSWORD=secret")).toBe("APP_KEY=[redacted] DB_PASSWORD=[redacted]");
  });

  it("redacts Cowrie login credential previews with slash", () => {
    expect(redactPreview("login attempt [admin/password] succeeded")).toBe(
      "login attempt [[redacted]/[redacted]] succeeded"
    );
  });

  it("redacts Cowrie login credential previews without slash", () => {
    expect(redactPreview("login attempt [admin] succeeded")).toBe("login attempt [[redacted]] succeeded");
  });

  it("redacts Authorization Bearer headers", () => {
    expect(redactPreview("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9")).toBe(
      "Authorization: Bearer [redacted]"
    );
  });

  it("redacts standalone Bearer tokens", () => {
    expect(redactPreview("curl -H 'Bearer secret-token'")).toBe("curl -H 'Bearer [redacted]'");
  });

  it("redacts Basic auth credentials", () => {
    expect(redactPreview("Authorization: Basic dXNlcjpwYXNz")).toBe("Authorization: Basic [redacted]");
    expect(redactPreview("proxy auth Basic dXNlcjpwYXNz ok")).toBe("proxy auth Basic [redacted] ok");
  });
});
