import { afterEach, describe, expect, it, vi } from "vitest";
import { isBlockedWebhookHost, postWebhook, validateWebhookUrl } from "./webhookUrl";

describe("isBlockedWebhookHost", () => {
  it("blocks loopback and metadata hosts", () => {
    expect(isBlockedWebhookHost("127.0.0.1")).toBe(true);
    expect(isBlockedWebhookHost("localhost")).toBe(true);
    expect(isBlockedWebhookHost("169.254.169.254")).toBe(true);
    expect(isBlockedWebhookHost("10.0.0.5")).toBe(true);
    expect(isBlockedWebhookHost("192.168.1.1")).toBe(true);
  });

  it("allows public hosts", () => {
    expect(isBlockedWebhookHost("hooks.slack.com")).toBe(false);
  });
});

describe("validateWebhookUrl", () => {
  it("requires https and rejects private hosts", () => {
    expect(validateWebhookUrl("http://hooks.example.com/x")).toBeInstanceOf(Response);
    expect(validateWebhookUrl("https://127.0.0.1/x")).toBeInstanceOf(Response);
    const ok = validateWebhookUrl("https://hooks.example.com/path");
    expect(ok).toBeInstanceOf(URL);
  });
});

describe("postWebhook", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("blocks redirects and treats them as errors", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response("", { status: 302, headers: { Location: "https://evil.test" } }))
    );

    await expect(
      postWebhook("https://hooks.example.com/path", { body: "{}", headers: { "content-type": "application/json" } })
    ).rejects.toThrow("webhook redirect blocked: 302");
  });

  it("posts with redirect manual and succeeds on 2xx", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response("ok", { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);

    await postWebhook("https://hooks.example.com/path", {
      body: '{"ok":true}',
      headers: { "content-type": "application/json" }
    });

    expect(fetchMock).toHaveBeenCalledWith(
      "https://hooks.example.com/path",
      expect.objectContaining({
        method: "POST",
        redirect: "manual",
        body: '{"ok":true}'
      })
    );
  });
});
