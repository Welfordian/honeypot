import { describe, expect, it } from "vitest";
import { cowrieRecordToEvent } from "./cowrie.js";

describe("cowrie log parser", () => {
  it("maps login attempts into normalized honeypot events", () => {
    const event = cowrieRecordToEvent(
      {
        eventid: "cowrie.login.failed",
        timestamp: "2026-06-29T12:00:00Z",
        src_ip: "203.0.113.50",
        src_port: 51515,
        dst_port: 22,
        username: "root",
        password: "toor"
      },
      "cowrie-1",
      4096
    );

    expect(event?.trap).toBe("cowrie-login");
    expect(event?.credentials?.username).toBe("root");
    expect(event?.severity).toBe(6);
  });
});
