import { describe, expect, it } from "vitest";
import { publicEvent, publicEventPage, type EventRow } from "./rows";

describe("public event serialization", () => {
  const row: EventRow = {
    id: "event-1",
    occurred_at: "2026-06-29T12:00:00.000Z",
    received_at: "2026-06-29T12:00:01.000Z",
    event_kind: "trap",
    source_ip: "203.0.113.10",
    source_port: null,
    destination_port: 80,
    protocol: "http",
    trap: "env",
    sensor_id: "web",
    http_method: "GET",
    http_path: "/.env",
    http_status: 200,
    user_agent: "curl",
    credential_kind: null,
    has_username: 0,
    has_password: 0,
    payload_sha256: "a".repeat(64),
    payload_size: 12,
    payload_preview: "APP_KEY=secret",
    packet_count: 0,
    byte_count: 0,
    tcp_flags: null,
    is_aggregate: 0,
    pcap_sha256: null,
    pcap_available: 0,
    severity: 8,
    confidence: 92,
    confidence_reasons_json: "[\"payload_present\"]",
    tags_json: "[\"web\"]"
  };

  it("returns confidence fields and redacts hostile preview content", () => {
    expect(publicEvent(row)).toMatchObject({
      event_kind: "trap",
      confidence: 92,
      confidence_reasons: ["payload_present"],
      attack_techniques: ["T1110"],
      payload_preview: "APP_KEY=[redacted]"
    });
  });

  it("escapes non-printable payload previews", () => {
    expect(publicEvent({ ...row, payload_preview: "admin\u0000\u0003password=secret" })).toMatchObject({
      payload_preview: "admin\\x00\\x03password=[redacted]"
    });
  });

  it("returns only public-safe pcap metadata", () => {
    const network = {
      ...row,
      event_kind: "network-attempt",
      packet_count: 12,
      byte_count: 720,
      tcp_flags: "SYN",
      is_aggregate: 1,
      pcap_sha256: "b".repeat(64),
      pcap_available: 1
    };

    expect(publicEvent(network)).toMatchObject({
      event_kind: "network-attempt",
      packet_count: 12,
      byte_count: 720,
      tcp_flags: "SYN",
      is_aggregate: true,
      pcap_sha256: "b".repeat(64),
      pcap_available: true
    });
    expect(JSON.stringify(publicEvent(network))).not.toContain(".pcap");
    expect(JSON.stringify(publicEvent(network))).not.toContain("r2_key");
  });

  it("maps attack techniques from path and credential signals", () => {
    const login = publicEvent({
      ...row,
      http_path: "/wp-login.php",
      has_username: 1,
      has_password: 1,
      confidence_reasons_json: '["credential_attempt","scanner_user_agent"]'
    });

    expect(login.attack_techniques).toEqual(
      expect.arrayContaining(["T1110", "T1110.001", "T1595.002"])
    );
  });

  it("builds an event page cursor from the last returned row", () => {
    const second = { ...row, id: "event-2", occurred_at: "2026-06-29T11:00:00.000Z" };
    const page = publicEventPage([row, second], 1);

    expect(page.events).toHaveLength(1);
    expect(page.next_cursor).toBe("2026-06-29T12:00:00.000Z|event-1");
  });
});
