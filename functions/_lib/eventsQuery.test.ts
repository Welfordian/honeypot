import { describe, expect, it } from "vitest";
import { buildEventsQuery } from "./eventsQuery";

describe("buildEventsQuery", () => {
  it("does not filter by port when destinationPort is omitted", () => {
    const query = buildEventsQuery(new URL("https://dashboard.example.com/api/v1/events"));

    expect(query).not.toBeInstanceOf(Response);
    if (query instanceof Response) return;
    expect(query.sql).not.toContain("destination_port = ?");
    expect(query.params).not.toContain(0);
  });

  it("filters by a valid destination port", () => {
    const query = buildEventsQuery(new URL("https://dashboard.example.com/api/v1/events?destinationPort=65001"));

    expect(query).not.toBeInstanceOf(Response);
    if (query instanceof Response) return;
    expect(query.sql).toContain("destination_port = ?");
    expect(query.params).toContain(65001);
  });

  it("rejects invalid destination ports", () => {
    const query = buildEventsQuery(new URL("https://dashboard.example.com/api/v1/events?destinationPort=70000"));

    expect(query).toBeInstanceOf(Response);
    expect((query as Response).status).toBe(400);
  });
});
