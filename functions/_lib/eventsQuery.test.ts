import { describe, expect, it } from "vitest";
import { buildEventsQuery } from "./eventsQuery";

function queryFrom(search: string) {
  return buildEventsQuery(new URL(`https://dashboard.example.com/api/v1/events${search}`));
}

describe("buildEventsQuery", () => {
  it("does not filter by port when destinationPort is omitted", () => {
    const query = queryFrom("");

    expect(query).not.toBeInstanceOf(Response);
    if (query instanceof Response) return;
    expect(query.sql).not.toContain("destination_port = ?");
    expect(query.params).not.toContain(0);
  });

  it("filters by a valid destination port", () => {
    const query = queryFrom("?destinationPort=65001");

    expect(query).not.toBeInstanceOf(Response);
    if (query instanceof Response) return;
    expect(query.sql).toContain("destination_port = ?");
    expect(query.params).toContain(65001);
  });

  it("rejects invalid destination ports", () => {
    const query = queryFrom("?destinationPort=70000");

    expect(query).toBeInstanceOf(Response);
    expect((query as Response).status).toBe(400);
  });

  it("filters by minConfidence", () => {
    const query = queryFrom("?minConfidence=80");

    expect(query).not.toBeInstanceOf(Response);
    if (query instanceof Response) return;
    expect(query.sql).toContain("confidence >= ?");
    expect(query.params).toContain(80);
  });

  it("rejects invalid minConfidence", () => {
    const query = queryFrom("?minConfidence=150");
    expect(query).toBeInstanceOf(Response);
    expect((query as Response).status).toBe(400);
  });

  it("filters credential attempts when hasCredentials=true", () => {
    const query = queryFrom("?hasCredentials=true");

    expect(query).not.toBeInstanceOf(Response);
    if (query instanceof Response) return;
    expect(query.sql).toContain("(has_username = 1 OR has_password = 1)");
  });

  it("filters by tag via json_each", () => {
    const query = queryFrom("?tag=scanner_user_agent");

    expect(query).not.toBeInstanceOf(Response);
    if (query instanceof Response) return;
    expect(query.sql).toContain("json_each(tags_json)");
    expect(query.params).toContain("scanner_user_agent");
  });

  it("filters by confidenceReason via json_each", () => {
    const query = queryFrom("?confidenceReason=credential_attempt");

    expect(query).not.toBeInstanceOf(Response);
    if (query instanceof Response) return;
    expect(query.sql).toContain("json_each(confidence_reasons_json)");
    expect(query.params).toContain("credential_attempt");
  });

  it("rejects invalid tag tokens", () => {
    const query = queryFrom("?tag=bad%20tag");
    expect(query).toBeInstanceOf(Response);
    expect((query as Response).status).toBe(400);
  });
});
