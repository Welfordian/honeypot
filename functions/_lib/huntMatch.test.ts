import { describe, expect, it } from "vitest";
import { eventMatchesHunt } from "./huntMatch";

const baseRule = {
  min_confidence: 50,
  trap: null,
  protocol: null,
  tag: null,
  has_credentials: null
};

const baseEvent = {
  confidence: 60,
  trap: "cowrie",
  protocol: "ssh",
  has_username: 0,
  has_password: 0,
  tags_json: '["scanner"]'
};

describe("eventMatchesHunt", () => {
  it("matches when confidence meets minimum and no optional filters", () => {
    expect(eventMatchesHunt(baseEvent, baseRule)).toBe(true);
  });

  it("rejects events below min_confidence", () => {
    expect(eventMatchesHunt({ ...baseEvent, confidence: 40 }, baseRule)).toBe(false);
  });

  it("filters by trap", () => {
    expect(eventMatchesHunt(baseEvent, { ...baseRule, trap: "cowrie" })).toBe(true);
    expect(eventMatchesHunt(baseEvent, { ...baseRule, trap: "http" })).toBe(false);
  });

  it("filters by protocol", () => {
    expect(eventMatchesHunt(baseEvent, { ...baseRule, protocol: "ssh" })).toBe(true);
    expect(eventMatchesHunt(baseEvent, { ...baseRule, protocol: "tcp" })).toBe(false);
  });

  it("filters by tag", () => {
    expect(eventMatchesHunt(baseEvent, { ...baseRule, tag: "scanner" })).toBe(true);
    expect(eventMatchesHunt(baseEvent, { ...baseRule, tag: "bruteforce" })).toBe(false);
  });

  it("filters credential attempts when has_credentials=1", () => {
    const rule = { ...baseRule, has_credentials: 1 };
    expect(eventMatchesHunt(baseEvent, rule)).toBe(false);
    expect(eventMatchesHunt({ ...baseEvent, has_username: 1 }, rule)).toBe(true);
    expect(eventMatchesHunt({ ...baseEvent, has_password: 1 }, rule)).toBe(true);
  });

  it("filters non-credential events when has_credentials=0", () => {
    const rule = { ...baseRule, has_credentials: 0 };
    expect(eventMatchesHunt(baseEvent, rule)).toBe(true);
    expect(eventMatchesHunt({ ...baseEvent, has_username: 1 }, rule)).toBe(false);
  });

  it("combines multiple filters", () => {
    const rule = {
      min_confidence: 70,
      trap: "cowrie",
      protocol: "ssh",
      tag: "scanner",
      has_credentials: 0
    };
    expect(eventMatchesHunt(baseEvent, rule)).toBe(false);
    expect(eventMatchesHunt({ ...baseEvent, confidence: 80 }, rule)).toBe(true);
  });
});
