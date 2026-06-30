import { describe, expect, it } from "vitest";
import { bucketStart } from "./rollups";

describe("bucketStart", () => {
  it("aligns to hour boundaries", () => {
    expect(bucketStart("2026-06-30T18:21:16.067Z", "hour")).toBe("2026-06-30T18:00:00.000Z");
  });

  it("aligns to day boundaries", () => {
    expect(bucketStart("2026-06-30T18:21:16.067Z", "day")).toBe("2026-06-30T00:00:00.000Z");
  });
});
