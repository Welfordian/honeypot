import { describe, expect, it } from "vitest";
import { sensorStatusFromLastSeen, worstSensorStatus } from "./sensorStatus";

describe("sensorStatusFromLastSeen", () => {
  const now = Date.parse("2026-06-30T12:00:00.000Z");

  it("returns ok for recent heartbeats", () => {
    expect(sensorStatusFromLastSeen("2026-06-30T11:50:00.000Z", now)).toBe("ok");
  });

  it("returns warning between 15 and 60 minutes", () => {
    expect(sensorStatusFromLastSeen("2026-06-30T11:30:00.000Z", now)).toBe("warning");
  });

  it("returns stale after 60 minutes", () => {
    expect(sensorStatusFromLastSeen("2026-06-30T10:00:00.000Z", now)).toBe("stale");
  });
});

describe("worstSensorStatus", () => {
  it("prefers stale over warning and ok", () => {
    expect(worstSensorStatus(["ok", "warning", "stale"])).toBe("stale");
    expect(worstSensorStatus(["ok", "warning"])).toBe("warning");
    expect(worstSensorStatus(["ok", "ok"])).toBe("ok");
  });
});
