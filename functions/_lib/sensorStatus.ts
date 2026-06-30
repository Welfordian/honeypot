export type SensorStatus = "ok" | "warning" | "stale";

const WARNING_MS = 15 * 60 * 1000;
const STALE_MS = 60 * 60 * 1000;
const NON_OPERATIONAL_SENSOR_IDS = new Set(["deployment-self-test"]);

export function isOperationalSensorId(sensorId: string): boolean {
  return !NON_OPERATIONAL_SENSOR_IDS.has(sensorId);
}

export function sensorStatusFromLastSeen(lastSeen: string, now = Date.now()): SensorStatus {
  const ageMs = now - Date.parse(lastSeen);
  if (!Number.isFinite(ageMs) || ageMs < 0) return "stale";
  if (ageMs >= STALE_MS) return "stale";
  if (ageMs >= WARNING_MS) return "warning";
  return "ok";
}

export function worstSensorStatus(statuses: SensorStatus[]): SensorStatus {
  if (statuses.includes("stale")) return "stale";
  if (statuses.includes("warning")) return "warning";
  return "ok";
}
