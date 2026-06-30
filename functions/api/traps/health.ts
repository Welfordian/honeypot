import type { PagesCtx } from "../../_lib/env";
import { json } from "../../_lib/http";
import { isOperationalSensorId } from "../../_lib/sensorStatus";

export const onRequestGet: PagesFunction<PagesCtx["env"]> = async (ctx) => {
  const result = await ctx.env.DB.prepare(
    `SELECT sensor_id, last_seen, last_protocol, last_trap, event_count
     FROM sensor_health
     ORDER BY last_seen DESC
     LIMIT 100`
  ).all();
  return json({
    sensors: result.results.filter((sensor) =>
      typeof sensor.sensor_id === "string" && isOperationalSensorId(sensor.sensor_id)
    )
  });
};
