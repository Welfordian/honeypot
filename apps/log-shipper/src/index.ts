import { createReadStream, statSync, watchFile } from "node:fs";
import { setTimeout as sleep } from "node:timers/promises";
import { loadLogShipperConfig } from "./config.js";
import { cowrieRecordToEvent } from "./cowrie.js";
import { sendEvent } from "./ingest.js";

const config = loadLogShipperConfig();
let offset = config.START_AT_BEGINNING ? 0 : initialOffset(config.LOG_FILE);
let shuttingDown = false;

function initialOffset(path: string): number {
  try {
    return statSync(path).size;
  } catch {
    return 0;
  }
}

async function readNewLines(): Promise<void> {
  let size = 0;
  try {
    size = statSync(config.LOG_FILE).size;
  } catch {
    return;
  }
  if (size < offset) offset = 0;
  if (size === offset) return;

  const stream = createReadStream(config.LOG_FILE, { start: offset, end: size - 1, encoding: "utf8" });
  let buffer = "";
  for await (const chunk of stream) buffer += chunk;
  offset = size;

  for (const line of buffer.split(/\r?\n/)) {
    if (!line.trim()) continue;
    try {
      const event = cowrieRecordToEvent(JSON.parse(line), config.SENSOR_ID, config.MAX_PAYLOAD_BYTES);
      if (event) await sendEvent(config, event);
    } catch (error) {
      console.warn("failed to ship cowrie log line", error);
    }
  }
}

process.on("SIGTERM", () => {
  shuttingDown = true;
});
process.on("SIGINT", () => {
  shuttingDown = true;
});

watchFile(config.LOG_FILE, { interval: 2000 }, () => {
  void readNewLines();
});

while (!shuttingDown) {
  await readNewLines();
  await sleep(2000);
}
