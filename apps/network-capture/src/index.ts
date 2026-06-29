import { setDefaultResultOrder } from "node:dns";
import { setTimeout as sleep } from "node:timers/promises";
import { loadNetworkCaptureConfig } from "./config.js";
import { startBannerSink } from "./banner.js";
import { startKernelLogFollower } from "./kernelLog.js";
import { ensureSpool, scanAndUploadPcaps, startTcpdump } from "./pcap.js";

const config = loadNetworkCaptureConfig();
setDefaultResultOrder("ipv4first");
let shuttingDown = false;

await ensureSpool(config);

const tcpdump = startTcpdump(config);
const journal = startKernelLogFollower(config);
const banner = startBannerSink(config);

function shutdown() {
  shuttingDown = true;
  tcpdump.kill("SIGTERM");
  journal.kill("SIGTERM");
  banner.close();
}

process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);

while (!shuttingDown) {
  await scanAndUploadPcaps(config);
  await sleep(5000);
}
