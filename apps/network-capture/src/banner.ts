import net from "node:net";
import type { NetworkCaptureConfig } from "./config.js";
import { bannerEvent, sendEvent } from "./events.js";
import { warnThrottled } from "./logging.js";

const BANNER = "220 service ready\r\n";
const RESPONSE = "421 service unavailable\r\n";

export function startBannerSink(config: NetworkCaptureConfig): net.Server {
  const server = net.createServer((socket) => {
    socket.setTimeout(config.BANNER_CLOSE_AFTER_MS);
    socket.write(BANNER);

    const initial = bannerEvent(config, socket);
    if (initial) {
      sendEvent(config, initial).catch((error) => warnThrottled("banner-connection", "failed to ship banner connection", error));
    }

    let captured = false;
    socket.on("data", (chunk) => {
      if (captured) return;
      captured = true;
      const event = bannerEvent(config, socket, chunk.subarray(0, config.MAX_BANNER_BYTES));
      if (event) {
        sendEvent(config, event).catch((error) => warnThrottled("banner-payload", "failed to ship banner payload", error));
      }
      socket.write(RESPONSE);
      setTimeout(() => socket.destroy(), 250);
    });
    socket.on("timeout", () => socket.destroy());
    socket.on("error", () => socket.destroy());
  });

  server.maxConnections = 512;
  server.listen(config.GENERIC_BANNER_PORT, "0.0.0.0", () => {
    console.log(`generic banner sink listening on 0.0.0.0:${config.GENERIC_BANNER_PORT}`);
  });
  return server;
}
