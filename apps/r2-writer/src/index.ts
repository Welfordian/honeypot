import { loadConfig } from "./config.js";
import { createServer } from "./server.js";

const config = loadConfig();
const app = createServer(config);

const close = async () => {
  await app.close();
};

process.on("SIGTERM", () => {
  void close().then(() => process.exit(0));
});
process.on("SIGINT", () => {
  void close().then(() => process.exit(0));
});

await app.listen({ host: config.WRITER_HOST, port: config.WRITER_PORT });
