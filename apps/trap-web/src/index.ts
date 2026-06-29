import { readFileSync } from "node:fs";
import type { ServerOptions as HttpsOptions } from "node:https";
import selfsigned from "selfsigned";
import { loadTrapConfig } from "./config.js";
import { createTrapServer } from "./server.js";

const config = loadTrapConfig();
const httpApp = createTrapServer(config, "http");

function tlsOptions(): HttpsOptions {
  if (config.TRAP_TLS_KEY_PATH && config.TRAP_TLS_CERT_PATH) {
    return {
      key: readFileSync(config.TRAP_TLS_KEY_PATH),
      cert: readFileSync(config.TRAP_TLS_CERT_PATH)
    };
  }

  const cert = selfsigned.generate([{ name: "commonName", value: "honeypot.invalid" }], { days: 365, keySize: 2048 });
  return {
    key: cert.private,
    cert: cert.cert
  };
}

const httpsApp = createTrapServer(config, "https", tlsOptions());

const close = async () => {
  await httpApp.close();
  await httpsApp.close();
};

process.on("SIGTERM", () => {
  void close().then(() => process.exit(0));
});
process.on("SIGINT", () => {
  void close().then(() => process.exit(0));
});

await Promise.all([
  httpApp.listen({ host: config.TRAP_HTTP_HOST, port: config.TRAP_HTTP_PORT }),
  httpsApp.listen({ host: config.TRAP_HTTP_HOST, port: config.TRAP_HTTPS_PORT })
]);
