import dgram from "node:dgram";
import net from "node:net";
import type { HoneypotEvent } from "@honeypot/shared";
import { normalizeIp, safePreview } from "@honeypot/shared";
import { loadTcpTrapsConfig } from "./config.js";
import { sendEvent } from "./ingest.js";
import { TCP_TRAPS, UDP_TRAPS, type TcpTrapDefinition, type UdpTrapDefinition } from "./protocols.js";

const config = loadTcpTrapsConfig();
const servers: Array<net.Server | dgram.Socket> = [];

function sourceIp(ip: string | undefined): string {
  return normalizeIp(ip ?? "0.0.0.0");
}

function tcpEvent(definition: TcpTrapDefinition, socket: net.Socket, payload?: Buffer): HoneypotEvent {
  return {
    sensorId: config.SENSOR_ID,
    trap: definition.trap,
    protocol: definition.protocol,
    source: {
      ip: sourceIp(socket.remoteAddress),
      port: socket.remotePort
    },
    destination: {
      port: definition.publicPort
    },
    payload: payload ? { text: safePreview(payload.subarray(0, config.MAX_PAYLOAD_BYTES).toString("utf8")), mimeGuess: "application/octet-stream" } : undefined,
    tags: definition.tags,
    raw: {
      localPort: definition.listenPort,
      bytes: payload?.byteLength ?? 0
    }
  };
}

function udpEvent(definition: UdpTrapDefinition, remote: dgram.RemoteInfo, payload: Buffer): HoneypotEvent {
  return {
    sensorId: config.SENSOR_ID,
    trap: definition.trap,
    protocol: definition.protocol,
    source: {
      ip: sourceIp(remote.address),
      port: remote.port
    },
    destination: {
      port: definition.publicPort
    },
    payload: { text: safePreview(payload.subarray(0, config.MAX_PAYLOAD_BYTES).toString("utf8")), mimeGuess: "application/octet-stream" },
    tags: definition.tags,
    raw: {
      localPort: definition.listenPort,
      udp: true,
      bytes: payload.byteLength
    }
  };
}

function startTcpTrap(definition: TcpTrapDefinition): net.Server {
  const server = net.createServer((socket) => {
    socket.setTimeout(definition.closeAfterMs);
    if (definition.banner) socket.write(definition.banner);

    sendEvent(config, tcpEvent(definition, socket)).catch((error) => {
      console.warn(`failed to ingest ${definition.protocol} connection`, error);
    });

    let captured = false;
    socket.on("data", (chunk) => {
      if (captured) return;
      captured = true;
      sendEvent(config, tcpEvent(definition, socket, chunk)).catch((error) => {
        console.warn(`failed to ingest ${definition.protocol} payload`, error);
      });
      if (definition.response) socket.write(definition.response);
      setTimeout(() => socket.destroy(), 250);
    });

    socket.on("timeout", () => socket.destroy());
    socket.on("error", () => socket.destroy());
  });

  server.listen(definition.listenPort, config.TCP_TRAP_HOST, () => {
    console.log(`${definition.protocol} trap listening on ${config.TCP_TRAP_HOST}:${definition.listenPort}`);
  });
  return server;
}

function startUdpTrap(definition: UdpTrapDefinition): dgram.Socket {
  const socket = dgram.createSocket("udp4");
  socket.on("message", (message, remote) => {
    sendEvent(config, udpEvent(definition, remote, message)).catch((error) => {
      console.warn(`failed to ingest ${definition.protocol} datagram`, error);
    });
    if (definition.response) socket.send(definition.response, remote.port, remote.address);
  });
  socket.bind(definition.listenPort, config.TCP_TRAP_HOST, () => {
    console.log(`${definition.protocol} trap listening on ${config.TCP_TRAP_HOST}:${definition.listenPort}/udp`);
  });
  return socket;
}

for (const definition of TCP_TRAPS) servers.push(startTcpTrap(definition));
for (const definition of UDP_TRAPS) servers.push(startUdpTrap(definition));

async function closeAll() {
  await Promise.all(servers.map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
}

process.on("SIGTERM", () => {
  void closeAll().then(() => process.exit(0));
});
process.on("SIGINT", () => {
  void closeAll().then(() => process.exit(0));
});
