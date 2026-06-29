import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { mkdir, readdir, rm, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import { spawn, type ChildProcess } from "node:child_process";
import { gzip } from "node:zlib";
import { promisify } from "node:util";
import type { NetworkCaptureConfig } from "./config.js";
import { signedHeaders } from "./signature.js";

const gzipAsync = promisify(gzip);

interface PcapSummary {
  packetCount: number;
  firstSeen: string;
  lastSeen: string;
  sourceIps: string[];
}

function bpfFilter(config: NetworkCaptureConfig): string {
  const suppressed = config.SUPPRESSED_SOURCE_IPS.map((ip) => `not host ${ip}`).join(" and ");
  return `dst host ${config.PUBLIC_IP} and not tcp port ${config.ADMIN_SSH_PORT} and not (udp and src port 53) and ${suppressed}`;
}

function sourceIpFromTcpdumpAddress(value: string): string {
  const trimmed = value.replace(/:$/, "");
  if (trimmed.includes(":")) return trimmed.replace(/^::ffff:/, "");
  const parts = trimmed.split(".");
  return parts.length > 4 ? parts.slice(0, 4).join(".") : trimmed;
}

export async function ensureSpool(config: NetworkCaptureConfig): Promise<void> {
  await mkdir(config.PCAP_SPOOL_DIR, { recursive: true, mode: 0o700 });
}

export function startTcpdump(config: NetworkCaptureConfig): ChildProcess {
  const pattern = path.join(config.PCAP_SPOOL_DIR, "capture-%Y%m%d%H%M%S.pcap");
  const args = [
    "-i",
    config.CAPTURE_INTERFACE,
    "-Z",
    "root",
    "-n",
    "-s",
    "0",
    "-U",
    "-G",
    String(config.PCAP_ROTATE_SECONDS),
    "-C",
    String(config.PCAP_MAX_MB),
    "-w",
    pattern,
    bpfFilter(config)
  ];
  const child = spawn("tcpdump", args, { stdio: ["ignore", "ignore", "pipe"] });
  if (!child.stderr) throw new Error("tcpdump stderr unavailable");
  child.stderr.on("data", (chunk) => console.warn(`tcpdump: ${chunk.toString("utf8").trim()}`));
  return child;
}

function sha256(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}

async function fileSha256(file: string): Promise<string> {
  const hash = createHash("sha256");
  await new Promise<void>((resolve, reject) => {
    const stream = createReadStream(file);
    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("error", reject);
    stream.on("end", resolve);
  });
  return hash.digest("hex");
}

async function summarizePcap(file: string, config: NetworkCaptureConfig): Promise<PcapSummary> {
  const child = spawn("tcpdump", ["-Z", "root", "-tt", "-nn", "-r", file], { stdio: ["ignore", "pipe", "pipe"] });
  if (!child.stdout) throw new Error("tcpdump summary stdout unavailable");
  let output = "";
  for await (const chunk of child.stdout) output += chunk.toString("utf8");
  await new Promise<void>((resolve) => child.on("close", () => resolve()));

  const sourceIps = new Set<string>();
  let packetCount = 0;
  let firstSeen = "";
  let lastSeen = "";

  for (const line of output.split(/\r?\n/)) {
    if (!line.trim()) continue;
    packetCount += 1;
    const timestamp = Number(line.match(/^(\d+(?:\.\d+)?)/)?.[1] ?? 0);
    if (timestamp > 0) {
      const iso = new Date(timestamp * 1000).toISOString();
      firstSeen ||= iso;
      lastSeen = iso;
    }
    const ipMatch = line.match(/\bIP6?\s+(\S+)\s+>\s+(\S+)/);
    if (ipMatch?.[1]) {
      const sourceIp = sourceIpFromTcpdumpAddress(ipMatch[1]);
      if (!config.SUPPRESSED_SOURCE_IPS.includes(sourceIp)) sourceIps.add(sourceIp);
    }
  }

  const stats = await stat(file);
  const fallbackTime = stats.mtime.toISOString();
  return {
    packetCount,
    firstSeen: firstSeen || fallbackTime,
    lastSeen: lastSeen || fallbackTime,
    sourceIps: Array.from(sourceIps).sort()
  };
}

async function uploadPcap(config: NetworkCaptureConfig, file: string): Promise<void> {
  const summary = await summarizePcap(file, config);
  if (summary.sourceIps.some((ip) => config.SUPPRESSED_SOURCE_IPS.includes(ip))) {
    await rm(file, { force: true });
    return;
  }

  const original = await createReadStream(file).toArray();
  const gzipped = await gzipAsync(Buffer.concat(original as Buffer[]), { level: 6 });
  const digest = sha256(gzipped);
  const captureId = path.basename(file, ".pcap");
  const response = await fetch(config.CLOUDFLARE_PCAP_INGEST_URL, {
    method: "POST",
    headers: {
      "content-type": "application/gzip",
      "x-hp-capture-id": captureId,
      "x-hp-first-seen": summary.firstSeen,
      "x-hp-last-seen": summary.lastSeen,
      "x-hp-interface": config.CAPTURE_INTERFACE,
      "x-hp-packet-count": String(summary.packetCount),
      "x-hp-source-ips": summary.sourceIps.join(","),
      "x-hp-sha256": digest,
      ...signedHeaders(config.INGEST_HMAC_SECRET, gzipped)
    },
    body: gzipped,
    signal: AbortSignal.timeout(config.INGEST_TIMEOUT_MS)
  });

  if (!response.ok) throw new Error(`pcap ingest rejected ${file} with ${response.status}: ${(await response.text()).slice(0, 200)}`);
  await rm(file, { force: true });
}

async function enforceSpoolLimit(config: NetworkCaptureConfig): Promise<void> {
  const entries = await readdir(config.PCAP_SPOOL_DIR);
  const files = await Promise.all(
    entries
      .filter((entry) => entry.endsWith(".pcap"))
      .map(async (entry) => {
        const file = path.join(config.PCAP_SPOOL_DIR, entry);
        const stats = await stat(file);
        return { file, mtimeMs: stats.mtimeMs, size: stats.size };
      })
  );
  let total = files.reduce((sum, file) => sum + file.size, 0);
  for (const file of files.sort((a, b) => a.mtimeMs - b.mtimeMs)) {
    if (total <= config.PCAP_MAX_SPOOL_BYTES) break;
    await rm(file.file, { force: true });
    total -= file.size;
  }
}

export async function scanAndUploadPcaps(config: NetworkCaptureConfig): Promise<void> {
  await ensureSpool(config);
  await enforceSpoolLimit(config);
  const now = Date.now();
  const entries = await readdir(config.PCAP_SPOOL_DIR);
  for (const entry of entries) {
    if (!entry.endsWith(".pcap")) continue;
    const file = path.join(config.PCAP_SPOOL_DIR, entry);
    const stats = await stat(file);
    if (now - stats.mtimeMs < config.PCAP_UPLOAD_MIN_AGE_MS) continue;
    if (stats.size === 0) {
      await rm(file, { force: true });
      continue;
    }
    try {
      await uploadPcap(config, file);
    } catch (error) {
      const marker = `${file}.failed`;
      await writeFile(marker, `${new Date().toISOString()} ${String(error)}\n`, { flag: "a", mode: 0o600 }).catch(() => undefined);
      console.warn("failed to upload pcap", error);
    }
  }
}

export async function pcapSha256(file: string): Promise<string> {
  return fileSha256(file);
}
