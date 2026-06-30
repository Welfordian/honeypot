import type { IpIoc } from "./ipIocs";

export interface StixBundle {
  type: "bundle";
  id: string;
  spec_version: "2.1";
  objects: StixIndicator[];
}

export interface StixIndicator {
  type: "indicator";
  spec_version: "2.1";
  id: string;
  created: string;
  modified: string;
  name: string;
  description: string;
  pattern: string;
  pattern_type: "stix";
  valid_from: string;
  valid_until: string;
  labels: string[];
  confidence: number;
}

export function buildStixBundle(iocs: IpIoc[], generatedAt = new Date().toISOString()): StixBundle {
  return {
    type: "bundle",
    id: stixDeterministicId("bundle", generatedAt),
    spec_version: "2.1",
    objects: iocs.map((ioc) => stixIndicatorFromIoc(ioc))
  };
}

function stixIndicatorFromIoc(ioc: IpIoc): StixIndicator {
  const labels = [`confidence:${ioc.confidence}`, ...ioc.confidence_reasons.map((reason) => `reason:${reason}`)];
  return {
    type: "indicator",
    spec_version: "2.1",
    id: stixDeterministicId("indicator", ioc.source_ip),
    created: ioc.first_seen,
    modified: ioc.last_seen,
    name: `Honeypot source IP ${ioc.source_ip}`,
    description: `Observed across traps: ${ioc.unique_traps.join(", ") || "unknown"}`,
    pattern: stixIpPattern(ioc.source_ip),
    pattern_type: "stix",
    valid_from: ioc.first_seen,
    valid_until: ioc.last_seen,
    labels,
    confidence: ioc.confidence
  };
}

export function stixIpPattern(ip: string): string {
  const escaped = ip.replaceAll("'", "''");
  const type = ip.includes(":") ? "ipv6-addr" : "ipv4-addr";
  return `[${type}:value = '${escaped}']`;
}

export function stixDeterministicId(prefix: string, value: string): string {
  let hash = 0x811c9dc5;
  for (let i = 0; i < value.length; i++) {
    hash ^= value.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193);
  }
  const parts = [0, 1, 2, 3].map((index) => {
    const mixed = Math.imul(hash ^ index, 0x9e3779b1) >>> 0;
    return mixed.toString(16).padStart(8, "0");
  });
  const [part0, part1, part2, part3] = parts as [string, string, string, string];
  const uuid = `${part0}-${part1.slice(0, 4)}-4${part1.slice(4, 7)}-8${part2.slice(0, 3)}-${part2.slice(3)}${part3}`.slice(
    0,
    36
  );
  return `${prefix}--${uuid}`;
}
