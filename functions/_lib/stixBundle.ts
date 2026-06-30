import type { AttackTechnique } from "./attackMapping";
import type { ArtifactIoc } from "./artifactIocs";
import type { IpIoc } from "./ipIocs";

export interface StixBundle {
  type: "bundle";
  id: string;
  spec_version: "2.1";
  objects: StixObject[];
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

export interface StixAttackPattern {
  type: "attack-pattern";
  spec_version: "2.1";
  id: string;
  name: string;
  description: string;
  external_references: Array<{
    source_name: string;
    external_id: string;
    url: string;
  }>;
  kill_chain_phases: Array<{
    kill_chain_name: string;
    phase_name: string;
  }>;
}

export interface StixRelationship {
  type: "relationship";
  spec_version: "2.1";
  id: string;
  created: string;
  modified: string;
  relationship_type: "related-to";
  source_ref: string;
  target_ref: string;
  description: string;
}

export type StixObject = StixIndicator | StixAttackPattern | StixRelationship;

export function buildStixBundle(iocs: IpIoc[], generatedAt = new Date().toISOString()): StixBundle {
  return {
    type: "bundle",
    id: stixDeterministicId("bundle", generatedAt),
    spec_version: "2.1",
    objects: iocs.map((ioc) => stixIndicatorFromIpIoc(ioc))
  };
}

export function buildRichStixBundle({
  ips,
  artifacts,
  generatedAt = new Date().toISOString()
}: {
  ips: IpIoc[];
  artifacts: ArtifactIoc[];
  generatedAt?: string;
}): StixBundle {
  const objects: StixObject[] = [];
  const ipIndicatorIds = new Map<string, string>();

  for (const ioc of ips) {
    const indicator = stixIndicatorFromIpIoc(ioc);
    objects.push(indicator);
    ipIndicatorIds.set(ioc.source_ip, indicator.id);
  }

  for (const artifact of artifacts) {
    const indicator = stixIndicatorFromArtifact(artifact);
    objects.push(indicator);

    for (const sourceIp of artifact.source_ips ?? []) {
      const ipIndicatorId = ipIndicatorIds.get(sourceIp);
      if (!ipIndicatorId) continue;
      objects.push(
        stixRelationshipFromRefs(
          indicator.id,
          ipIndicatorId,
          artifact.last_seen,
          `Artifact observed from honeypot source IP ${sourceIp}`
        )
      );
    }
  }

  return {
    type: "bundle",
    id: stixDeterministicId("bundle", generatedAt),
    spec_version: "2.1",
    objects
  };
}

export function stixAttackPatternFromTechnique(technique: AttackTechnique): StixAttackPattern {
  return {
    type: "attack-pattern",
    spec_version: "2.1",
    id: stixDeterministicId("attack-pattern", technique.id),
    name: technique.name,
    description: `${technique.name} (${technique.id})`,
    external_references: [
      {
        source_name: "mitre-attack",
        external_id: technique.id,
        url: technique.url
      }
    ],
    kill_chain_phases: [
      {
        kill_chain_name: "mitre-attack",
        phase_name: technique.tactic
      }
    ]
  };
}

export function buildAttackStixBundle(
  techniques: AttackTechnique[],
  indicators: StixIndicator[],
  generatedAt = new Date().toISOString()
): StixBundle {
  const uniqueTechniques = new Map<string, AttackTechnique>();
  for (const technique of techniques) {
    uniqueTechniques.set(technique.id, technique);
  }

  return {
    type: "bundle",
    id: stixDeterministicId("bundle", `attack-${generatedAt}`),
    spec_version: "2.1",
    objects: [
      ...[...uniqueTechniques.values()].map((technique) => stixAttackPatternFromTechnique(technique)),
      ...indicators
    ]
  };
}

function stixIndicatorFromIpIoc(ioc: IpIoc): StixIndicator {
  const labels = [`confidence:${ioc.confidence}`, ...ioc.confidence_reasons.map((reason) => `reason:${reason}`)];
  if (ioc.country_code) labels.push(`country:${ioc.country_code}`);
  if (ioc.asn != null) labels.push(`asn:${ioc.asn}`);
  if (ioc.as_name) labels.push(`as_name:${ioc.as_name}`);

  return {
    type: "indicator",
    spec_version: "2.1",
    id: stixDeterministicId("indicator", `ip:${ioc.source_ip}`),
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

function stixIndicatorFromArtifact(artifact: ArtifactIoc): StixIndicator {
  const labels = [`confidence:${artifact.confidence}`, `artifact_type:${artifact.type}`];
  const pattern =
    artifact.type === "file"
      ? stixFilePattern(artifact.value)
      : artifact.type === "domain"
        ? stixDomainPattern(artifact.value)
        : stixUrlPattern(artifact.value);

  const name =
    artifact.type === "file"
      ? `Honeypot payload ${artifact.value.slice(0, 12)}…`
      : artifact.type === "domain"
        ? `Honeypot domain ${artifact.value}`
        : `Honeypot URI ${artifact.value}`;

  const description =
    artifact.type === "file"
      ? `Payload hash observed ${artifact.event_count} times across ${artifact.unique_ips} IPs`
      : `URI observed ${artifact.event_count} times across ${artifact.unique_ips} IPs`;

  return {
    type: "indicator",
    spec_version: "2.1",
    id: stixDeterministicId("indicator", `${artifact.type}:${artifact.value}`),
    created: artifact.first_seen,
    modified: artifact.last_seen,
    name,
    description,
    pattern,
    pattern_type: "stix",
    valid_from: artifact.first_seen,
    valid_until: artifact.last_seen,
    labels,
    confidence: artifact.confidence
  };
}

function stixRelationshipFromRefs(
  sourceRef: string,
  targetRef: string,
  modified: string,
  description: string
): StixRelationship {
  return {
    type: "relationship",
    spec_version: "2.1",
    id: stixDeterministicId("relationship", `${sourceRef}->${targetRef}`),
    created: modified,
    modified,
    relationship_type: "related-to",
    source_ref: sourceRef,
    target_ref: targetRef,
    description
  };
}

export function stixIpPattern(ip: string): string {
  const escaped = escapeStixValue(ip);
  const type = ip.includes(":") ? "ipv6-addr" : "ipv4-addr";
  return `[${type}:value = '${escaped}']`;
}

export function stixFilePattern(sha256: string): string {
  return `[file:hashes.'SHA-256' = '${escapeStixValue(sha256)}']`;
}

export function stixUrlPattern(url: string): string {
  return `[url:value = '${escapeStixValue(url)}']`;
}

export function stixDomainPattern(domain: string): string {
  return `[domain-name:value = '${escapeStixValue(domain)}']`;
}

function escapeStixValue(value: string): string {
  return value.replaceAll("'", "''");
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
