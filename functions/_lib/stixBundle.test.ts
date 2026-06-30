import { describe, expect, it } from "vitest";
import type { AttackTechnique } from "./attackMapping";
import type { ArtifactIoc } from "./artifactIocs";
import type { IpIoc } from "./ipIocs";
import {
  buildAttackStixBundle,
  buildRichStixBundle,
  buildStixBundle,
  stixAttackPatternFromTechnique,
  stixDeterministicId,
  stixDomainPattern,
  stixFilePattern,
  stixIpPattern,
  stixUrlPattern,
  type StixIndicator
} from "./stixBundle";

describe("STIX bundle builder", () => {
  const sample: IpIoc = {
    source_ip: "203.0.113.10",
    first_seen: "2026-06-29T10:00:00.000Z",
    last_seen: "2026-06-30T12:00:00.000Z",
    confidence: 85,
    score: 8,
    confidence_reasons: ["credential_attempt", "multi_trap"],
    unique_traps: ["env", "admin"],
    protocols: ["http"],
    country_code: "US",
    asn: 15169,
    as_name: "Google LLC"
  };

  const artifact: ArtifactIoc = {
    type: "file",
    value: "a".repeat(64),
    first_seen: "2026-06-29T11:00:00.000Z",
    last_seen: "2026-06-30T11:00:00.000Z",
    confidence: 75,
    event_count: 3,
    unique_ips: 1,
    source_ips: ["203.0.113.10"]
  };

  it("builds a STIX 2.1 bundle with ipv4 indicators", () => {
    const bundle = buildStixBundle([sample], "2026-06-30T15:00:00.000Z");

    expect(bundle.type).toBe("bundle");
    expect(bundle.spec_version).toBe("2.1");
    expect(bundle.id).toMatch(/^bundle--[0-9a-f-]{36}$/);
    expect(bundle.objects).toHaveLength(1);

    const indicator = bundle.objects[0];
    expect(indicator?.type).toBe("indicator");
    if (!indicator || indicator.type !== "indicator") return;
    expect(indicator.spec_version).toBe("2.1");
    expect(indicator.pattern).toBe("[ipv4-addr:value = '203.0.113.10']");
    expect(indicator.pattern_type).toBe("stix");
    expect(indicator.valid_from).toBe(sample.first_seen);
    expect(indicator.valid_until).toBe(sample.last_seen);
    expect(indicator.confidence).toBe(85);
    expect(indicator.labels).toEqual([
      "confidence:85",
      "reason:credential_attempt",
      "reason:multi_trap",
      "country:US",
      "asn:15169",
      "as_name:Google LLC"
    ]);
  });

  it("uses ipv6 patterns for IPv6 addresses", () => {
    expect(stixIpPattern("2001:db8::1")).toBe("[ipv6-addr:value = '2001:db8::1']");
  });

  it("builds artifact patterns", () => {
    expect(stixFilePattern("a".repeat(64))).toBe(`[file:hashes.'SHA-256' = '${"a".repeat(64)}']`);
    expect(stixUrlPattern("https://evil.example/x")).toBe("[url:value = 'https://evil.example/x']");
    expect(stixDomainPattern("evil.example")).toBe("[domain-name:value = 'evil.example']");
  });

  it("builds rich bundles with relationships to observed IPs", () => {
    const bundle = buildRichStixBundle({
      ips: [sample],
      artifacts: [artifact],
      generatedAt: "2026-06-30T15:00:00.000Z"
    });

    expect(bundle.objects).toHaveLength(3);
    const indicators = bundle.objects.filter((object) => object.type === "indicator");
    const relationships = bundle.objects.filter((object) => object.type === "relationship");
    expect(indicators).toHaveLength(2);
    expect(relationships).toHaveLength(1);
    expect(relationships[0]).toMatchObject({
      relationship_type: "related-to",
      description: "Artifact observed from honeypot source IP 203.0.113.10"
    });
  });

  it("generates stable indicator ids per IP", () => {
    const first = stixDeterministicId("indicator", "203.0.113.10");
    const second = stixDeterministicId("indicator", "203.0.113.10");
    const other = stixDeterministicId("indicator", "198.51.100.4");

    expect(first).toBe(second);
    expect(first).not.toBe(other);
    expect(first).toMatch(/^indicator--[0-9a-f-]{36}$/);
  });

  it("builds attack-pattern objects from ATT&CK techniques", () => {
    const technique: AttackTechnique = {
      id: "T1190",
      name: "Exploit Public-Facing Application",
      tactic: "initial-access",
      url: "https://attack.mitre.org/techniques/T1190/"
    };

    const pattern = stixAttackPatternFromTechnique(technique);
    expect(pattern.type).toBe("attack-pattern");
    expect(pattern.name).toBe(technique.name);
    expect(pattern.external_references[0]).toMatchObject({
      source_name: "mitre-attack",
      external_id: "T1190",
      url: technique.url
    });
    expect(pattern.kill_chain_phases[0]).toMatchObject({
      kill_chain_name: "mitre-attack",
      phase_name: "initial-access"
    });
  });

  it("builds mixed attack-pattern and indicator bundles", () => {
    const technique: AttackTechnique = {
      id: "T1110.001",
      name: "Brute Force: Password Guessing",
      tactic: "credential-access",
      url: "https://attack.mitre.org/techniques/T1110/001/"
    };
    const ipBundle = buildStixBundle([sample]);
    const indicators = ipBundle.objects.filter((object): object is StixIndicator => object.type === "indicator");
    const bundle = buildAttackStixBundle([technique], indicators);

    expect(bundle.objects).toHaveLength(2);
    expect(bundle.objects[0]?.type).toBe("attack-pattern");
    expect(bundle.objects[1]?.type).toBe("indicator");
  });
});
