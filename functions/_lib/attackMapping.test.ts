import { describe, expect, it } from "vitest";
import {
  attackTechniqueIds,
  mapConfidenceReasonToTechniques,
  mapEventToTechniques,
  techniqueById
} from "./attackMapping";

describe("attackMapping", () => {
  it("maps scanner_user_agent confidence reason to T1595.002", () => {
    const techniques = mapConfidenceReasonToTechniques("scanner_user_agent");
    expect(techniques).toHaveLength(1);
    expect(techniques[0]).toMatchObject({
      id: "T1595.002",
      name: "Active Scanning: Vulnerability Scanning",
      tactic: "reconnaissance",
      url: "https://attack.mitre.org/techniques/T1595/002/"
    });
  });

  it("maps credential and exploit confidence reasons", () => {
    expect(mapConfidenceReasonToTechniques("credential_attempt").map((t) => t.id)).toEqual(["T1110"]);
    expect(mapConfidenceReasonToTechniques("exploit_path").map((t) => t.id)).toEqual(["T1190"]);
    expect(mapConfidenceReasonToTechniques("sensitive_path").map((t) => t.id)).toEqual(["T1110"]);
    expect(mapConfidenceReasonToTechniques("unknown_reason")).toEqual([]);
  });

  it("maps HTTP path patterns to ATT&CK techniques", () => {
    const traversal = mapEventToTechniques({
      protocol: "http",
      trap: "env",
      http_path: "/../../etc/passwd"
    });
    expect(traversal.map((t) => t.id)).toContain("T1190");

    const sql = mapEventToTechniques({
      protocol: "http",
      trap: "env",
      http_path: "/?id=1 union select password from users"
    });
    expect(sql.map((t) => t.id)).toContain("T1190");

    const shell = mapEventToTechniques({
      protocol: "http",
      trap: "env",
      http_path: "/cgi-bin/test?cmd=whoami"
    });
    expect(shell.map((t) => t.id)).toContain("T1059");

    const loginPath = mapEventToTechniques({
      protocol: "http",
      trap: "admin",
      http_path: "/wp-login.php"
    });
    expect(loginPath.map((t) => t.id)).toContain("T1110");
  });

  it("maps credential submissions to password guessing", () => {
    const techniques = mapEventToTechniques({
      protocol: "http",
      trap: "admin",
      has_credentials: true
    });
    expect(techniques.map((t) => t.id)).toContain("T1110.001");
  });

  it("maps ftp and smtp login traps to valid accounts", () => {
    const ftp = mapEventToTechniques({
      protocol: "ftp",
      trap: "ftp-login",
      has_credentials: true
    });
    expect(ftp.map((t) => t.id)).toContain("T1078");
    expect(ftp.map((t) => t.id)).toContain("T1110.001");

    const smtp = mapEventToTechniques({
      protocol: "smtp",
      trap: "smtp-relay",
      has_credentials: false
    });
    expect(smtp.map((t) => t.id)).toContain("T1078");
  });

  it("deduplicates techniques and returns stable ids", () => {
    const techniques = mapEventToTechniques({
      protocol: "http",
      trap: "admin",
      http_path: "/wp-login.php",
      has_credentials: true,
      confidence_reasons: ["credential_attempt", "sensitive_path", "scanner_user_agent"]
    });

    const ids = techniques.map((t) => t.id);
    expect(ids).toEqual([...new Set(ids)].sort());
    expect(ids).toEqual(expect.arrayContaining(["T1110", "T1110.001", "T1595.002"]));
    expect(attackTechniqueIds({
      protocol: "http",
      trap: "admin",
      http_path: "/wp-login.php",
      has_credentials: true,
      confidence_reasons: ["credential_attempt"]
    })).toEqual(ids.filter((id) => id !== "T1595.002"));
  });

  it("returns null for unknown technique ids", () => {
    expect(techniqueById("T9999")).toBeNull();
  });
});
