import { describe, expect, it } from "vitest";
import { TCP_TRAPS, UDP_TRAPS } from "./protocols.js";

describe("protocol trap coverage", () => {
  it("covers the planned low-interaction services", () => {
    const protocols = new Set([...TCP_TRAPS.map((trap) => trap.protocol), ...UDP_TRAPS.map((trap) => trap.protocol)]);
    for (const protocol of ["ftp", "smtp", "http-proxy", "mysql", "mssql", "redis", "rdp", "smb", "snmp", "tftp", "vnc"]) {
      expect(protocols.has(protocol)).toBe(true);
    }
  });
});
