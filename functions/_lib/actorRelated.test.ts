import { describe, expect, it } from "vitest";
import { relatedIpsAmongActors } from "./actorRelated";

describe("relatedIpsAmongActors", () => {
  it("links actors with matching UA prefix and shared traps", () => {
    const trapSeqByIp = new Map([
      ["1.1.1.1", ["cowrie", "http-admin", "ftp"]],
      ["2.2.2.2", ["cowrie", "http-admin"]],
      ["3.3.3.3", ["cowrie", "http-admin"]]
    ]);
    const uaByIp = new Map([
      ["1.1.1.1", "scanner-a"],
      ["2.2.2.2", "scanner-a"],
      ["3.3.3.3", "other"]
    ]);

    const related = relatedIpsAmongActors(["1.1.1.1", "2.2.2.2", "3.3.3.3"], trapSeqByIp, uaByIp);
    expect([...(related.get("1.1.1.1") ?? [])]).toEqual(["2.2.2.2"]);
    expect([...(related.get("2.2.2.2") ?? [])]).toEqual(["1.1.1.1"]);
    expect(related.has("3.3.3.3")).toBe(false);
  });
});
