import { describe, expect, it } from "vitest";
import { classifyPath } from "./decoys.js";

describe("web decoys", () => {
  it("classifies common credential and config probes", () => {
    expect(classifyPath("/.env").trap).toBe("env-file");
    expect(classifyPath("/wp-login.php").tags).toContain("login");
    expect(classifyPath("/latest/meta-data/iam/security-credentials/").trap).toBe("cloud-metadata");
  });

  it("serves a legitimate-looking decoy site at the root", () => {
    const root = classifyPath("/");
    expect(root.trap).toBe("desktopc-homepage");
    expect(root.body).toContain("Managed desktop support");
  });
});
