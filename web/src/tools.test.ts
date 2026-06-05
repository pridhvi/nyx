import { describe, expect, it } from "vitest";
import type { ToolRecord } from "./api/client";
import { compactToolRows, toolInstallState } from "./pages/Tools";

describe("tool inventory helpers", () => {
  it("maps tools to compact table rows", () => {
    const rows = compactToolRows([
      tool({ id: "http-probe", kind: "builtin_http", installed: true, phase: "recon", binary_path: "", version: "built-in" }),
      tool({ id: "nuclei", installed: false, default_enabled: false, phase: "vuln_scan", binary_path: "" }),
    ]);

    expect(rows).toEqual([
      { id: "http-probe", name: "HTTP probe", phase: "Recon", version: "built-in", path: "built in", status: "ready" },
      { id: "nuclei", name: "HTTP probe", phase: "Vulnerability", version: "-", path: "-", status: "optional" },
    ]);
  });

  it("distinguishes ready, missing, and optional tools", () => {
    expect(toolInstallState(tool({ installed: true }))).toBe("ready");
    expect(toolInstallState(tool({ installed: false, default_enabled: true }))).toBe("missing");
    expect(toolInstallState(tool({ installed: false, default_enabled: false }))).toBe("optional");
  });
});

function tool(overrides: Partial<ToolRecord>): ToolRecord {
  return {
    id: "tool",
    name: "HTTP probe",
    description: "Checks if a host is reachable.",
    homepage_url: "",
    phase: "recon",
    depends_on: [],
    kind: "subprocess",
    default_enabled: true,
    installed: true,
    binary_path: "/usr/bin/tool",
    version: "",
    install_hint: "",
    parameters: [],
    ...overrides,
  };
}
