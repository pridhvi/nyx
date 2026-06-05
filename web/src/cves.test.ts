import { describe, expect, it } from "vitest";
import type { CVEMatch } from "./api/client";
import { cveSeverity, cveSourceKind, filterCVEs, packageLabel } from "./pages/CVEs";

function cve(overrides: Partial<CVEMatch>): CVEMatch {
  return {
    id: "cve-1",
    finding_id: "",
    cve_id: "CVE-2026-0001",
    cvss_v3_score: 7.5,
    description: "Demo",
    patch_available: false,
    exploit_available: false,
    source: "nvd",
    references: [],
    ...overrides,
  };
}

describe("CVE table helpers", () => {
  it("classifies severity from CVSS scores", () => {
    expect(cveSeverity(9.8)).toBe("critical");
    expect(cveSeverity(7.1)).toBe("high");
    expect(cveSeverity(4)).toBe("medium");
    expect(cveSeverity(0.1)).toBe("low");
    expect(cveSeverity(0)).toBe("info");
  });

  it("normalizes source categories for triage", () => {
    expect(cveSourceKind("source-audit/grype")).toBe("dependency");
    expect(cveSourceKind("osint-provider")).toBe("osint");
    expect(cveSourceKind("nvd")).toBe("dynamic");
  });

  it("builds package labels with detected versions", () => {
    expect(packageLabel(cve({ package_name: "openssl", package_version: "3.0.1" }))).toBe("openssl@3.0.1");
    expect(packageLabel(cve({ package_name: "openssl" }))).toBe("openssl");
  });

  it("filters by package, source, fixability, and exploitability", () => {
    const rows = [
      cve({ id: "fixable", package_name: "openssl", package_version: "3.0.1", fixed_version: "3.0.9", source: "source-audit/grype", exploit_available: true }),
      cve({ id: "unfixed", package_name: "nginx", package_version: "1.20.0", source: "nvd", exploit_available: false }),
    ];

    expect(filterCVEs(rows, { packageFilter: "openssl@3.0.1", sourceFilter: "", fixFilter: "fixable", exploitFilter: "exploitable" }).map((row) => row.id)).toEqual(["fixable"]);
    expect(filterCVEs(rows, { packageFilter: "", sourceFilter: "nvd", fixFilter: "unfixable", exploitFilter: "no-known-exploit" }).map((row) => row.id)).toEqual(["unfixed"]);
  });
});
