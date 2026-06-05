import { describe, expect, it } from "vitest";
import type { Finding } from "./api/client";
import { reportFindingPreview, reportFormatNote } from "./pages/Reports";

function finding(overrides: Partial<Finding>): Finding {
  return {
    id: "finding-1",
    session_id: "session-1",
    tool_id: "test",
    type: "vulnerability",
    severity: "medium",
    confidence: 0.8,
    cvss_score: 5,
    title: "Medium finding",
    description: "",
    remediation: "",
    url: "https://example.com",
    status: "open",
    created_at: "2026-06-05T12:00:00Z",
    ...overrides,
  };
}

describe("report composer helpers", () => {
  it("explains SARIF as machine-readable output", () => {
    expect(reportFormatNote("sarif")).toContain("CI/CD");
    expect(reportFormatNote("sarif")).toContain("not human reading");
  });

  it("orders included findings by report section priority", () => {
    const rows = [
      finding({ id: "low", severity: "low", title: "Low finding" }),
      finding({ id: "suppressed", severity: "critical", status: "suppressed", title: "Suppressed critical" }),
      finding({ id: "high", severity: "high", title: "High finding" }),
    ];

    expect(reportFindingPreview(rows, false).map((item) => item.id)).toEqual(["high", "low"]);
    expect(reportFindingPreview(rows, true).map((item) => item.id)).toEqual(["high", "low", "suppressed"]);
  });
});
