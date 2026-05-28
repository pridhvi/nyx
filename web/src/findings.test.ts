import { describe, expect, it } from "vitest";
import type { Finding } from "./api/client";
import { findingEvidenceObject, isHumanAssistFinding } from "./pages/Findings";

function finding(overrides: Partial<Finding>): Finding {
  return {
    id: "f1",
    session_id: "s1",
    target_id: "t1",
    tool_id: "test",
    type: "vulnerability",
    severity: "low",
    confidence: 0.45,
    cvss_score: 0,
    title: "Finding",
    description: "",
    remediation: "",
    url: "",
    created_at: "",
    ...overrides,
  };
}

describe("human assist finding helpers", () => {
  it("parses structured normalized evidence objects", () => {
    const parsed = findingEvidenceObject(finding({
      evidence_normalized: `{"human_assist":true,"indicators":["yaml-data"],"source":"route"}`,
    }));
    expect(parsed?.human_assist).toBe(true);
    expect(parsed?.source).toBe("route");
  });

  it("detects human-assist findings from normalized evidence, tags, or tool id", () => {
    expect(isHumanAssistFinding(finding({ evidence_normalized: `{"human_assist":true}` }))).toBe(true);
    expect(isHumanAssistFinding(finding({ tags: ["human-assist"] }))).toBe(true);
    expect(isHumanAssistFinding(finding({ tool_id: "deserialization-assist" }))).toBe(true);
    expect(isHumanAssistFinding(finding({ tool_id: "sqli-check", evidence_normalized: `{"validated":true}` }))).toBe(false);
  });

  it("ignores non-object and invalid normalized evidence", () => {
    expect(findingEvidenceObject(finding({ evidence_normalized: "not-json" }))).toBeNull();
    expect(findingEvidenceObject(finding({ evidence_normalized: `["human_assist"]` }))).toBeNull();
  });
});
