import { describe, expect, it } from "vitest";
import type { AttackVector, Finding, SourceFinding } from "./api/client";
import { applyTriageFilters, attackChainsForFinding, buildTriageRecords, defaultSelectedFinding, findingEvidenceObject, isHumanAssistFinding } from "./pages/Findings";

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

function sourceFinding(overrides: Partial<SourceFinding>): SourceFinding {
  return {
    id: "sf1",
    session_id: "s1",
    kind: "sql_sink",
    language: "python",
    framework: "flask",
    file_path: "app.py",
    line_number: 12,
    value: "db.execute(query)",
    context: "db.execute(query)",
    confirmed_dynamic: false,
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

  it("keeps a visible selection or falls back to the first visible finding", () => {
    const rows = buildTriageRecords([
      finding({ id: "first", severity: "high" }),
      finding({ id: "second", severity: "medium" }),
    ], []);
    expect(defaultSelectedFinding("second", rows)?.id).toBe("second");
    expect(defaultSelectedFinding("missing", rows)?.id).toBe("first");
    expect(defaultSelectedFinding(undefined, [])).toBeNull();
  });

  it("unifies source findings with normalized findings for triage filters", () => {
    const rows = buildTriageRecords([
      finding({ id: "dynamic", tool_id: "sqlmap", severity: "high", evidence_normalized: `{"validated":true}` }),
    ], [
      sourceFinding({ id: "source", confirmed_dynamic: true }),
    ]);
    expect(rows.map((row) => row.id)).toEqual(["dynamic", "source:source"]);
    expect(applyTriageFilters(rows, { severity: "", origin: "both", status: "", evidenceKind: "cross-confirmed", category: "", tool: "", confirmation: "confirmed", suppression: "" }).map((row) => row.id)).toEqual(["source:source"]);
    expect(applyTriageFilters(rows, { severity: "high", origin: "", status: "", evidenceKind: "", category: "", tool: "sqlmap", confirmation: "", suppression: "unsuppressed" }).map((row) => row.id)).toEqual(["dynamic"]);
  });

  it("maps findings back to attack chains that reference them", () => {
    const vectors: AttackVector[] = [{
      id: "chain-1",
      title: "Exploit chain",
      description: "",
      narrative: "",
      owasp_category: "A01",
      severity: "high",
      confidence: 0.9,
      steps: [{ order: 2, description: "Use finding", finding_id: "finding-1" }],
      prereq_finding_ids: [],
    }, {
      id: "chain-2",
      title: "Prereq chain",
      description: "",
      narrative: "",
      owasp_category: "A05",
      severity: "medium",
      confidence: 0.6,
      steps: [],
      prereq_finding_ids: ["finding-1"],
    }];
    expect(attackChainsForFinding(vectors, "finding-1")).toEqual([
      { id: "chain-1", title: "Exploit chain", severity: "high", owasp: "A01", stepLabel: "2" },
      { id: "chain-2", title: "Prereq chain", severity: "medium", owasp: "A05", stepLabel: "1" },
    ]);
    expect(attackChainsForFinding(vectors, "missing")).toEqual([]);
  });
});
