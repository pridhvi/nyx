import { describe, expect, it } from "vitest";
import { buildAttackChains, chainForFinding, connectedNodeIDs, layoutAttackChain, relationLabel, type AttackChain } from "./pages/AttackGraph";
import type { AttackGraphEdge, AttackVector, Finding, ToolRecord } from "./api/client";
import { filterFindingsByID, findingOrigin } from "./pages/Findings";

describe("attack path helpers", () => {
  it("builds chains from vector findings and skips missing findings", () => {
    const findings = [finding("f1", "medium"), finding("f2", "high")];
    const vectors: AttackVector[] = [{
      id: "v1",
      title: "Vector",
      description: "Description",
      narrative: "Narrative",
      owasp_category: "A01",
      severity: "high",
      confidence: 0.8,
      steps: [
        { order: 2, description: "Use second finding", finding_id: "f2" },
        { order: 1, description: "Use first finding", finding_id: "f1" },
        { order: 3, description: "Missing", finding_id: "missing" },
      ],
      prereq_finding_ids: [],
    }];
    const tools = [tool("test", "vulnerability-scan", "Test Tool")];

    const chains = buildAttackChains(vectors, findings, [], tools);

    expect(chains).toHaveLength(1);
    expect(chains[0].nodes.map((node) => node.finding?.id)).toEqual(["f1", "f2"]);
    expect(chains[0].nodes[0].phase).toBe("Vulnerability Scan");
    expect(chains[0].nodes[0].toolName).toBe("Test Tool");
    expect(chains[0].edges[0]).toMatchObject({ source: "finding:f1", target: "finding:f2", label: "escalates to", authoritative: false });
    expect(chains[0].skippedFindingIDs).toEqual(["missing"]);
  });

  it("keeps manual vector steps visible as action nodes", () => {
    const findings = [finding("f1", "medium")];
    const vectors: AttackVector[] = [{
      id: "v1",
      title: "Manual chain",
      description: "",
      narrative: "",
      owasp_category: "A01",
      severity: "high",
      confidence: 0.7,
      steps: [
        { order: 1, description: "Review finding", finding_id: "f1" },
        { order: 2, description: "Manually verify exploitability" },
      ],
      prereq_finding_ids: ["f1"],
    }];

    const chains = buildAttackChains(vectors, findings);

    expect(chains[0].nodes).toHaveLength(2);
    expect(chains[0].nodes[0]).toMatchObject({ kind: "finding", id: "finding:f1" });
    expect(chains[0].nodes[1]).toMatchObject({ kind: "step", title: "Step 2", description: "Manually verify exploitability" });
    expect(chains[0].edges[0]).toMatchObject({ source: "finding:f1", target: "step:v1:2" });
  });

  it("uses authoritative graph edge labels when chain endpoints match", () => {
    const findings = [finding("f1", "medium"), finding("f2", "high")];
    const vectors: AttackVector[] = [{
      id: "v1",
      title: "Vector",
      description: "",
      narrative: "",
      owasp_category: "A03",
      severity: "high",
      confidence: 0.75,
      steps: [],
      prereq_finding_ids: ["f1", "f2"],
    }];
    const edges: AttackGraphEdge[] = [{ id: "e1", session_id: "s1", from_id: "finding:f1", to_id: "finding:f2", relation: "confirms", confidence: 0.9, created_at: "" }];

    const chains = buildAttackChains(vectors, findings, edges);

    expect(chains[0].edges[0]).toMatchObject({ id: "graph:e1", label: "confirms", authoritative: true });
    expect(relationLabel("inferred")).toBe("escalates to");
  });

  it("lays out multi-node chains left to right and centers single-node chains", () => {
    const chain = chainFixture();
    const layout = layoutAttackChain(chain);
    const single = layoutAttackChain({ ...chain, nodes: [chain.nodes[0]], edges: [] });

    expect(layout.nodes[1].position.x).toBeGreaterThan(layout.nodes[0].position.x);
    expect(single.nodes[0].position).toEqual({ x: 0, y: 0 });
    expect(single.edges).toEqual([]);
  });

  it("reports nodes connected to the active node for dimming rules", () => {
    const chain = chainFixture();
    const connected = connectedNodeIDs(chain.edges, "finding:f1");

    expect(connected.has("finding:f2")).toBe(true);
    expect(connected.has("finding:f3")).toBe(false);
  });

  it("filters findings by deep-linked id", () => {
    const findings = [finding("f1", "medium"), finding("f2", "high")];

    expect(filterFindingsByID(findings, "f2").map((item) => item.id)).toEqual(["f2"]);
    expect(filterFindingsByID(findings, "")).toHaveLength(2);
    expect(findingOrigin({ ...findings[0], target_id: "" })).toBe("static");
  });

  it("finds chains that contain a finding node for graph deep links", () => {
    const chain = chainFixture();

    expect(chainForFinding([chain], "f2")?.id).toBe("v1");
    expect(chainForFinding([chain], "missing")).toBeUndefined();
  });
});

function chainFixture(): AttackChain {
  const f1 = finding("f1", "medium");
  const f2 = finding("f2", "high");
  const f3 = finding("f3", "low");
  return {
    id: "v1",
    title: "Vector",
    description: "",
    narrative: "",
    severity: "high",
    confidence: 0.8,
    owasp: "A01",
    llmReviewed: false,
    llmNotes: "",
    skippedFindingIDs: [],
    nodes: [
      chainFindingNode(f1, 0),
      chainFindingNode(f2, 1),
      chainFindingNode(f3, 2),
    ],
    edges: [
      { id: "e1", source: "finding:f1", target: "finding:f2", relation: "inferred", label: "escalates to", confidence: 0.8, authoritative: false },
      { id: "e2", source: "finding:f2", target: "finding:f3", relation: "inferred", label: "escalates to", confidence: 0.8, authoritative: false },
    ],
  };
}

function chainFindingNode(item: Finding, order: number) {
  return {
    id: `finding:${item.id}`,
    kind: "finding" as const,
    finding: item,
    order,
    phase: "Vulnerability",
    toolName: "Tool",
    owasp: "A01",
    title: item.title,
    description: item.description,
    severity: item.severity,
    confidence: item.confidence,
    typeLabel: item.type,
  };
}

function finding(id: string, severity: string): Finding {
  return {
    id,
    session_id: "s1",
    target_id: "t1",
    tool_id: "test",
    type: "vulnerability",
    severity,
    confidence: 0.8,
    cvss_score: 5,
    title: `Finding ${id}`,
    description: "A test finding",
    remediation: "",
    url: "",
    created_at: "",
  };
}

function tool(id: string, phase: string, name: string): ToolRecord {
  return {
    id,
    name,
    phase,
    description: "",
    homepage_url: "",
    depends_on: [],
    kind: "builtin_http",
    default_enabled: true,
    installed: true,
    binary_path: "",
    version: "",
    install_hint: "",
    parameters: [],
  };
}
