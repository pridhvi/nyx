import type cytoscape from "cytoscape";
import { type AttackGraphEdge, type AttackVector, type Finding, type SourceFinding, type Target } from "../api/client";

export function AttackGraph() {
  return (
    <section className="page">
      <header className="page-header">
        <div>
          <h1>Attack Paths</h1>
          <p>This workspace is being reworked.</p>
        </div>
      </header>
      <section className="panel attack-page-placeholder">
        <h2>Attack Paths is in progress</h2>
        <p>
          The previous graph and chain workspace has been hidden while it is redesigned.
          Findings, CVEs, Tool Runs, Reports, and LLM Analyst remain available for the selected session.
        </p>
      </section>
    </section>
  );
}

export function graphElements(targets: Target[], findings: Finding[], vectors: AttackVector[], sourceFindings: SourceFinding[] = [], graphEdges: AttackGraphEdge[] = []) {
  const elements: cytoscape.ElementDefinition[] = [];
  const nodeIDs = new Set<string>();
  let skippedEdges = 0;
  const addNode = (element: cytoscape.ElementDefinition) => {
    if (typeof element.data?.id === "string") {
      nodeIDs.add(element.data.id);
    }
    elements.push(element);
  };
  const addEdge = (element: cytoscape.ElementDefinition) => {
    const source = element.data?.source;
    const target = element.data?.target;
    if (typeof source === "string" && typeof target === "string" && nodeIDs.has(source) && nodeIDs.has(target)) {
      elements.push(element);
      return;
    }
    skippedEdges += 1;
  };
  for (const target of targets) {
    addNode({ data: { id: `target:${target.id}`, label: target.host, displayLabel: target.host, type: "target", weight: 3, detail: `${target.protocol}:${target.port} discovered by ${target.discovered_by}` } });
    for (const tech of target.technologies ?? []) {
      const techID = `tech:${tech.id}`;
      const label = `${tech.name} ${tech.version}`.trim();
      addNode({ data: { id: techID, label, displayLabel: label, type: "tech", weight: 2, detail: `${tech.category || "technology"} confidence ${Math.round(tech.confidence * 100)}%` } });
      addEdge({ data: { id: `edge:${target.id}:${tech.id}`, source: `target:${target.id}`, target: techID } });
    }
  }
  for (const finding of findings) {
    addNode({ data: { id: `finding:${finding.id}`, label: finding.title, displayLabel: "", type: "finding", weight: severityWeight(finding.severity), color: severityColor(finding.severity), detail: `${finding.severity} ${finding.type} from ${finding.tool_id}. ${finding.url}` } });
    if (finding.target_id) {
      addEdge({ data: { id: `edge:${finding.target_id}:${finding.id}`, source: `target:${finding.target_id}`, target: `finding:${finding.id}` } });
    }
  }
  for (const finding of sourceFindings) {
    addNode({ data: { id: `source:${finding.id}`, label: finding.kind, displayLabel: "", type: "source", weight: finding.confirmed_dynamic ? 3 : 2, detail: `${finding.file_path}:${finding.line_number} ${finding.value}` } });
  }
  for (const edge of graphEdges) {
      addEdge({ data: { id: `graph:${edge.id}`, source: edge.from_id, target: edge.to_id, label: edge.relation, type: "attack" } });
  }
  for (const vector of vectors) {
    addNode({ data: { id: `vector:${vector.id}`, label: vector.title, displayLabel: vector.title, type: "vector", weight: severityWeight(vector.severity), detail: `${vector.severity} confidence ${Math.round(vector.confidence * 100)}%. ${vector.narrative}` } });
    for (const findingID of vector.prereq_finding_ids ?? []) {
      addEdge({ data: { id: `edge:${findingID}:${vector.id}`, source: `finding:${findingID}`, target: `vector:${vector.id}`, type: "attack" } });
    }
  }
  return { elements, skippedEdges };
}

function severityColor(severity: string) {
  switch (severity) {
    case "critical": return "#ff3b5c";
    case "high": return "#ff7a30";
    case "medium": return "#f0c040";
    case "low": return "#30d58c";
    default: return "#4ca8ff";
  }
}

function severityWeight(severity: string) {
  switch (severity) {
    case "critical": return 5;
    case "high": return 4;
    case "medium": return 3;
    case "low": return 2;
    default: return 1;
  }
}
