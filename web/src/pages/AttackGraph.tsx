import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import cytoscape from "cytoscape";
import { listAttackGraphEdges, listFindings, listSourceFindings, listTargets, listVectors, type AttackGraphEdge, type AttackVector, type Finding, type SourceFinding, type Target } from "../api/client";
import { useSessionContext } from "../session";

export function AttackGraph() {
  const { selectedSessionID: selected } = useSessionContext();
  const [severity, setSeverity] = useState("");
  const targetsQuery = useQuery({ queryKey: ["targets", selected], queryFn: () => listTargets(selected), enabled: selected !== "" });
  const findingsQuery = useQuery({ queryKey: ["findings", selected], queryFn: () => listFindings(selected), enabled: selected !== "" });
  const vectorsQuery = useQuery({ queryKey: ["vectors", selected], queryFn: () => listVectors(selected), enabled: selected !== "" });
  const sourceQuery = useQuery({ queryKey: ["source-findings", selected], queryFn: () => listSourceFindings(selected), enabled: selected !== "" });
  const edgesQuery = useQuery({ queryKey: ["attack-graph-edges", selected], queryFn: () => listAttackGraphEdges(selected), enabled: selected !== "" });

  const nodes = useMemo(() => {
    const targets = targetsQuery.data ?? [];
    const findings = (findingsQuery.data ?? []).filter((finding) => !severity || finding.severity === severity);
    const vectors = vectorsQuery.data ?? [];
    const sourceFindings = sourceQuery.data ?? [];
    const edges = edgesQuery.data ?? [];
    return { targets, findings, vectors, sourceFindings, edges };
  }, [edgesQuery.data, findingsQuery.data, severity, sourceQuery.data, targetsQuery.data, vectorsQuery.data]);
  const graphRef = useRef<HTMLDivElement | null>(null);
  const [selectedNode, setSelectedNode] = useState<{ label: string; detail: string } | null>(null);
  const [selectedVectorID, setSelectedVectorID] = useState("");

  useEffect(() => {
    if (!graphRef.current) {
      return;
    }
    const { elements } = graphElements(nodes.targets, nodes.findings, nodes.vectors, nodes.sourceFindings, nodes.edges);
    const graph = cytoscape({
      container: graphRef.current,
      elements,
      layout: { name: "cose", animate: false, padding: 36, nodeRepulsion: 9000, idealEdgeLength: 140, componentSpacing: 90 },
      style: [
        { selector: "node", style: { label: "data(label)", "font-family": "JetBrains Mono", "font-size": "10px", "font-weight": "600", color: "#e4e7f0", "text-valign": "bottom", "text-halign": "center", "text-margin-y": "10px", width: "mapData(weight, 1, 5, 54, 88)", height: "mapData(weight, 1, 5, 54, 88)", "text-wrap": "wrap", "text-max-width": "120px", "border-width": "2px", "border-color": "#2a2e47", "background-color": "#191c2b" } },
        { selector: "node[type='target']", style: { "background-color": "#7968f2", color: "#9585f8", shape: "round-rectangle" } },
        { selector: "node[type='tech']", style: { "background-color": "#4ca8ff", color: "#4ca8ff", shape: "ellipse" } },
        { selector: "node[type='finding']", style: { "background-color": "data(color)", color: "data(color)", shape: "diamond" } },
        { selector: "node[type='vector']", style: { "background-color": "#f0c040", color: "#f0c040", shape: "hexagon" } },
        { selector: "node[type='source']", style: { "background-color": "#30d58c", color: "#30d58c", shape: "tag" } },
        { selector: "node:selected", style: { "border-color": "#ffffff", "border-width": "5px" } },
        { selector: "edge", style: { "font-family": "JetBrains Mono", "font-size": "9px", color: "#a9b0c4", "text-background-color": "#07080e", "text-background-opacity": 0.9, "text-background-padding": "3px", width: "2px", "line-color": "#4e5468", "target-arrow-color": "#4e5468", "target-arrow-shape": "triangle", "curve-style": "bezier", "line-style": "dotted", opacity: 0.82 } },
        { selector: "edge[label]", style: { label: "data(label)" } },
        { selector: "edge[type='attack']", style: { width: "3px", "line-color": "#7968f2", "target-arrow-color": "#7968f2" } },
      ] as any,
    });
    graph.on("tap", "node", (event) => {
      const node = event.target;
      setSelectedNode({ label: node.data("label"), detail: node.data("detail") });
    });
    return () => graph.destroy();
  }, [nodes]);

  const graphData = useMemo(() => graphElements(nodes.targets, nodes.findings, nodes.vectors, nodes.sourceFindings, nodes.edges), [nodes]);

  return (
    <section className="page wide-page">
      <header className="page-header">
        <div>
          <h1>Attack Graph</h1>
          <p>Targets, source findings, dynamic findings, and labelled attack-chain edges.</p>
        </div>
        <label className="compact-control">
          Severity
          <select value={severity} onChange={(event) => setSeverity(event.target.value)}>
            <option value="">All</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
        </label>
      </header>
      <section className="panel">
        <div className="graph-toolbar">
          <h2>Interactive Graph</h2>
          <div className="graph-legend">
            <span><i className="legend-target" />Target</span>
            <span><i className="legend-tech" />Technology</span>
            <span><i className="legend-finding" />Finding</span>
            <span><i className="legend-vector" />Attack Vector</span>
            <span><i className="legend-source" />Source</span>
          </div>
        </div>
        <div className="cy-graph" ref={graphRef} />
        {graphData.skippedEdges > 0 ? <p className="graph-warning">Skipped {graphData.skippedEdges} graph edge{graphData.skippedEdges === 1 ? "" : "s"} with missing source or target data.</p> : null}
        {selectedNode ? (
          <div className="graph-detail">
            <strong>{selectedNode.label}</strong>
            <p>{selectedNode.detail}</p>
          </div>
        ) : null}
      </section>
      <div className="graph-summary">
        <article><span>Targets</span><strong>{nodes.targets.length}</strong></article>
        <article><span>Findings</span><strong>{nodes.findings.length}</strong></article>
        <article><span>Attack Vectors</span><strong>{nodes.vectors.length}</strong></article>
        <article><span>Source Findings</span><strong>{nodes.sourceFindings.length}</strong></article>
      </div>
      <div className="graph-layout">
        <section className="graph-column">
          <h2>Targets</h2>
          {nodes.targets.map((target) => (
            <article key={target.id} className="graph-node target-node">
              <strong>{target.host}</strong>
              <span>{target.protocol}:{target.port} · {target.discovered_by}</span>
              {(target.technologies ?? []).map((tech) => (
                <small key={tech.id}>{tech.name} {tech.version}</small>
              ))}
            </article>
          ))}
        </section>
        <section className="graph-column">
          <h2>Findings</h2>
          {nodes.findings.map((finding) => (
            <article key={finding.id} className={`graph-node finding-node ${finding.severity}`}>
              <span className={`severity ${finding.severity}`}>{finding.severity}</span>
              <span className={`origin-badge ${finding.tool_id.startsWith("audit/") ? "static" : "dynamic"}`}>{finding.tool_id.startsWith("audit/") ? "Static" : "Dynamic"}</span>
              <strong>{finding.title}</strong>
              <small>{finding.tool_id} · {finding.type}</small>
            </article>
          ))}
        </section>
        <section className="graph-column">
          <h2>Attack Vectors</h2>
          {nodes.vectors.map((vector) => (
            <article key={vector.id} className={`graph-node vector-node ${vector.severity} ${selectedVectorID === vector.id ? "selected-graph-node" : ""}`} onClick={() => setSelectedVectorID(vector.id)}>
              <span className={`severity ${vector.severity}`}>{vector.severity}</span>
              <strong>{vector.title}</strong>
              <small>{vector.owasp_category || "uncategorized"} · score {vectorScore(vector)} · confidence {Math.round(vector.confidence * 100)}%</small>
              {vector.steps.slice(0, 3).map((step) => <small key={step.order}>{step.order}. {step.description}</small>)}
            </article>
          ))}
        </section>
        <section className="graph-column">
          <h2>Source</h2>
          {nodes.sourceFindings.map((finding) => (
            <article key={finding.id} className="graph-node source-node">
              <span className={finding.confirmed_dynamic ? "origin-badge both" : "origin-badge static"}>{finding.confirmed_dynamic ? "Static + Dynamic" : "Static"}</span>
              <strong>{finding.kind}</strong>
              <small>{finding.file_path}:{finding.line_number}</small>
              <small>{finding.value}</small>
            </article>
          ))}
        </section>
      </div>
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
    addNode({ data: { id: `target:${target.id}`, label: target.host, type: "target", weight: 3, detail: `${target.protocol}:${target.port} discovered by ${target.discovered_by}` } });
    for (const tech of target.technologies ?? []) {
      const techID = `tech:${tech.id}`;
      addNode({ data: { id: techID, label: `${tech.name} ${tech.version}`.trim(), type: "tech", weight: 2, detail: `${tech.category || "technology"} confidence ${Math.round(tech.confidence * 100)}%` } });
      addEdge({ data: { id: `edge:${target.id}:${tech.id}`, source: `target:${target.id}`, target: techID } });
    }
  }
  for (const finding of findings) {
    addNode({ data: { id: `finding:${finding.id}`, label: finding.title, type: "finding", weight: severityWeight(finding.severity), color: severityColor(finding.severity), detail: `${finding.severity} ${finding.type} from ${finding.tool_id}. ${finding.url}` } });
    if (finding.target_id) {
      addEdge({ data: { id: `edge:${finding.target_id}:${finding.id}`, source: `target:${finding.target_id}`, target: `finding:${finding.id}` } });
    }
  }
  for (const finding of sourceFindings) {
    addNode({ data: { id: `source:${finding.id}`, label: finding.kind, type: "source", weight: finding.confirmed_dynamic ? 3 : 2, detail: `${finding.file_path}:${finding.line_number} ${finding.value}` } });
  }
  for (const edge of graphEdges) {
      addEdge({ data: { id: `graph:${edge.id}`, source: edge.from_id, target: edge.to_id, label: edge.relation, type: "attack" } });
  }
  for (const vector of vectors) {
    addNode({ data: { id: `vector:${vector.id}`, label: vector.title, type: "vector", weight: severityWeight(vector.severity), detail: `${vector.severity} confidence ${Math.round(vector.confidence * 100)}%. ${vector.narrative}` } });
    for (const findingID of vector.prereq_finding_ids ?? []) {
      addEdge({ data: { id: `edge:${findingID}:${vector.id}`, source: `finding:${findingID}`, target: `vector:${vector.id}`, type: "attack" } });
    }
  }
  return { elements, skippedEdges };
}

function vectorScore(vector: AttackVector) {
  return Math.round(severityWeight(vector.severity) * vector.confidence * 20);
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
