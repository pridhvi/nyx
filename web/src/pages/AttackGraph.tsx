import { useCallback, useEffect, useMemo, useState, type CSSProperties } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Controls,
  Handle,
  MiniMap,
  Position,
  ReactFlow,
  ReactFlowProvider,
  type Edge,
  type Node,
  type NodeProps,
  type ReactFlowInstance,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import dagre from "dagre";
import { Graph } from "@dagrejs/graphlib";
import { X } from "lucide-react";
import { useNavigate } from "react-router-dom";
import {
  listAttackGraphEdges,
  listFindings,
  listTools,
  listVectors,
  type AttackGraphEdge,
  type AttackVector,
  type Finding,
  type ToolRecord,
} from "../api/client";
import { useSessionContext } from "../session";

export const ATTACK_NODE_WIDTH = 220;
export const ATTACK_NODE_HEIGHT = 95;

type VectorStep = AttackVector["steps"][number];
type ChainRelation = AttackGraphEdge["relation"] | "inferred";

export type AttackChainNode = {
  id: string;
  kind: "finding" | "step";
  finding?: Finding;
  order: number;
  phase: string;
  toolName: string;
  owasp: string;
  title: string;
  description: string;
  severity: string;
  confidence: number;
  typeLabel: string;
  step?: VectorStep;
};

export type AttackChainEdge = {
  id: string;
  source: string;
  target: string;
  relation: ChainRelation;
  label: string;
  confidence: number;
  authoritative: boolean;
};

export type AttackChain = {
  id: string;
  title: string;
  description: string;
  narrative: string;
  severity: string;
  confidence: number;
  owasp: string;
  llmReviewed: boolean;
  llmNotes: string;
  nodes: AttackChainNode[];
  edges: AttackChainEdge[];
  skippedFindingIDs: string[];
};

type LayoutedChainNode = AttackChainNode & {
  position: { x: number; y: number };
};

type AttackNodeData = Record<string, unknown> & {
  node: AttackChainNode;
  selected: boolean;
  dimmed: boolean;
};

type AttackFlowNode = Node<AttackNodeData, "attackNode">;

const nodeTypes = { attackNode: AttackNodeCard };

export function AttackGraph() {
  const { selectedSessionID } = useSessionContext();
  const [activeChainID, setActiveChainID] = useState("");
  const [selectedNodeID, setSelectedNodeID] = useState("");
  const [hoveredNodeID, setHoveredNodeID] = useState("");
  const navigate = useNavigate();

  const vectorsQuery = useQuery({
    queryKey: ["attack-vectors", selectedSessionID],
    queryFn: () => listVectors(selectedSessionID),
    enabled: selectedSessionID !== "",
  });
  const findingsQuery = useQuery({
    queryKey: ["attack-path-findings", selectedSessionID],
    queryFn: () => listFindings(selectedSessionID),
    enabled: selectedSessionID !== "",
  });
  const edgesQuery = useQuery({
    queryKey: ["attack-graph-edges", selectedSessionID],
    queryFn: () => listAttackGraphEdges(selectedSessionID),
    enabled: selectedSessionID !== "",
  });
  const toolsQuery = useQuery({
    queryKey: ["attack-path-tools", selectedSessionID],
    queryFn: () => listTools(selectedSessionID || undefined),
    enabled: selectedSessionID !== "",
  });

  const chains = useMemo(() => buildAttackChains(
    vectorsQuery.data ?? [],
    findingsQuery.data ?? [],
    edgesQuery.data ?? [],
    toolsQuery.data ?? [],
  ), [edgesQuery.data, findingsQuery.data, toolsQuery.data, vectorsQuery.data]);

  useEffect(() => {
    if (chains.length === 0) {
      setActiveChainID("");
      setSelectedNodeID("");
      return;
    }
    if (!chains.some((chain) => chain.id === activeChainID)) {
      setActiveChainID(chains[0].id);
      setSelectedNodeID("");
    }
  }, [activeChainID, chains]);

  const activeChain = chains.find((chain) => chain.id === activeChainID) ?? chains[0];
  const activeNodeID = selectedNodeID || hoveredNodeID;
  const selectedNode = activeChain?.nodes.find((node) => node.id === selectedNodeID);
  const isLoading = vectorsQuery.isLoading || findingsQuery.isLoading || edgesQuery.isLoading || toolsQuery.isLoading;
  const error = vectorsQuery.error ?? findingsQuery.error ?? edgesQuery.error ?? toolsQuery.error;

  const selectChain = useCallback((chainID: string) => {
    setActiveChainID(chainID);
    setSelectedNodeID("");
    setHoveredNodeID("");
  }, []);

  const viewFinding = useCallback((findingID: string) => {
    if (!selectedSessionID) return;
    navigate(`/sessions/${selectedSessionID}/findings?finding_id=${encodeURIComponent(findingID)}`);
  }, [navigate, selectedSessionID]);

  return (
    <section className="page attack-paths-page">
      <header className="page-header">
        <div>
          <h1>Attack Paths</h1>
          <p>Review ranked chains as connected finding paths, with evidence kept in the Findings workspace.</p>
        </div>
      </header>

      {!selectedSessionID ? (
        <section className="panel attack-empty-panel">
          <h2>Select a Session</h2>
          <p>Choose a session to inspect attack chains.</p>
        </section>
      ) : null}

      {selectedSessionID && isLoading ? <AttackPathSkeleton /> : null}

      {selectedSessionID && error ? (
        <section className="panel attack-empty-panel">
          <h2>Attack Paths Unavailable</h2>
          <p>{error.message}</p>
        </section>
      ) : null}

      {selectedSessionID && !isLoading && !error && chains.length === 0 ? (
        <section className="panel attack-empty-panel">
          <h2>No Attack Chains Yet</h2>
          <p>Nyx has not generated attack vectors with linked findings for this session.</p>
        </section>
      ) : null}

      {selectedSessionID && !isLoading && !error && activeChain ? (
        <div className={`attack-paths-workspace ${selectedNode ? "detail-open" : ""}`}>
          <ChainSidebar chains={chains} activeChainID={activeChain.id} onSelect={selectChain} />
          <ReactFlowProvider>
            <AttackFlowCanvas
              chain={activeChain}
              activeNodeID={activeNodeID}
              selectedNodeID={selectedNodeID}
              onSelectNode={setSelectedNodeID}
              onHoverNode={setHoveredNodeID}
              onPaneClick={() => setSelectedNodeID("")}
            />
          </ReactFlowProvider>
          <NodeDetailPanel node={selectedNode} chain={activeChain} onClose={() => setSelectedNodeID("")} onViewFinding={viewFinding} />
        </div>
      ) : null}
    </section>
  );
}

function ChainSidebar({ chains, activeChainID, onSelect }: { chains: AttackChain[]; activeChainID: string; onSelect: (id: string) => void }) {
  return (
    <aside className="panel attack-chain-sidebar" aria-label="Attack chains">
      <div>
        <h2>Chains</h2>
        <p>{chains.length} ranked path{chains.length === 1 ? "" : "s"}</p>
      </div>
      <div className="attack-chain-list">
        {chains.map((chain) => (
          <button key={chain.id} className={`attack-chain-card ${chain.id === activeChainID ? "active" : ""}`} type="button" onClick={() => onSelect(chain.id)}>
            <span className={`severity ${chain.severity}`}>{chain.severity}</span>
            <strong>{chain.title}</strong>
            <small>{chain.nodes.length} step{chain.nodes.length === 1 ? "" : "s"} · {chain.owasp || "Unmapped"}</small>
            <ConfidenceBar value={chain.confidence} />
          </button>
        ))}
      </div>
    </aside>
  );
}

function AttackFlowCanvas({
  chain,
  activeNodeID,
  selectedNodeID,
  onSelectNode,
  onHoverNode,
  onPaneClick,
}: {
  chain: AttackChain;
  activeNodeID: string;
  selectedNodeID: string;
  onSelectNode: (id: string) => void;
  onHoverNode: (id: string) => void;
  onPaneClick: () => void;
}) {
  const [flow, setFlow] = useState<ReactFlowInstance<AttackFlowNode, Edge> | null>(null);
  const layout = useMemo(() => layoutAttackChain(chain), [chain]);
  const connected = useMemo(() => connectedNodeIDs(chain.edges, activeNodeID), [activeNodeID, chain.edges]);
  const nodes = useMemo<AttackFlowNode[]>(() => layout.nodes.map((node) => {
    const dimmed = Boolean(activeNodeID && node.id !== activeNodeID && !connected.has(node.id));
    return {
      id: node.id,
      type: "attackNode",
      position: node.position,
      data: { node, selected: node.id === selectedNodeID, dimmed },
      width: ATTACK_NODE_WIDTH,
      height: ATTACK_NODE_HEIGHT,
      draggable: false,
      selectable: true,
      style: { width: ATTACK_NODE_WIDTH, height: ATTACK_NODE_HEIGHT },
    };
  }), [activeNodeID, connected, layout.nodes, selectedNodeID]);
  const edges = useMemo<Edge[]>(() => chain.edges.map((edge) => {
    const highlighted = Boolean(activeNodeID && (edge.source === activeNodeID || edge.target === activeNodeID));
    const dimmed = Boolean(activeNodeID && !highlighted);
    return {
      id: edge.id,
      source: edge.source,
      target: edge.target,
      type: "smoothstep",
      label: edge.label,
      animated: highlighted,
      style: {
        opacity: dimmed ? 0.25 : 0.85,
        stroke: highlighted ? "var(--accent)" : "rgba(149, 133, 248, 0.46)",
        strokeWidth: highlighted ? 2.5 : 1.5,
      },
      labelStyle: {
        fill: highlighted ? "#f7f5ff" : "var(--text-2)",
        fontSize: 11,
        fontWeight: 700,
      },
      labelBgStyle: {
        fill: highlighted ? "rgba(121, 104, 242, 0.9)" : "rgba(13, 15, 26, 0.92)",
        fillOpacity: 1,
      },
      labelBgPadding: [10, 5],
      labelBgBorderRadius: 999,
    };
  }), [activeNodeID, chain.edges]);

  useEffect(() => {
    if (!flow || nodes.length === 0) return;
    const frame = window.requestAnimationFrame(() => {
      void flow.fitView({ padding: nodes.length === 1 ? 0.45 : 0.18, duration: 250 });
    });
    return () => window.cancelAnimationFrame(frame);
  }, [chain.id, flow, nodes.length]);

  return (
    <section className="panel attack-flow-panel">
      <div className="attack-flow-heading">
        <div>
          <span className={`severity ${chain.severity}`}>{chain.severity}</span>
          <h2>{chain.title}</h2>
        </div>
        <ConfidenceBar value={chain.confidence} />
      </div>
      <div className="attack-flow-canvas">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          fitView
          nodesDraggable={false}
          nodesConnectable={false}
          elementsSelectable
          onInit={setFlow}
          onNodeClick={(_, node) => onSelectNode(node.id)}
          onNodeMouseEnter={(_, node) => onHoverNode(node.id)}
          onNodeMouseLeave={() => onHoverNode("")}
          onPaneClick={onPaneClick}
          proOptions={{ hideAttribution: true }}
        >
          <MiniMap
            pannable
            zoomable
            nodeBorderRadius={8}
            nodeColor={(node) => severityColor(nodeSeverity(node))}
            nodeStrokeColor={() => "rgba(149, 133, 248, 0.55)"}
          />
          <Controls showInteractive={false} />
        </ReactFlow>
      </div>
    </section>
  );
}

function AttackNodeCard({ data }: NodeProps<AttackFlowNode>) {
  const { node, selected, dimmed } = data;
  return (
    <article className={`attack-flow-node ${node.kind} ${selected ? "selected" : ""} ${dimmed ? "dimmed" : ""}`} style={{ "--node-severity": severityColor(node.severity) } as CSSProperties}>
      <Handle className="attack-node-handle" type="target" position={Position.Left} />
      <div className="attack-node-topline">
        <span>{node.phase}</span>
        <span className={`severity ${node.severity}`}>{node.severity}</span>
      </div>
      <strong>{node.title}</strong>
      <p>{shortText(node.description || node.typeLabel, 92)}</p>
      <footer>
        <span>{node.owasp || "OWASP -"}</span>
        <span>{node.toolName}</span>
        <code>{node.finding?.id ?? `step ${node.order + 1}`}</code>
      </footer>
      <span className="attack-node-confidence" style={{ width: `${confidencePercent(node.confidence)}%` }} />
      <Handle className="attack-node-handle" type="source" position={Position.Right} />
    </article>
  );
}

function NodeDetailPanel({
  node,
  chain,
  onClose,
  onViewFinding,
}: {
  node?: AttackChainNode;
  chain: AttackChain;
  onClose: () => void;
  onViewFinding: (findingID: string) => void;
}) {
  return (
    <aside className={`panel attack-detail-panel ${node ? "open" : ""}`} aria-label="Attack node details" aria-hidden={!node}>
      {node ? (
        <>
          <div className="detail-header">
            <div>
              <span className="eyebrow">{node.phase}</span>
              <h2>{node.title}</h2>
            </div>
            <button className="icon-button detail-close-button" type="button" onClick={onClose} aria-label="Close attack node details">
              <X size={16} />
            </button>
          </div>
          <p>{node.description || "No description recorded for this step."}</p>
          <dl className="attack-detail-list">
            <div>
              <dt>Severity</dt>
              <dd><span className={`severity ${node.severity}`}>{node.severity}</span></dd>
            </div>
            <div>
              <dt>Confidence</dt>
              <dd><ConfidenceBar value={node.confidence} /></dd>
            </div>
            <div>
              <dt>OWASP</dt>
              <dd>{node.owasp || "Unmapped"}</dd>
            </div>
            <div>
              <dt>Tool</dt>
              <dd>{node.toolName}</dd>
            </div>
            <div>
              <dt>{node.finding ? "Finding ID" : "Step"}</dt>
              <dd><code>{node.finding?.id ?? `${node.order + 1}`}</code></dd>
            </div>
          </dl>
          {chain.llmReviewed || chain.llmNotes ? (
            <div className="attack-annotation">
              <strong>LLM annotation</strong>
              <p>{chain.llmNotes || "Reviewed by the configured analyst model."}</p>
            </div>
          ) : null}
          {node.finding ? <button className="primary" type="button" onClick={() => onViewFinding(node.finding!.id)}>View Finding</button> : null}
        </>
      ) : null}
    </aside>
  );
}

function AttackPathSkeleton() {
  return (
    <div className="attack-paths-workspace detail-open">
      <section className="panel attack-chain-sidebar">
        <span className="skeleton-line short" />
        <span className="skeleton-line" />
        <span className="skeleton-line" />
        <span className="skeleton-line" />
      </section>
      <section className="panel attack-flow-panel">
        <span className="skeleton-line short" />
        <div className="attack-flow-skeleton" />
      </section>
      <section className="panel attack-detail-panel open">
        <span className="skeleton-line short" />
        <span className="skeleton-line" />
        <span className="skeleton-line" />
      </section>
    </div>
  );
}

function ConfidenceBar({ value }: { value: number }) {
  return (
    <span className="confidence-meter" aria-label={`Confidence ${confidencePercent(value)} percent`}>
      <span style={{ width: `${confidencePercent(value)}%` }} />
    </span>
  );
}

export function buildAttackChains(vectors: AttackVector[], findings: Finding[], graphEdges: AttackGraphEdge[] = [], tools: ToolRecord[] = []): AttackChain[] {
  const findingsByID = new Map(findings.map((finding) => [finding.id, finding]));
  const toolsByID = new Map(tools.map((tool) => [tool.id, tool]));
  return vectors.flatMap((vector) => {
    const orderedSteps = [...(vector.steps ?? [])].sort((left, right) => left.order - right.order);
    const skippedFindingIDs: string[] = [];
    const usedFindingIDs = new Set<string>();
    const nodes = orderedSteps.length > 0
      ? orderedSteps.flatMap((step, index) => {
        if (!step.finding_id) {
          return [stepNode(vector, step, index)];
        }
        const finding = findingsByID.get(step.finding_id);
        if (!finding) {
          skippedFindingIDs.push(step.finding_id);
          return [];
        }
        if (usedFindingIDs.has(finding.id)) {
          return [stepNode(vector, step, index)];
        }
        usedFindingIDs.add(finding.id);
        return [findingNode(vector, finding, toolsByID.get(finding.tool_id), index, step)];
      })
      : uniqueInOrder(vector.prereq_finding_ids ?? []).flatMap((findingID, index) => {
        const finding = findingsByID.get(findingID);
        if (!finding) {
          skippedFindingIDs.push(findingID);
          return [];
        }
        return [findingNode(vector, finding, toolsByID.get(finding.tool_id), index)];
      });
    if (nodes.length === 0) return [];
    const edges = buildChainEdges(vector.id, nodes, graphEdges, vector.confidence);
    return [{
      id: vector.id,
      title: vector.title,
      description: vector.description,
      narrative: vector.narrative,
      severity: normalizeSeverity(vector.severity),
      confidence: vector.confidence,
      owasp: vector.owasp_category,
      llmReviewed: Boolean(vector.llm_reviewed),
      llmNotes: vector.llm_notes ?? "",
      nodes,
      edges,
      skippedFindingIDs,
    }];
  });
}

export function layoutAttackChain(chain: AttackChain): { nodes: LayoutedChainNode[]; edges: AttackChainEdge[] } {
  if (chain.nodes.length === 1) {
    return { nodes: [{ ...chain.nodes[0], position: { x: 0, y: 0 } }], edges: [] };
  }
  const graph = new Graph();
  graph.setGraph({ rankdir: "LR", nodesep: 60, ranksep: 100 });
  graph.setDefaultEdgeLabel(() => ({}));
  for (const node of chain.nodes) {
    graph.setNode(node.id, { width: ATTACK_NODE_WIDTH, height: ATTACK_NODE_HEIGHT });
  }
  for (const edge of chain.edges) {
    graph.setEdge(edge.source, edge.target);
  }
  dagre.layout(graph);
  return {
    nodes: chain.nodes.map((node) => {
      const layout = graph.node(node.id) as { x?: number; y?: number } | undefined;
      return {
        ...node,
        position: {
          x: (layout?.x ?? 0) - ATTACK_NODE_WIDTH / 2,
          y: (layout?.y ?? 0) - ATTACK_NODE_HEIGHT / 2,
        },
      };
    }),
    edges: chain.edges,
  };
}

export function connectedNodeIDs(edges: AttackChainEdge[], activeNodeID: string) {
  const connected = new Set<string>();
  if (!activeNodeID) return connected;
  for (const edge of edges) {
    if (edge.source === activeNodeID) connected.add(edge.target);
    if (edge.target === activeNodeID) connected.add(edge.source);
  }
  return connected;
}

export function relationLabel(relation: ChainRelation) {
  switch (relation) {
    case "enables": return "enables";
    case "amplifies": return "amplifies";
    case "requires": return "requires";
    case "confirms": return "confirms";
    case "inferred": return "escalates to";
  }
}

function buildChainEdges(vectorID: string, nodes: AttackChainNode[], graphEdges: AttackGraphEdge[], confidence: number) {
  const nodeIDs = new Set(nodes.map((node) => node.id));
  const authoritative = graphEdges.flatMap((edge) => {
    const source = findingNodeID(edge.from_id);
    const target = findingNodeID(edge.to_id);
    if (!source || !target || !nodeIDs.has(source) || !nodeIDs.has(target)) return [];
    return [{
      id: `graph:${edge.id}`,
      source,
      target,
      relation: edge.relation,
      label: relationLabel(edge.relation),
      confidence: edge.confidence,
      authoritative: true,
    }];
  });
  const byPair = new Map(authoritative.map((edge) => [`${edge.source}->${edge.target}`, edge]));
  const edges: AttackChainEdge[] = [];
  for (let index = 0; index < nodes.length - 1; index += 1) {
    const source = nodes[index].id;
    const target = nodes[index + 1].id;
    const existing = byPair.get(`${source}->${target}`);
    if (existing) {
      edges.push(existing);
      continue;
    }
    edges.push({
      id: `chain:${vectorID}:${source}:${target}`,
      source,
      target,
      relation: "inferred",
      label: relationLabel("inferred"),
      confidence,
      authoritative: false,
    });
  }
  const known = new Set(edges.map((edge) => edge.id));
  for (const edge of authoritative) {
    if (!known.has(edge.id)) edges.push(edge);
  }
  return edges;
}

function findingNode(vector: AttackVector, finding: Finding, tool: ToolRecord | undefined, index: number, step?: VectorStep): AttackChainNode {
  return {
    id: `finding:${finding.id}`,
    kind: "finding",
    finding,
    order: index,
    phase: displayPhase(tool?.phase || phaseForFinding(finding)),
    toolName: tool?.name || finding.tool_id,
    owasp: vector.owasp_category,
    title: finding.title,
    description: finding.description || step?.description || finding.url || finding.type,
    severity: normalizeSeverity(finding.severity),
    confidence: finding.confidence,
    typeLabel: finding.type,
    step,
  };
}

function stepNode(vector: AttackVector, step: VectorStep, index: number): AttackChainNode {
  return {
    id: `step:${vector.id}:${step.order || index + 1}`,
    kind: "step",
    order: index,
    phase: "Action",
    toolName: step.tool_suggested || "Nyx",
    owasp: vector.owasp_category,
    title: step.tool_suggested ? `Run ${step.tool_suggested}` : `Step ${step.order || index + 1}`,
    description: step.description,
    severity: normalizeSeverity(vector.severity),
    confidence: vector.confidence,
    typeLabel: "attack step",
    step,
  };
}

function findingNodeID(id: string) {
  if (id.startsWith("finding:")) return id;
  if (id.startsWith("source:") || id.startsWith("target:") || id.startsWith("tech:") || id.startsWith("vector:")) return "";
  return `finding:${id}`;
}

function nodeSeverity(node: Node) {
  const dataNode = node.data?.node;
  if (!dataNode || typeof dataNode !== "object" || !("severity" in dataNode)) return "info";
  return String(dataNode.severity);
}

function uniqueInOrder(values: string[]) {
  const seen = new Set<string>();
  return values.filter((value) => {
    if (seen.has(value)) return false;
    seen.add(value);
    return true;
  });
}

function normalizeSeverity(severity: string) {
  return ["critical", "high", "medium", "low", "info"].includes(severity) ? severity : "info";
}

function severityColor(severity: string) {
  switch (normalizeSeverity(severity)) {
    case "critical": return "#ff3b5c";
    case "high": return "#ff7a30";
    case "medium": return "#f0c040";
    case "low": return "#30d58c";
    default: return "#4ca8ff";
  }
}

function confidencePercent(value: number) {
  if (!Number.isFinite(value)) return 0;
  return Math.max(0, Math.min(100, Math.round(value * 100)));
}

function phaseForFinding(finding: Finding) {
  const key = `${finding.tool_id} ${finding.type}`.toLowerCase();
  if (finding.tool_id.startsWith("audit/")) return "source";
  if (key.includes("xss") || key.includes("sqli") || key.includes("injection") || key.includes("vulnerability") || key.includes("cve")) return "vulnerability";
  if (key.includes("route") || key.includes("endpoint") || key.includes("bucket") || key.includes("ffuf") || key.includes("enumer")) return "enumeration";
  if (key.includes("probe") || key.includes("header") || key.includes("whatweb") || key.includes("tech")) return "fingerprint";
  return "analysis";
}

function displayPhase(phase: string) {
  return phase.replace(/[-_]/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function shortText(value: string, max: number) {
  const normalized = value.replace(/\s+/g, " ").trim();
  if (normalized.length <= max) return normalized;
  return `${normalized.slice(0, max - 1).trim()}…`;
}
