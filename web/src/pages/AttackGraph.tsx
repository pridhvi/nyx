import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useParams } from "react-router-dom";
import { listFindings, listSessions, listTargets, listVectors } from "../api/client";

export function AttackGraph() {
  const params = useParams();
  const sessionsQuery = useQuery({ queryKey: ["sessions"], queryFn: listSessions });
  const selected = params.sessionID ?? sessionsQuery.data?.[0]?.session.id ?? "";
  const [severity, setSeverity] = useState("");
  const targetsQuery = useQuery({ queryKey: ["targets", selected], queryFn: () => listTargets(selected), enabled: selected !== "" });
  const findingsQuery = useQuery({ queryKey: ["findings", selected], queryFn: () => listFindings(selected), enabled: selected !== "" });
  const vectorsQuery = useQuery({ queryKey: ["vectors", selected], queryFn: () => listVectors(selected), enabled: selected !== "" });

  const nodes = useMemo(() => {
    const targets = targetsQuery.data ?? [];
    const findings = (findingsQuery.data ?? []).filter((finding) => !severity || finding.severity === severity);
    const vectors = vectorsQuery.data ?? [];
    return { targets, findings, vectors };
  }, [findingsQuery.data, severity, targetsQuery.data, vectorsQuery.data]);

  return (
    <section className="page">
      <header className="page-header">
        <div>
          <h1>Attack Graph</h1>
          <p>Targets, findings, technologies, and deterministic attack chains.</p>
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
              <strong>{finding.title}</strong>
              <small>{finding.tool_id} · {finding.type}</small>
            </article>
          ))}
        </section>
        <section className="graph-column">
          <h2>Attack Vectors</h2>
          {nodes.vectors.map((vector) => (
            <article key={vector.id} className={`graph-node vector-node ${vector.severity}`}>
              <span className={`severity ${vector.severity}`}>{vector.severity}</span>
              <strong>{vector.title}</strong>
              <small>{vector.owasp_category || "uncategorized"} · confidence {Math.round(vector.confidence * 100)}%</small>
              {vector.steps.slice(0, 3).map((step) => <small key={step.order}>{step.order}. {step.description}</small>)}
            </article>
          ))}
        </section>
      </div>
    </section>
  );
}
