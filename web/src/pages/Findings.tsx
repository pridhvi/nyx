import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { listFindings, updateFinding, type Finding } from "../api/client";
import { useSessionContext } from "../session";
import { sortLabel, useSortableRows } from "../sort";

export function Findings() {
  const queryClient = useQueryClient();
  const { selectedSessionID: selected } = useSessionContext();
  const [severity, setSeverity] = useState("");
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [selectedFindingIDs, setSelectedFindingIDs] = useState<Set<string>>(() => new Set());
  const [editSeverity, setEditSeverity] = useState("");
  const [editRemediation, setEditRemediation] = useState("");
  const [bulkSeverity, setBulkSeverity] = useState("");
  const [bulkRemediation, setBulkRemediation] = useState("");
  const findingsQuery = useQuery({
    queryKey: ["findings-page", selected, severity],
    queryFn: () => listFindings(selected, severity ? { severity } : {}),
    enabled: selected !== "",
  });
  const findings = findingsQuery.data ?? [];
  type FindingSortKey = "severity" | "origin" | "type" | "tool" | "title" | "cves" | "evidence";
  const accessors = useMemo<Record<FindingSortKey, (finding: Finding) => string | number>>(() => ({
    severity: (finding: Finding) => severityRank(finding.severity),
    origin: (finding: Finding) => findingOrigin(finding),
    type: (finding: Finding) => finding.type,
    tool: (finding: Finding) => finding.tool_id,
    title: (finding: Finding) => finding.title,
    cves: (finding: Finding) => (finding.cve_matches ?? []).map((cve) => cve.cve_id).join(", "),
    evidence: (finding: Finding) => finding.evidence_normalized || finding.evidence_raw || "",
  }), []);
  const { sortedRows: sortedFindings, sort, toggleSort } = useSortableRows<Finding, FindingSortKey>(findings, { key: "severity", direction: "desc" }, accessors);
  const selectedCount = selectedFindingIDs.size;
  const allVisibleSelected = sortedFindings.length > 0 && sortedFindings.every((finding) => selectedFindingIDs.has(finding.id));
  const updateMutation = useMutation({
    mutationFn: () => updateFinding(selected, selectedFinding?.id ?? "", { severity: editSeverity, remediation: editRemediation }),
    onSuccess: (finding) => {
      setSelectedFinding(finding);
      queryClient.invalidateQueries({ queryKey: ["findings-page", selected] });
      queryClient.invalidateQueries({ queryKey: ["findings", selected] });
      queryClient.invalidateQueries({ queryKey: ["session-stats", selected] });
    },
  });
  const bulkUpdateMutation = useMutation({
    mutationFn: async () => {
      const payload = {
        severity: bulkSeverity || undefined,
        remediation: bulkRemediation || undefined,
      };
      await Promise.all(Array.from(selectedFindingIDs).map((findingID) => updateFinding(selected, findingID, payload)));
    },
    onSuccess: () => {
      setSelectedFindingIDs(new Set());
      setBulkSeverity("");
      setBulkRemediation("");
      queryClient.invalidateQueries({ queryKey: ["findings-page", selected] });
      queryClient.invalidateQueries({ queryKey: ["findings", selected] });
      queryClient.invalidateQueries({ queryKey: ["session-stats", selected] });
    },
  });

  function openFinding(finding: Finding) {
    setSelectedFinding(finding);
    setEditSeverity(finding.severity);
    setEditRemediation(finding.remediation ?? "");
  }

  function toggleFindingSelection(findingID: string) {
    setSelectedFindingIDs((current) => {
      const next = new Set(current);
      if (next.has(findingID)) {
        next.delete(findingID);
      } else {
        next.add(findingID);
      }
      return next;
    });
  }

  function toggleVisibleSelection() {
    setSelectedFindingIDs((current) => {
      const next = new Set(current);
      if (allVisibleSelected) {
        sortedFindings.forEach((finding) => next.delete(finding.id));
      } else {
        sortedFindings.forEach((finding) => next.add(finding.id));
      }
      return next;
    });
  }

  return (
    <section className="page">
      <header className="page-header">
        <div>
          <h1>Findings</h1>
          <p>Review normalized findings, CVEs, remediation, and persisted evidence.</p>
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
      <section className="panel bulk-panel">
        <div>
          <h2>Bulk Workflow</h2>
          <p>{selectedCount} selected finding{selectedCount === 1 ? "" : "s"}</p>
        </div>
        <label className="compact-control">
          Severity
          <select value={bulkSeverity} onChange={(event) => setBulkSeverity(event.target.value)}>
            <option value="">Keep current</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
        </label>
        <label className="bulk-remediation">
          Remediation
          <input value={bulkRemediation} onChange={(event) => setBulkRemediation(event.target.value)} placeholder="Leave blank to keep current remediation" />
        </label>
        <button
          className="primary"
          type="button"
          onClick={() => bulkUpdateMutation.mutate()}
          disabled={selectedCount === 0 || (!bulkSeverity && !bulkRemediation) || bulkUpdateMutation.isPending}
        >
          {bulkUpdateMutation.isPending ? "Applying" : "Apply"}
        </button>
        {selectedCount > 0 ? <button className="secondary" type="button" onClick={() => setSelectedFindingIDs(new Set())}>Clear</button> : null}
        {bulkUpdateMutation.error ? <p className="error-text">{bulkUpdateMutation.error.message}</p> : null}
      </section>
      <section className="panel">
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>
                  <input
                    type="checkbox"
                    aria-label="Select visible findings"
                    checked={allVisibleSelected}
                    onChange={toggleVisibleSelection}
                  />
                </th>
                <SortableHeader label="Severity" active={sort.key === "severity"} direction={sort.direction} onClick={() => toggleSort("severity")} />
                <SortableHeader label="Source" active={sort.key === "origin"} direction={sort.direction} onClick={() => toggleSort("origin")} />
                <SortableHeader label="Type" active={sort.key === "type"} direction={sort.direction} onClick={() => toggleSort("type")} />
                <SortableHeader label="Tool" active={sort.key === "tool"} direction={sort.direction} onClick={() => toggleSort("tool")} />
                <SortableHeader label="Title" active={sort.key === "title"} direction={sort.direction} onClick={() => toggleSort("title")} />
                <SortableHeader label="CVEs" active={sort.key === "cves"} direction={sort.direction} onClick={() => toggleSort("cves")} />
                <SortableHeader label="Evidence" active={sort.key === "evidence"} direction={sort.direction} onClick={() => toggleSort("evidence")} />
              </tr>
            </thead>
            <tbody>
              {sortedFindings.map((finding) => (
                <tr key={finding.id} className={selectedFinding?.id === finding.id ? "selected-row" : ""} onClick={() => openFinding(finding)}>
                  <td onClick={(event) => event.stopPropagation()}>
                    <input
                      type="checkbox"
                      aria-label={`Select ${finding.title}`}
                      checked={selectedFindingIDs.has(finding.id)}
                      onChange={() => toggleFindingSelection(finding.id)}
                    />
                  </td>
                  <td><span className={`severity ${finding.severity}`}>{finding.severity}</span></td>
                  <td><span className={`origin-badge ${findingOrigin(finding)}`}>{originLabel(findingOrigin(finding))}</span>{finding.status ? <small>{finding.status}</small> : null}</td>
                  <td>{finding.type}</td>
                  <td>{finding.tool_id}</td>
                  <td>{finding.title}<small>{finding.url}</small></td>
                  <td>{(finding.cve_matches ?? []).map((cve) => cve.cve_id).join(", ") || "-"}</td>
                  <td><code>{finding.evidence_normalized || finding.evidence_raw || "-"}</code></td>
                </tr>
              ))}
              {findings.length === 0 ? <tr><td colSpan={8}>No findings for the selected filters.</td></tr> : null}
            </tbody>
          </table>
        </div>
      </section>
      {selectedFinding ? (
        <section className="panel finding-detail-panel">
          <div className="detail-header">
            <div>
              <h2>{selectedFinding.title}</h2>
              <p>{selectedFinding.tool_id} · {selectedFinding.type} · {originLabel(findingOrigin(selectedFinding))} · {selectedFinding.url || "no URL"}</p>
            </div>
            <button className="secondary" onClick={() => setSelectedFinding(null)}>Close</button>
          </div>
          <div className="finding-editor">
            <label className="compact-control">
              Severity
              <select value={editSeverity} onChange={(event) => setEditSeverity(event.target.value)}>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Info</option>
              </select>
            </label>
            <label>
              Remediation
              <textarea value={editRemediation} onChange={(event) => setEditRemediation(event.target.value)} rows={4} />
            </label>
            <button className="primary" onClick={() => updateMutation.mutate()} disabled={updateMutation.isPending}>
              {updateMutation.isPending ? "Saving" : "Save Changes"}
            </button>
          </div>
          {updateMutation.error ? <p className="error-text">{updateMutation.error.message}</p> : null}
          <div className="evidence-grid">
            <article>
              <h3>Normalized Evidence</h3>
              <pre>{selectedFinding.evidence_normalized || "-"}</pre>
            </article>
            <article>
              <h3>Raw Evidence</h3>
              <pre>{selectedFinding.evidence_raw || "-"}</pre>
            </article>
            <article>
              <h3>HTTP Request</h3>
              <pre>{selectedFinding.http_evidence?.request_raw || "-"}</pre>
            </article>
            <article>
              <h3>HTTP Response</h3>
              <pre>{selectedFinding.http_evidence?.response_raw || "-"}</pre>
            </article>
            <article>
              <h3>Code Context</h3>
              <pre>{selectedFinding.code_context || selectedFinding.flow_summary || selectedFinding.notes || "-"}</pre>
            </article>
          </div>
        </section>
      ) : null}
    </section>
  );
}

function SortableHeader({ label, active, direction, onClick }: { label: string; active: boolean; direction: "asc" | "desc"; onClick: () => void }) {
  return <th><button className="table-sort" type="button" onClick={onClick}>{label}{sortLabel(active, direction)}</button></th>;
}

function severityRank(severity: string) {
  return { info: 1, low: 2, medium: 3, high: 4, critical: 5 }[severity] ?? 0;
}

function findingOrigin(finding: Finding) {
  const isStatic = finding.tool_id.startsWith("audit/") || !finding.target_id;
  const hasDynamic = Boolean(finding.target_id);
  if (isStatic && hasDynamic) return "both";
  return isStatic ? "static" : "dynamic";
}

function originLabel(origin: string) {
  if (origin === "both") return "Static + Dynamic";
  return origin === "static" ? "Static" : "Dynamic";
}
