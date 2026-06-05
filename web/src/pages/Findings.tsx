import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { X } from "lucide-react";
import { useSearchParams } from "react-router-dom";
import { listFindings, updateFinding, type Finding, type FindingStatus } from "../api/client";
import { useSessionContext } from "../session";
import { sortLabel, useSortableRows } from "../sort";

export function Findings() {
  const queryClient = useQueryClient();
  const { selectedSessionID: selected } = useSessionContext();
  const [searchParams] = useSearchParams();
  const focusedFindingID = searchParams.get("finding_id")?.trim() ?? "";
  const [severity, setSeverity] = useState("");
  const [origin, setOrigin] = useState("");
  const [status, setStatus] = useState("");
  const [evidenceKind, setEvidenceKind] = useState("");
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [selectedFindingIDs, setSelectedFindingIDs] = useState<Set<string>>(() => new Set());
  const [editSeverity, setEditSeverity] = useState("");
  const [editStatus, setEditStatus] = useState<FindingStatus>("open");
  const [editRemediation, setEditRemediation] = useState("");
  const [bulkSeverity, setBulkSeverity] = useState("");
  const [bulkStatus, setBulkStatus] = useState("");
  const [bulkRemediation, setBulkRemediation] = useState("");
  const [evidenceTab, setEvidenceTab] = useState<"normalized" | "raw" | "http" | "cves" | "code">("normalized");
  const [dismissedFindingSignature, setDismissedFindingSignature] = useState("");
  const sessionFindingsQuery = useQuery({
    queryKey: ["findings-page-all", selected],
    queryFn: () => listFindings(selected),
    enabled: selected !== "",
  });
  const findingsQuery = useQuery({
    queryKey: ["findings-page", selected, severity, origin, status],
    queryFn: () => listFindings(selected, cleanFilters({ severity, origin, status })),
    enabled: selected !== "",
  });
  const allFindings = findingsQuery.data ?? [];
  const evidenceFilteredFindings = evidenceKind === "human-assist" ? allFindings.filter(isHumanAssistFinding) : allFindings;
  const findings = filterFindingsByID(evidenceFilteredFindings, focusedFindingID);
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
  const visibleFindingSignature = useMemo(() => sortedFindings.map((finding) => finding.id).join("|"), [sortedFindings]);
  const selectedCount = selectedFindingIDs.size;
  const allVisibleSelected = sortedFindings.length > 0 && sortedFindings.every((finding) => selectedFindingIDs.has(finding.id));
  const hasStoredFindings = (sessionFindingsQuery.data ?? []).length > 0;
  const hasVisibleFindings = sortedFindings.length > 0;
  const hasFilters = Boolean(severity || origin || status || evidenceKind || focusedFindingID);
  const emptyMessage = !selected
    ? "Select a session to review findings."
    : findingsQuery.isLoading || sessionFindingsQuery.isLoading
      ? "Loading findings."
      : focusedFindingID
        ? `No finding matches ${focusedFindingID}.`
      : hasStoredFindings && hasFilters
        ? "No findings match the current filters."
        : "No findings yet for the selected session.";
  const updateMutation = useMutation({
    mutationFn: () => updateFinding(selected, selectedFinding?.id ?? "", { severity: editSeverity, status: editStatus, remediation: editRemediation }),
    onSuccess: (finding) => {
      setSelectedFinding(finding);
      queryClient.invalidateQueries({ queryKey: ["findings-page-all", selected] });
      queryClient.invalidateQueries({ queryKey: ["findings-page", selected] });
      queryClient.invalidateQueries({ queryKey: ["findings", selected] });
      queryClient.invalidateQueries({ queryKey: ["session-stats", selected] });
    },
  });
  const bulkUpdateMutation = useMutation({
    mutationFn: async () => {
      const payload = {
        severity: bulkSeverity || undefined,
        status: (bulkStatus || undefined) as FindingStatus | undefined,
        remediation: bulkRemediation || undefined,
      };
      await Promise.all(Array.from(selectedFindingIDs).map((findingID) => updateFinding(selected, findingID, payload)));
    },
    onSuccess: () => {
      setSelectedFindingIDs(new Set());
      setBulkSeverity("");
      setBulkStatus("");
      setBulkRemediation("");
      queryClient.invalidateQueries({ queryKey: ["findings-page-all", selected] });
      queryClient.invalidateQueries({ queryKey: ["findings-page", selected] });
      queryClient.invalidateQueries({ queryKey: ["findings", selected] });
      queryClient.invalidateQueries({ queryKey: ["session-stats", selected] });
    },
  });

  function openFinding(finding: Finding) {
    setDismissedFindingSignature("");
    setSelectedFinding(finding);
    setEditSeverity(finding.severity);
    setEditStatus(finding.status ?? "open");
    setEditRemediation(finding.remediation ?? "");
    setEvidenceTab("normalized");
  }

  function closeFindingDetails() {
    setDismissedFindingSignature(visibleFindingSignature);
    setSelectedFinding(null);
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

  useEffect(() => {
    const nextFinding = defaultSelectedFinding(selectedFinding?.id, sortedFindings);
    if (!nextFinding) {
      if (selectedFinding) {
        setSelectedFinding(null);
      }
      if (dismissedFindingSignature) {
        setDismissedFindingSignature("");
      }
      return;
    }
    if (!selectedFinding && dismissedFindingSignature === visibleFindingSignature) {
      return;
    }
    if (nextFinding.id !== selectedFinding?.id) {
      setSelectedFinding(nextFinding);
      setEditSeverity(nextFinding.severity);
      setEditStatus(nextFinding.status ?? "open");
      setEditRemediation(nextFinding.remediation ?? "");
      setEvidenceTab("normalized");
    }
  }, [dismissedFindingSignature, selectedFinding, selectedFinding?.id, sortedFindings, visibleFindingSignature]);

  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") {
        setDismissedFindingSignature(visibleFindingSignature);
        setSelectedFinding(null);
      }
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [visibleFindingSignature]);

  return (
    <section className="page">
      <header className="page-header">
        <div>
          <h1>Findings</h1>
          <p>Review normalized findings, CVEs, remediation, and persisted evidence.</p>
        </div>
      </header>
      {hasStoredFindings ? <section className="filter-bar">
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
        <label className="compact-control">
          Origin
          <select value={origin} onChange={(event) => setOrigin(event.target.value)}>
            <option value="">All</option>
            <option value="dynamic">Dynamic</option>
            <option value="static">Static</option>
          </select>
        </label>
        <label className="compact-control">
          Status
          <select value={status} onChange={(event) => setStatus(event.target.value)}>
            <option value="">All</option>
            <option value="open">Open</option>
            <option value="confirmed">Confirmed</option>
            <option value="false-positive">False Positive</option>
            <option value="suppressed">Suppressed</option>
            <option value="wont-fix">Won't Fix</option>
          </select>
        </label>
        <label className="compact-control">
          Evidence
          <select value={evidenceKind} onChange={(event) => setEvidenceKind(event.target.value)}>
            <option value="">All</option>
            <option value="human-assist">Human Assist</option>
          </select>
        </label>
      </section> : null}
      {hasVisibleFindings ? <section className="panel bulk-panel">
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
        <label className="compact-control">
          Status
          <select value={bulkStatus} onChange={(event) => setBulkStatus(event.target.value)}>
            <option value="">Keep current</option>
            <option value="open">Open</option>
            <option value="confirmed">Confirmed</option>
            <option value="false-positive">False Positive</option>
            <option value="suppressed">Suppressed</option>
            <option value="wont-fix">Won't Fix</option>
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
          disabled={selectedCount === 0 || (!bulkSeverity && !bulkStatus && !bulkRemediation) || bulkUpdateMutation.isPending}
        >
          {bulkUpdateMutation.isPending ? "Applying" : "Apply"}
        </button>
        {selectedCount > 0 ? <button className="secondary" type="button" onClick={() => setSelectedFindingIDs(new Set())}>Clear</button> : null}
        {bulkUpdateMutation.error ? <p className="error-text">{bulkUpdateMutation.error.message}</p> : null}
      </section> : null}
      {!hasVisibleFindings ? <section className="panel empty-state-panel"><h2>{hasStoredFindings && hasFilters ? "No Matching Findings" : "No Findings"}</h2><p>{emptyMessage}</p></section> : null}
      {hasVisibleFindings ? (
      <div className="split-workspace triage-workspace">
      <section className="panel">
        <div className="finding-card-list">
          {sortedFindings.map((finding) => (
            <article key={finding.id} className={`finding-card ${finding.severity} ${selectedFinding?.id === finding.id ? "selected-row" : ""}`}>
              <div className="finding-card-top">
                <input
                  type="checkbox"
                  aria-label={`Select ${finding.title}`}
                  checked={selectedFindingIDs.has(finding.id)}
                  onChange={() => toggleFindingSelection(finding.id)}
                />
                <span className={`severity ${finding.severity}`}>{finding.severity}</span>
                <span className={`origin-badge ${findingOrigin(finding)}`}>{originLabel(findingOrigin(finding))}</span>
                {isHumanAssistFinding(finding) ? <span className="assist-badge">Human Assist</span> : null}
                {finding.status ? <span className={`status ${finding.status}`}>{finding.status}</span> : null}
              </div>
              <button className="finding-card-main" type="button" onClick={() => openFinding(finding)}>
                <strong>{finding.title}</strong>
                <small>{finding.tool_id} · {finding.type}</small>
                <small>{finding.url || "No URL"}</small>
                <code>{evidencePreview(finding)}</code>
              </button>
            </article>
          ))}
        </div>
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
                <tr key={finding.id} className={`finding-row ${finding.severity} ${selectedFinding?.id === finding.id ? "selected-row" : ""}`} onClick={() => openFinding(finding)}>
                  <td onClick={(event) => event.stopPropagation()}>
                    <input
                      type="checkbox"
                      aria-label={`Select ${finding.title}`}
                      checked={selectedFindingIDs.has(finding.id)}
                      onChange={() => toggleFindingSelection(finding.id)}
                    />
                  </td>
                  <td><span className={`severity ${finding.severity}`}>{finding.severity}</span></td>
                  <td>
                    <span className={`origin-badge ${findingOrigin(finding)}`}>{originLabel(findingOrigin(finding))}</span>
                    {isHumanAssistFinding(finding) ? <span className="assist-badge">Human Assist</span> : null}
                    {finding.status ? <small>{finding.status}</small> : null}
                  </td>
                  <td>{finding.type}</td>
                  <td>{finding.tool_id}</td>
                  <td>{finding.title}<small>{finding.url}</small></td>
                  <td>{(finding.cve_matches ?? []).map((cve) => cve.cve_id).join(", ") || "-"}</td>
                  <td><code>{evidencePreview(finding)}</code></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
      {selectedFinding ? (
          <>
          <button className="finding-detail-scrim" type="button" aria-label="Close finding details" onClick={closeFindingDetails} />
          <aside className="panel detail-pane finding-detail-panel" aria-label="Finding details">
            <div className="detail-header">
              <div>
                <span className={`severity ${selectedFinding.severity}`}>{selectedFinding.severity}</span>
                {isHumanAssistFinding(selectedFinding) ? <span className="assist-badge">Human Assist</span> : null}
                <h2>{selectedFinding.title}</h2>
                <p>{selectedFinding.tool_id} · {selectedFinding.type} · {originLabel(findingOrigin(selectedFinding))} · {selectedFinding.url || "no URL"}</p>
              </div>
              <button className="icon-button detail-close-button" type="button" onClick={closeFindingDetails} aria-label="Close finding details">
                <X size={16} />
              </button>
            </div>
            <section className="finding-decision-summary" aria-label="Finding decision summary">
              <article>
                <span>Why it matters</span>
                <strong>{findingImpact(selectedFinding)}</strong>
              </article>
              <article>
                <span>Evidence strength</span>
                <strong>{evidenceStrength(selectedFinding)}</strong>
              </article>
              <article>
                <span>Next action</span>
                <strong>{primaryFindingAction(selectedFinding)}</strong>
              </article>
            </section>
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
              <label className="compact-control">
                Status
                <select value={editStatus} onChange={(event) => setEditStatus(event.target.value as FindingStatus)}>
                  <option value="open">Open</option>
                  <option value="confirmed">Confirmed</option>
                  <option value="false-positive">False Positive</option>
                  <option value="suppressed">Suppressed</option>
                  <option value="wont-fix">Won't Fix</option>
                </select>
              </label>
              <label>
                Remediation
                <textarea value={editRemediation} onChange={(event) => setEditRemediation(event.target.value)} rows={4} />
              </label>
              <button className="primary finding-save-button" onClick={() => updateMutation.mutate()} disabled={updateMutation.isPending}>
                {updateMutation.isPending ? "Saving" : "Save Changes"}
              </button>
            </div>
            {updateMutation.error ? <p className="error-text">{updateMutation.error.message}</p> : null}
            <div className="tab-row" role="tablist" aria-label="Evidence views">
              {[
                ["normalized", "Normalized"],
                ["raw", "Raw"],
                ["http", "HTTP"],
                ["cves", "CVSS/CVEs"],
                ["code", "Code"],
              ].map(([id, label]) => <button key={id} className={evidenceTab === id ? "active" : ""} type="button" onClick={() => setEvidenceTab(id as typeof evidenceTab)}>{label}</button>)}
            </div>
            <EvidenceTab finding={selectedFinding} tab={evidenceTab} />
          </aside>
          </>
      ) : null}
      </div>
      ) : null}
    </section>
  );
}

function EvidenceTab({ finding, tab }: { finding: Finding; tab: "normalized" | "raw" | "http" | "cves" | "code" }) {
  if (tab === "raw") return <pre>{finding.evidence_raw || "-"}</pre>;
  if (tab === "http") return <div className="evidence-grid"><article><h3>Request</h3><pre>{finding.http_evidence?.request_raw || "-"}</pre></article><article><h3>Response</h3><pre>{finding.http_evidence?.response_raw || "-"}</pre></article></div>;
  if (tab === "cves") return <pre>{`CVSS: ${finding.cvss_score || "-"}\n${(finding.cve_matches ?? []).map((cve) => `${cve.cve_id} ${cve.cvss_v3_score}`).join("\n") || "-"}`}</pre>;
  if (tab === "code") return <pre>{finding.code_context || finding.flow_summary || finding.notes || "-"}</pre>;
  return <StructuredEvidence finding={finding} />;
}

function StructuredEvidence({ finding }: { finding: Finding }) {
  const evidence = findingEvidenceObject(finding);
  if (!evidence) return <pre>{finding.evidence_normalized || "-"}</pre>;
  const entries = Object.entries(evidence);
  return (
    <div className="structured-evidence">
      <dl>
        {entries.map(([key, value]) => (
          <div key={key}>
            <dt>{humanizeEvidenceKey(key)}</dt>
            <dd>{formatEvidenceValue(value)}</dd>
          </div>
        ))}
      </dl>
      <pre>{JSON.stringify(evidence, null, 2)}</pre>
    </div>
  );
}

function SortableHeader({ label, active, direction, onClick }: { label: string; active: boolean; direction: "asc" | "desc"; onClick: () => void }) {
  return <th><button className="table-sort" type="button" onClick={onClick}>{label}{sortLabel(active, direction)}</button></th>;
}

function severityRank(severity: string) {
  return { info: 1, low: 2, medium: 3, high: 4, critical: 5 }[severity] ?? 0;
}

export function findingOrigin(finding: Finding) {
  const isStatic = finding.tool_id.startsWith("audit/") || !finding.target_id;
  const hasDynamic = Boolean(finding.target_id);
  if (isStatic && hasDynamic) return "both";
  return isStatic ? "static" : "dynamic";
}

function originLabel(origin: string) {
  if (origin === "both") return "Static + Dynamic";
  return origin === "static" ? "Static" : "Dynamic";
}

type EvidenceObject = Record<string, unknown>;

export function findingEvidenceObject(finding: Pick<Finding, "evidence_normalized">): EvidenceObject | null {
  if (!finding.evidence_normalized?.trim()) return null;
  try {
    const parsed = JSON.parse(finding.evidence_normalized) as unknown;
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return parsed as EvidenceObject;
    }
  } catch {
    return null;
  }
  return null;
}

export function defaultSelectedFinding(currentID: string | undefined, visibleFindings: Finding[]) {
  if (visibleFindings.length === 0) {
    return null;
  }
  return visibleFindings.find((finding) => finding.id === currentID) ?? visibleFindings[0];
}

export function filterFindingsByID(findings: Finding[], findingID: string) {
  if (!findingID) return findings;
  return findings.filter((finding) => finding.id === findingID);
}

export function isHumanAssistFinding(finding: Pick<Finding, "evidence_normalized" | "tags" | "tool_id"> & { tags?: string[] }) {
  const evidence = findingEvidenceObject(finding);
  if (evidence?.human_assist === true) return true;
  if (finding.tags?.includes("human-assist")) return true;
  return finding.tool_id.endsWith("-assist");
}

function evidencePreview(finding: Finding) {
  const evidence = findingEvidenceObject(finding);
  if (!evidence) return finding.evidence_normalized || finding.evidence_raw || "-";
  const indicators = Array.isArray(evidence.indicators) ? evidence.indicators.join(", ") : "";
  const source = typeof evidence.source === "string" ? evidence.source : "";
  const url = typeof evidence.url === "string" ? evidence.url : finding.url;
  return [source, indicators, url].filter(Boolean).join(" · ") || JSON.stringify(evidence);
}

function findingImpact(finding: Finding) {
  if (finding.severity === "critical" || finding.severity === "high") {
    return "Prioritize owner review and remediation before broader tuning.";
  }
  if (isHumanAssistFinding(finding)) {
    return "Needs human confirmation before it should drive active validation.";
  }
  if (finding.type === "misconfiguration") {
    return "Configuration drift or missing control may increase attack surface.";
  }
  return "Review evidence, confirm ownership, and decide whether to track.";
}

function evidenceStrength(finding: Finding) {
  if (finding.http_evidence?.response_raw || finding.evidence_normalized) {
    return "Persisted evidence available";
  }
  if (finding.evidence_raw) {
    return "Raw scanner evidence available";
  }
  return "Evidence is limited";
}

function primaryFindingAction(finding: Finding) {
  if (finding.status === "confirmed") {
    return "Track remediation and keep evidence attached.";
  }
  if (finding.severity === "critical" || finding.severity === "high") {
    return "Confirm scope, assign owner, and remediate.";
  }
  if (isHumanAssistFinding(finding)) {
    return "Manually review before any active follow-up.";
  }
  return "Triage status and capture remediation notes.";
}

function humanizeEvidenceKey(key: string) {
  return key.replace(/_/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function formatEvidenceValue(value: unknown) {
  if (Array.isArray(value)) return value.join(", ") || "-";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (value === null || value === undefined || value === "") return "-";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function cleanFilters(filters: Record<string, string>) {
  return Object.fromEntries(Object.entries(filters).filter(([, value]) => value));
}
