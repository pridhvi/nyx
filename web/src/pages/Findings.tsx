import { type KeyboardEvent as ReactKeyboardEvent, useEffect, useMemo, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, Clipboard, Download, X } from "lucide-react";
import { Link, useSearchParams } from "react-router-dom";
import { listFindings, listSourceFindings, listVectors, updateFinding, type AttackVector, type Finding, type FindingStatus, type SourceFinding } from "../api/client";
import { useSessionContext } from "../session";
import { sortLabel, useSortableRows } from "../sort";

type EvidenceTabID = "normalized" | "raw" | "http" | "cves" | "code";
type TriageRecordKind = "finding" | "source";
type ConfirmationFilter = "" | "confirmed" | "inferred";
type SuppressionFilter = "" | "unsuppressed" | "suppressed";
type TriageRecord = {
  id: string;
  kind: TriageRecordKind;
  finding?: Finding;
  sourceFinding?: SourceFinding;
  severity: string;
  status: FindingStatus | "source";
  origin: "dynamic" | "static" | "both";
  title: string;
  type: string;
  tool: string;
  category: string;
  location: string;
  evidence: string;
  confirmed: boolean;
  suppressed: boolean;
  createdAt: string;
};
type AttackChainReference = {
  id: string;
  title: string;
  severity: string;
  owasp: string;
  stepLabel: string;
};

const evidenceTabs: Array<{ id: EvidenceTabID; label: string }> = [
  { id: "normalized", label: "Normalized" },
  { id: "raw", label: "Raw" },
  { id: "http", label: "HTTP" },
  { id: "cves", label: "CVSS/CVEs" },
  { id: "code", label: "Code" },
];

export function Findings() {
  const queryClient = useQueryClient();
  const { selectedSessionID: selected } = useSessionContext();
  const [searchParams] = useSearchParams();
  const focusedFindingID = searchParams.get("finding_id")?.trim() ?? "";
  const graphChainID = searchParams.get("graph_chain")?.trim() ?? "";
  const [severity, setSeverity] = useState("");
  const [origin, setOrigin] = useState("");
  const [status, setStatus] = useState("");
  const [evidenceKind, setEvidenceKind] = useState("");
  const [category, setCategory] = useState("");
  const [toolFilter, setToolFilter] = useState("");
  const [confirmation, setConfirmation] = useState<ConfirmationFilter>("");
  const [suppression, setSuppression] = useState<SuppressionFilter>("");
  const [selectedRecord, setSelectedRecord] = useState<TriageRecord | null>(null);
  const [selectedRecordIDs, setSelectedRecordIDs] = useState<Set<string>>(() => new Set());
  const [editSeverity, setEditSeverity] = useState("");
  const [editStatus, setEditStatus] = useState<FindingStatus>("open");
  const [editRemediation, setEditRemediation] = useState("");
  const [bulkSeverity, setBulkSeverity] = useState("");
  const [bulkStatus, setBulkStatus] = useState("");
  const [bulkRemediation, setBulkRemediation] = useState("");
  const [evidenceTab, setEvidenceTab] = useState<EvidenceTabID>("normalized");
  const [dismissedFindingSignature, setDismissedFindingSignature] = useState("");
  const [copiedEvidence, setCopiedEvidence] = useState(false);
  const detailPaneRef = useRef<HTMLElement | null>(null);
  const shouldFocusDetailRef = useRef(false);
  const sessionFindingsQuery = useQuery({
    queryKey: ["findings-page-all", selected],
    queryFn: () => listFindings(selected),
    enabled: selected !== "",
  });
  const sourceFindingsQuery = useQuery({
    queryKey: ["source-findings-triage", selected],
    queryFn: () => listSourceFindings(selected),
    enabled: selected !== "",
  });
  const vectorsQuery = useQuery({
    queryKey: ["findings-attack-vectors", selected],
    queryFn: () => listVectors(selected),
    enabled: selected !== "",
  });
  const baseRecords = useMemo(() => buildTriageRecords(sessionFindingsQuery.data ?? [], sourceFindingsQuery.data ?? []), [sessionFindingsQuery.data, sourceFindingsQuery.data]);
  const categories = useMemo(() => uniqueSorted(baseRecords.map((record) => record.category).filter(Boolean)), [baseRecords]);
  const tools = useMemo(() => uniqueSorted(baseRecords.map((record) => record.tool).filter(Boolean)), [baseRecords]);
  const filteredRecords = useMemo(() => applyTriageFilters(baseRecords, { severity, origin, status, evidenceKind, category, tool: toolFilter, confirmation, suppression }), [baseRecords, category, confirmation, evidenceKind, origin, severity, status, suppression, toolFilter]);
  const findings = filterRecordsByFindingID(filteredRecords, focusedFindingID);
  type FindingSortKey = "severity" | "origin" | "type" | "tool" | "title" | "cves" | "evidence";
  const accessors = useMemo<Record<FindingSortKey, (record: TriageRecord) => string | number>>(() => ({
    severity: (record: TriageRecord) => severityRank(record.severity),
    origin: (record: TriageRecord) => record.origin,
    type: (record: TriageRecord) => record.type,
    tool: (record: TriageRecord) => record.tool,
    title: (record: TriageRecord) => record.title,
    cves: (record: TriageRecord) => (record.finding?.cve_matches ?? []).map((cve) => cve.cve_id).join(", "),
    evidence: (record: TriageRecord) => record.evidence,
  }), []);
  const { sortedRows: sortedFindings, sort, toggleSort } = useSortableRows<TriageRecord, FindingSortKey>(findings, { key: "severity", direction: "desc" }, accessors);
  const visibleFindingSignature = useMemo(() => sortedFindings.map((record) => record.id).join("|"), [sortedFindings]);
  const selectedCount = selectedRecordIDs.size;
  const selectedRecords = useMemo(() => baseRecords.filter((record) => selectedRecordIDs.has(record.id)), [baseRecords, selectedRecordIDs]);
  const selectedEditableRecords = selectedRecords.filter((record) => record.kind === "finding" && record.finding);
  const allVisibleSelected = sortedFindings.length > 0 && sortedFindings.every((record) => selectedRecordIDs.has(record.id));
  const hasStoredFindings = baseRecords.length > 0;
  const hasVisibleFindings = sortedFindings.length > 0;
  const hasFilters = Boolean(severity || origin || status || evidenceKind || category || toolFilter || confirmation || suppression || focusedFindingID);
  const selectedAttackChainRefs = useMemo(() => attackChainsForFinding(vectorsQuery.data ?? [], selectedRecord?.finding?.id ?? ""), [selectedRecord, vectorsQuery.data]);
  const emptyMessage = !selected
    ? "Select a session to review findings."
    : sessionFindingsQuery.isLoading || sourceFindingsQuery.isLoading
      ? "Loading findings."
      : focusedFindingID
        ? `No finding matches ${focusedFindingID}.`
      : hasStoredFindings && hasFilters
        ? "No findings match the current filters."
        : "No findings yet for the selected session.";
  const updateMutation = useMutation({
    mutationFn: () => updateFinding(selected, selectedRecord?.finding?.id ?? "", { severity: editSeverity, status: editStatus, remediation: editRemediation }),
    onSuccess: (finding) => {
      setSelectedRecord(findingToTriageRecord(finding));
      queryClient.invalidateQueries({ queryKey: ["findings-page-all", selected] });
      queryClient.invalidateQueries({ queryKey: ["findings", selected] });
      queryClient.invalidateQueries({ queryKey: ["session-stats", selected] });
    },
  });
  const bulkUpdateMutation = useMutation({
    mutationFn: async (override?: { severity?: string; status?: FindingStatus; remediation?: string }) => {
      const payload = {
        severity: override?.severity ?? (bulkSeverity || undefined),
        status: override?.status ?? ((bulkStatus || undefined) as FindingStatus | undefined),
        remediation: override?.remediation ?? (bulkRemediation || undefined),
      };
      await Promise.all(selectedEditableRecords.map((record) => updateFinding(selected, record.finding?.id ?? "", payload)));
    },
    onSuccess: () => {
      setSelectedRecordIDs(new Set());
      setBulkSeverity("");
      setBulkStatus("");
      setBulkRemediation("");
      queryClient.invalidateQueries({ queryKey: ["findings-page-all", selected] });
      queryClient.invalidateQueries({ queryKey: ["findings", selected] });
      queryClient.invalidateQueries({ queryKey: ["session-stats", selected] });
    },
  });

  function openFinding(record: TriageRecord) {
    setDismissedFindingSignature("");
    shouldFocusDetailRef.current = true;
    setSelectedRecord(record);
    setEditSeverity(record.severity);
    setEditStatus(record.finding?.status ?? "open");
    setEditRemediation(record.finding?.remediation ?? "");
    setEvidenceTab("normalized");
    setCopiedEvidence(false);
  }

  function closeFindingDetails() {
    setDismissedFindingSignature(visibleFindingSignature);
    setSelectedRecord(null);
  }

  function toggleFindingSelection(recordID: string) {
    setSelectedRecordIDs((current) => {
      const next = new Set(current);
      if (next.has(recordID)) {
        next.delete(recordID);
      } else {
        next.add(recordID);
      }
      return next;
    });
  }

  function toggleVisibleSelection() {
    setSelectedRecordIDs((current) => {
      const next = new Set(current);
      if (allVisibleSelected) {
        sortedFindings.forEach((record) => next.delete(record.id));
      } else {
        sortedFindings.forEach((record) => next.add(record.id));
      }
      return next;
    });
  }

  function openFindingWithKeyboard(event: ReactKeyboardEvent, record: TriageRecord) {
    if (event.key !== "Enter" && event.key !== " ") {
      return;
    }
    event.preventDefault();
    openFinding(record);
  }

  function selectEvidenceTab(nextTab: typeof evidenceTab) {
    setEvidenceTab(nextTab);
    setCopiedEvidence(false);
  }

  function moveEvidenceTab(event: ReactKeyboardEvent<HTMLButtonElement>, tabID: typeof evidenceTab) {
    const currentIndex = evidenceTabs.findIndex((tabItem) => tabItem.id === tabID);
    const lastIndex = evidenceTabs.length - 1;
    const nextIndex = event.key === "ArrowRight"
      ? currentIndex === lastIndex ? 0 : currentIndex + 1
      : event.key === "ArrowLeft"
        ? currentIndex === 0 ? lastIndex : currentIndex - 1
        : -1;
    if (nextIndex < 0) {
      return;
    }
    event.preventDefault();
    selectEvidenceTab(evidenceTabs[nextIndex].id);
    window.requestAnimationFrame(() => {
      document.getElementById(evidenceTabButtonID(evidenceTabs[nextIndex].id))?.focus();
    });
  }

  async function copyVisibleEvidence() {
    if (!selectedRecord?.finding) {
      return;
    }
    const text = detailEvidenceText(selectedRecord.finding, evidenceTab);
    if (navigator.clipboard) {
      try {
        await navigator.clipboard.writeText(text);
      } catch {
        // Clipboard permissions can be unavailable in hardened browser contexts.
      }
    }
    setCopiedEvidence(true);
  }

  function applyBulkStatus(nextStatus: FindingStatus) {
    bulkUpdateMutation.mutate({ status: nextStatus });
  }

  function exportSelectedFindings() {
    const rows = selectedRecords.length > 0 ? selectedRecords : sortedFindings;
    const body = selectedFindingsMarkdown(rows);
    const blob = new Blob([body], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = "nyx-selected-findings.md";
    anchor.click();
    URL.revokeObjectURL(url);
  }

  useEffect(() => {
    const nextRecord = defaultSelectedFinding(selectedRecord?.id, sortedFindings);
    if (!nextRecord) {
      if (selectedRecord) {
        setSelectedRecord(null);
      }
      if (dismissedFindingSignature) {
        setDismissedFindingSignature("");
      }
      return;
    }
    if (!selectedRecord && dismissedFindingSignature === visibleFindingSignature) {
      return;
    }
    if (nextRecord.id !== selectedRecord?.id) {
      setSelectedRecord(nextRecord);
      setEditSeverity(nextRecord.severity);
      setEditStatus(nextRecord.finding?.status ?? "open");
      setEditRemediation(nextRecord.finding?.remediation ?? "");
      setEvidenceTab("normalized");
    }
  }, [dismissedFindingSignature, selectedRecord, selectedRecord?.id, sortedFindings, visibleFindingSignature]);

  useEffect(() => {
    if (!selectedRecord || !shouldFocusDetailRef.current) {
      return;
    }
    shouldFocusDetailRef.current = false;
    detailPaneRef.current?.focus({ preventScroll: true });
  }, [selectedRecord]);

  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") {
        setDismissedFindingSignature(visibleFindingSignature);
        setSelectedRecord(null);
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
            <option value="both">Static + Dynamic</option>
          </select>
        </label>
        <label className="compact-control">
          Category
          <select value={category} onChange={(event) => setCategory(event.target.value)}>
            <option value="">All</option>
            {categories.map((item) => <option key={item} value={item}>{item}</option>)}
          </select>
        </label>
        <label className="compact-control">
          Tool
          <select value={toolFilter} onChange={(event) => setToolFilter(event.target.value)}>
            <option value="">All</option>
            {tools.map((item) => <option key={item} value={item}>{item}</option>)}
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
          Confidence
          <select value={confirmation} onChange={(event) => setConfirmation(event.target.value as ConfirmationFilter)}>
            <option value="">All</option>
            <option value="confirmed">Confirmed</option>
            <option value="inferred">Inferred</option>
          </select>
        </label>
        <label className="compact-control">
          Suppression
          <select value={suppression} onChange={(event) => setSuppression(event.target.value as SuppressionFilter)}>
            <option value="">All</option>
            <option value="unsuppressed">Unsuppressed</option>
            <option value="suppressed">Suppressed</option>
          </select>
        </label>
        <label className="compact-control">
          Evidence
          <select value={evidenceKind} onChange={(event) => setEvidenceKind(event.target.value)}>
            <option value="">All</option>
            <option value="human-assist">Human Assist</option>
            <option value="cross-confirmed">Cross-confirmed</option>
            <option value="http">HTTP Evidence</option>
            <option value="code">Code Evidence</option>
          </select>
        </label>
        {hasFilters ? <button className="secondary compact-button" type="button" onClick={() => {
          setSeverity("");
          setOrigin("");
          setCategory("");
          setToolFilter("");
          setStatus("");
          setConfirmation("");
          setSuppression("");
          setEvidenceKind("");
        }}>Clear Filters</button> : null}
      </section> : null}
      {hasVisibleFindings ? <section className="panel bulk-panel">
        <div>
          <h2>Bulk Workflow</h2>
          <p>{selectedCount} selected item{selectedCount === 1 ? "" : "s"} · {selectedEditableRecords.length} editable finding{selectedEditableRecords.length === 1 ? "" : "s"}</p>
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
          onClick={() => bulkUpdateMutation.mutate(undefined)}
          disabled={selectedEditableRecords.length === 0 || (!bulkSeverity && !bulkStatus && !bulkRemediation) || bulkUpdateMutation.isPending}
        >
          {bulkUpdateMutation.isPending ? "Applying" : "Apply"}
        </button>
        <button className="secondary" type="button" disabled={selectedEditableRecords.length === 0 || bulkUpdateMutation.isPending} onClick={() => applyBulkStatus("suppressed")}>Suppress Selected</button>
        <button className="secondary" type="button" disabled={selectedEditableRecords.length === 0 || bulkUpdateMutation.isPending} onClick={() => applyBulkStatus("confirmed")}>Mark Reviewed</button>
        <button className="secondary" type="button" disabled={selectedCount === 0} onClick={exportSelectedFindings}><Download size={15} />Export Selected</button>
        {selectedCount > 0 ? <button className="secondary" type="button" onClick={() => setSelectedRecordIDs(new Set())}>Clear</button> : null}
        {bulkUpdateMutation.error ? <p className="error-text">{bulkUpdateMutation.error.message}</p> : null}
      </section> : null}
      {!hasVisibleFindings ? <section className="panel empty-state-panel"><h2>{hasStoredFindings && hasFilters ? "No Matching Findings" : "No Findings"}</h2><p>{emptyMessage}</p></section> : null}
      {hasVisibleFindings ? (
      <div className="split-workspace triage-workspace">
      <section className="panel">
        <div className="finding-card-list">
          {sortedFindings.map((record) => (
            <article key={record.id} className={`finding-card ${record.severity} ${record.suppressed ? "suppressed" : ""} ${selectedRecord?.id === record.id ? "selected-row" : ""}`}>
              <div className="finding-card-top">
                <input
                  type="checkbox"
                  aria-label={`Select ${record.title}`}
                  checked={selectedRecordIDs.has(record.id)}
                  onChange={() => toggleFindingSelection(record.id)}
                />
                <span className={`severity ${record.severity}`}>{record.severity}</span>
                <span className={`origin-badge ${record.origin}`}>{originLabel(record.origin)}</span>
                <span className={`origin-badge ${record.kind === "source" ? "static" : "dynamic"}`}>{record.kind === "source" ? "Source" : "Finding"}</span>
                {record.confirmed ? <span className="assist-badge">Confirmed</span> : null}
                {record.status ? <span className={`status ${record.status}`}>{record.status}</span> : null}
              </div>
              <button className="finding-card-main" type="button" onClick={() => openFinding(record)}>
                <strong>{record.title}</strong>
                <small>{record.tool} · {record.type} · {record.category}</small>
                <small>{record.location || "No location"}</small>
                <code>{record.evidence}</code>
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
              {sortedFindings.map((record) => (
                <tr
                  key={record.id}
                  className={`finding-row ${record.severity} ${record.suppressed ? "suppressed" : ""} ${selectedRecord?.id === record.id ? "selected-row" : ""}`}
                  onClick={() => openFinding(record)}
                  onKeyDown={(event) => openFindingWithKeyboard(event, record)}
                  tabIndex={0}
                  role="button"
                  aria-label={`Open finding details for ${record.title}`}
                  aria-selected={selectedRecord?.id === record.id}
                >
                  <td onClick={(event) => event.stopPropagation()}>
                    <input
                      type="checkbox"
                      aria-label={`Select ${record.title}`}
                      checked={selectedRecordIDs.has(record.id)}
                      onChange={() => toggleFindingSelection(record.id)}
                    />
                  </td>
                  <td><span className={`severity ${record.severity}`}>{record.severity}</span></td>
                  <td>
                    <span className={`origin-badge ${record.origin}`}>{originLabel(record.origin)}</span>
                    <span className={`source-kind-badge ${record.kind}`}>{record.kind === "source" ? "Source" : "Finding"}</span>
                    {record.confirmed ? <span className="assist-badge">Confirmed</span> : null}
                    {record.status ? <small>{record.status}</small> : null}
                  </td>
                  <td>{record.type}<small>{record.category}</small></td>
                  <td>{record.tool}</td>
                  <td>{record.title}<small>{record.location}</small></td>
                  <td>{(record.finding?.cve_matches ?? []).map((cve) => cve.cve_id).join(", ") || "-"}</td>
                  <td><code>{record.evidence}</code></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
      {selectedRecord ? (
          <>
          <button className="finding-detail-scrim" type="button" aria-label="Close finding details" onClick={closeFindingDetails} />
          <aside ref={detailPaneRef} className="panel detail-pane finding-detail-panel" aria-label="Finding details" tabIndex={-1}>
            <div className="detail-header">
              <div>
                <span className={`severity ${selectedRecord.severity}`}>{selectedRecord.severity}</span>
                <span className={`source-kind-badge ${selectedRecord.kind}`}>{selectedRecord.kind === "source" ? "Source" : "Finding"}</span>
                {selectedRecord.confirmed ? <span className="assist-badge">Confirmed</span> : null}
                <h2>{selectedRecord.title}</h2>
                <p>{selectedRecord.tool} · {selectedRecord.type} · {originLabel(selectedRecord.origin)} · {selectedRecord.location || "no location"}</p>
              </div>
              <button className="icon-button detail-close-button" type="button" onClick={closeFindingDetails} aria-label="Close finding details">
                <X size={16} />
              </button>
            </div>
            <CrossConfirmationSummary record={selectedRecord} />
            <AttackChainReferences sessionID={selected} findingID={selectedRecord.finding?.id ?? ""} refs={selectedAttackChainRefs} graphChainID={graphChainID} />
            <section className="finding-decision-summary" aria-label="Finding decision summary">
              <article>
                <span>Why it matters</span>
                <strong>{findingImpact(selectedRecord)}</strong>
              </article>
              <article>
                <span>Evidence strength</span>
                <strong>{evidenceStrength(selectedRecord)}</strong>
              </article>
              <article>
                <span>Next action</span>
                <strong>{primaryFindingAction(selectedRecord)}</strong>
              </article>
            </section>
            {selectedRecord.finding ? <div className="finding-editor">
              <div className="severity-edit-callout">
                <strong>Operator Triage</strong>
                <span>Severity and status changes are persisted with a field-level audit event.</span>
              </div>
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
            </div> : <section className="finding-editor read-only-source">
              <strong>Source finding</strong>
              <p>Source findings are read-only evidence records. Use the normalized audit finding when you need to change severity or triage status.</p>
            </section>}
            {updateMutation.error ? <p className="error-text">{updateMutation.error.message}</p> : null}
            <TriageAuditTrail finding={selectedRecord.finding} />
            <div className="evidence-toolbar">
              <div className="tab-row" role="tablist" aria-label="Evidence views">
                {evidenceTabs.map(({ id, label }) => (
                  <button
                    key={id}
                    id={evidenceTabButtonID(id)}
                    className={evidenceTab === id ? "active" : ""}
                    type="button"
                    role="tab"
                    aria-selected={evidenceTab === id}
                    aria-controls={evidenceTabPanelID(id)}
                    tabIndex={evidenceTab === id ? 0 : -1}
                    onClick={() => selectEvidenceTab(id)}
                    onKeyDown={(event) => moveEvidenceTab(event, id)}
                  >
                    {label}
                  </button>
                ))}
              </div>
              <button className="secondary evidence-copy-button" type="button" onClick={() => void copyVisibleEvidence()}>
                {copiedEvidence ? <Check size={15} /> : <Clipboard size={15} />}
                {copiedEvidence ? "Copied" : "Copy Evidence"}
              </button>
            </div>
            <section id={evidenceTabPanelID(evidenceTab)} role="tabpanel" aria-labelledby={evidenceTabButtonID(evidenceTab)} tabIndex={0}>
              {selectedRecord.finding ? <EvidenceTab finding={selectedRecord.finding} tab={evidenceTab} /> : <SourceEvidence sourceFinding={selectedRecord.sourceFinding} />}
            </section>
          </aside>
          </>
      ) : null}
      </div>
      ) : null}
    </section>
  );
}

function EvidenceTab({ finding, tab }: { finding: Finding; tab: EvidenceTabID }) {
  if (tab === "raw") return <pre>{finding.evidence_raw || "-"}</pre>;
  if (tab === "http") return <div className="evidence-grid"><article><h3>Request</h3><pre>{finding.http_evidence?.request_raw || "-"}</pre></article><article><h3>Response</h3><pre>{finding.http_evidence?.response_raw || "-"}</pre></article></div>;
  if (tab === "cves") return <pre>{`CVSS: ${finding.cvss_score || "-"}\n${(finding.cve_matches ?? []).map((cve) => `${cve.cve_id} ${cve.cvss_v3_score}`).join("\n") || "-"}`}</pre>;
  if (tab === "code") return <pre>{finding.code_context || finding.flow_summary || finding.notes || "-"}</pre>;
  return <StructuredEvidence finding={finding} />;
}

function CrossConfirmationSummary({ record }: { record: TriageRecord }) {
  const signals = crossConfirmationSignals(record);
  return (
    <section className={`cross-confirmation ${signals.length > 1 || record.confirmed ? "strong" : ""}`} aria-label="Cross confirmation evidence">
      <div>
        <span>Evidence Confidence</span>
        <strong>{signals.length > 1 || record.confirmed ? "Cross-confirmed evidence" : "Single-source evidence"}</strong>
      </div>
      <ul>
        {signals.map((signal) => <li key={signal}>{signal}</li>)}
      </ul>
    </section>
  );
}

function AttackChainReferences({ sessionID, findingID, refs, graphChainID }: { sessionID: string; findingID: string; refs: AttackChainReference[]; graphChainID: string }) {
  if (!findingID) return null;
  return (
    <section className="attack-chain-references" aria-label="Attack chains using this finding">
      <div>
        <span>Attack Path Usage</span>
        <strong>{refs.length ? `${refs.length} chain${refs.length === 1 ? "" : "s"} use this finding` : "No generated chains use this finding yet"}</strong>
      </div>
      {graphChainID ? <Link className="secondary compact-button" to={`/sessions/${sessionID}/graph?chain_id=${encodeURIComponent(graphChainID)}&finding_id=${encodeURIComponent(findingID)}`}>Back to Attack Chain</Link> : null}
      {refs.length > 0 ? (
        <ul>
          {refs.map((ref) => (
            <li key={ref.id}>
              <Link to={`/sessions/${sessionID}/graph?chain_id=${encodeURIComponent(ref.id)}&finding_id=${encodeURIComponent(findingID)}`}>{ref.title}</Link>
              <span>{ref.severity} · {ref.owasp || "Unmapped"} · step {ref.stepLabel}</span>
            </li>
          ))}
        </ul>
      ) : null}
    </section>
  );
}

function TriageAuditTrail({ finding }: { finding?: Finding }) {
  const events = finding?.triage_events ?? [];
  return (
    <section className="triage-audit-trail" aria-label="Triage audit trail">
      <h3>Triage Audit Trail</h3>
      {events.length === 0 ? <p>No operator triage edits have been saved yet.</p> : (
        <ol>
          {events.map((event) => (
            <li key={event.id}>
              <strong>{humanizeEvidenceKey(event.field)}</strong>
              <span>{event.old_value || "-"} → {event.new_value || "-"} · {event.actor} · {formatTimestamp(event.created_at)}</span>
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}

function SourceEvidence({ sourceFinding }: { sourceFinding?: SourceFinding }) {
  if (!sourceFinding) return <pre>-</pre>;
  return (
    <div className="structured-evidence">
      <dl>
        <div><dt>Kind</dt><dd>{sourceFinding.kind}</dd></div>
        <div><dt>Location</dt><dd>{sourceFinding.file_path}:{sourceFinding.line_number || "-"}</dd></div>
        <div><dt>Language</dt><dd>{[sourceFinding.language, sourceFinding.framework].filter(Boolean).join(" / ") || "-"}</dd></div>
        <div><dt>Value</dt><dd>{sourceFinding.value || "-"}</dd></div>
        <div><dt>Dynamic confirmation</dt><dd>{sourceFinding.confirmed_dynamic ? "confirmed by dynamic scan" : "not cross-confirmed yet"}</dd></div>
      </dl>
      <pre>{[sourceFinding.context, sourceFinding.notes].filter(Boolean).join("\n\n") || "-"}</pre>
    </div>
  );
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

function evidenceTabButtonID(tab: EvidenceTabID) {
  return `finding-evidence-tab-${tab}`;
}

function evidenceTabPanelID(tab: EvidenceTabID) {
  return `finding-evidence-panel-${tab}`;
}

function detailEvidenceText(finding: Finding, tab: EvidenceTabID) {
  if (tab === "raw") return finding.evidence_raw || "-";
  if (tab === "http") {
    return [
      "Request:",
      finding.http_evidence?.request_raw || "-",
      "",
      "Response:",
      finding.http_evidence?.response_raw || "-",
    ].join("\n");
  }
  if (tab === "cves") {
    return `CVSS: ${finding.cvss_score || "-"}\n${(finding.cve_matches ?? []).map((cve) => `${cve.cve_id} ${cve.cvss_v3_score}`).join("\n") || "-"}`;
  }
  if (tab === "code") return finding.code_context || finding.flow_summary || finding.notes || "-";
  return finding.evidence_normalized || finding.evidence_raw || "-";
}

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

export function defaultSelectedFinding(currentID: string | undefined, visibleFindings: TriageRecord[]) {
  if (visibleFindings.length === 0) {
    return null;
  }
  return visibleFindings.find((finding) => finding.id === currentID) ?? visibleFindings[0];
}

export function filterFindingsByID(findings: Finding[], findingID: string) {
  if (!findingID) return findings;
  return findings.filter((finding) => finding.id === findingID);
}

export function filterRecordsByFindingID(records: TriageRecord[], findingID: string) {
  if (!findingID) return records;
  return records.filter((record) => record.id === findingID || record.finding?.id === findingID || record.sourceFinding?.id === findingID);
}

export function buildTriageRecords(findings: Finding[], sourceFindings: SourceFinding[]) {
  return [
    ...findings.map(findingToTriageRecord),
    ...sourceFindings.map(sourceFindingToTriageRecord),
  ];
}

function findingToTriageRecord(finding: Finding): TriageRecord {
  const origin = findingOrigin(finding) as TriageRecord["origin"];
  const evidence = findingEvidenceObject(finding);
  return {
    id: finding.id,
    kind: "finding",
    finding,
    severity: finding.severity,
    status: finding.status ?? "open",
    origin,
    title: finding.title,
    type: finding.type,
    tool: finding.tool_id,
    category: findingCategory(finding),
    location: finding.url || finding.code_context?.split("\n")[0] || "",
    evidence: evidencePreview(finding),
    confirmed: isFindingConfirmed(finding),
    suppressed: finding.status === "suppressed",
    createdAt: finding.created_at,
  };
}

function sourceFindingToTriageRecord(sourceFinding: SourceFinding): TriageRecord {
  return {
    id: `source:${sourceFinding.id}`,
    kind: "source",
    sourceFinding,
    severity: sourceFinding.confirmed_dynamic ? "low" : "info",
    status: "source",
    origin: sourceFinding.confirmed_dynamic ? "both" : "static",
    title: sourceFindingTitle(sourceFinding),
    type: sourceFinding.kind,
    tool: "source-audit",
    category: sourceFindingCategory(sourceFinding),
    location: `${sourceFinding.file_path}${sourceFinding.line_number ? `:${sourceFinding.line_number}` : ""}`,
    evidence: sourceFinding.context || sourceFinding.value || sourceFinding.notes || "-",
    confirmed: Boolean(sourceFinding.confirmed_dynamic),
    suppressed: false,
    createdAt: sourceFinding.created_at,
  };
}

type TriageFilterState = {
  severity: string;
  origin: string;
  status: string;
  evidenceKind: string;
  category: string;
  tool: string;
  confirmation: ConfirmationFilter;
  suppression: SuppressionFilter;
};

export function applyTriageFilters(records: TriageRecord[], filters: TriageFilterState) {
  return records.filter((record) => {
    if (filters.severity && record.severity !== filters.severity) return false;
    if (filters.origin && record.origin !== filters.origin) return false;
    if (filters.category && record.category !== filters.category) return false;
    if (filters.tool && record.tool !== filters.tool) return false;
    if (filters.status && record.status !== filters.status) return false;
    if (filters.confirmation === "confirmed" && !record.confirmed) return false;
    if (filters.confirmation === "inferred" && record.confirmed) return false;
    if (filters.suppression === "suppressed" && !record.suppressed) return false;
    if (filters.suppression === "unsuppressed" && record.suppressed) return false;
    if (filters.evidenceKind === "human-assist" && (!record.finding || !isHumanAssistFinding(record.finding))) return false;
    if (filters.evidenceKind === "cross-confirmed" && !record.confirmed) return false;
    if (filters.evidenceKind === "http" && !record.finding?.http_evidence) return false;
    if (filters.evidenceKind === "code" && !record.finding?.code_context && !record.sourceFinding) return false;
    return true;
  });
}

export function attackChainsForFinding(vectors: AttackVector[], findingID: string): AttackChainReference[] {
  if (!findingID) return [];
  return vectors.flatMap((vector) => {
    const step = (vector.steps ?? []).find((item) => item.finding_id === findingID);
    const prereqIndex = (vector.prereq_finding_ids ?? []).findIndex((id) => id === findingID);
    if (!step && prereqIndex < 0) return [];
    return [{
      id: vector.id,
      title: vector.title,
      severity: vector.severity,
      owasp: vector.owasp_category,
      stepLabel: step ? String(step.order || 1) : String(prereqIndex + 1),
    }];
  });
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

function findingImpact(record: TriageRecord) {
  if (record.kind === "source") {
    return record.confirmed ? "Static source evidence is also linked to dynamic behavior." : "Static source evidence should be reviewed before dynamic follow-up.";
  }
  if (record.severity === "critical" || record.severity === "high") {
    return "Prioritize owner review and remediation before broader tuning.";
  }
  if (record.finding && isHumanAssistFinding(record.finding)) {
    return "Needs human confirmation before it should drive active validation.";
  }
  if (record.type === "misconfiguration") {
    return "Configuration drift or missing control may increase attack surface.";
  }
  return "Review evidence, confirm ownership, and decide whether to track.";
}

function evidenceStrength(record: TriageRecord) {
  if (record.confirmed) {
    return "Cross-confirmed evidence is available";
  }
  const finding = record.finding;
  if (finding?.http_evidence?.response_raw || finding?.evidence_normalized) {
    return "Persisted evidence available";
  }
  if (finding?.evidence_raw) {
    return "Raw scanner evidence available";
  }
  if (record.sourceFinding) {
    return "Source code evidence available";
  }
  return "Evidence is limited";
}

function primaryFindingAction(record: TriageRecord) {
  if (record.status === "confirmed") {
    return "Track remediation and keep evidence attached.";
  }
  if (record.suppressed) {
    return "Review suppression rationale before excluding from reports.";
  }
  if (record.severity === "critical" || record.severity === "high") {
    return "Confirm scope, assign owner, and remediate.";
  }
  if (record.finding && isHumanAssistFinding(record.finding)) {
    return "Manually review before any active follow-up.";
  }
  return "Triage status and capture remediation notes.";
}

function findingCategory(finding: Finding) {
  const evidence = findingEvidenceObject(finding);
  const evidenceCategory = stringEvidenceValue(evidence, ["owasp", "owasp_category", "category", "cwe"]);
  if (evidenceCategory) return evidenceCategory;
  const tagCategory = (finding.tags ?? []).find((tag) => /^owasp[:/]/i.test(tag) || /^cwe[:/-]/i.test(tag));
  if (tagCategory) return tagCategory.replace(/^[^:/-]+[:/-]/, "").toUpperCase();
  if (finding.type === "misconfiguration") return "Security Misconfiguration";
  if (finding.type === "exposure") return "Exposure";
  return "Unmapped";
}

function sourceFindingCategory(sourceFinding: SourceFinding) {
  switch (sourceFinding.kind) {
    case "sql_sink":
      return "Injection";
    case "ssrf_sink":
      return "SSRF";
    case "secret":
      return "Secrets";
    case "unprotected_route":
      return "Broken Access Control";
    case "deserialisation_sink":
      return "Insecure Deserialization";
    default:
      return "Source Review";
  }
}

function sourceFindingTitle(sourceFinding: SourceFinding) {
  return `${humanizeEvidenceKey(sourceFinding.kind)} in ${sourceFinding.file_path || "source"}`;
}

function isFindingConfirmed(finding: Finding) {
  if (finding.status === "confirmed") return true;
  if ((finding.tags ?? []).some((tag) => tag === "validated" || tag === "cross-confirmed")) return true;
  const evidence = findingEvidenceObject(finding);
  if (evidence?.validated === true || evidence?.confirmed === true || evidence?.cross_confirmed === true) return true;
  return findingOrigin(finding) === "both";
}

function crossConfirmationSignals(record: TriageRecord) {
  const signals = [`${record.tool} reported ${record.type}`];
  if (record.origin === "both") signals.push("Static and dynamic evidence are linked");
  if (record.confirmed) signals.push("Marked confirmed or validated");
  if (record.finding?.http_evidence) signals.push("HTTP request/response evidence is persisted");
  if (record.finding?.code_context || record.sourceFinding) signals.push("Source context is available");
  if ((record.finding?.cve_matches ?? []).length > 0) signals.push("CVE intelligence is attached");
  return uniqueSorted(signals);
}

function stringEvidenceValue(evidence: EvidenceObject | null, keys: string[]) {
  if (!evidence) return "";
  for (const key of keys) {
    const value = evidence[key];
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  return "";
}

function uniqueSorted(values: string[]) {
  return [...new Set(values)].sort((left, right) => left.localeCompare(right));
}

function selectedFindingsMarkdown(records: TriageRecord[]) {
  const lines = ["# Nyx Selected Findings", ""];
  for (const record of records) {
    lines.push(`## ${record.title}`);
    lines.push("");
    lines.push(`- Severity: ${record.severity}`);
    lines.push(`- Status: ${record.status}`);
    lines.push(`- Origin: ${originLabel(record.origin)}`);
    lines.push(`- Type: ${record.type}`);
    lines.push(`- Tool: ${record.tool}`);
    lines.push(`- Category: ${record.category}`);
    lines.push(`- Location: ${record.location || "-"}`);
    lines.push(`- Evidence: ${record.evidence || "-"}`);
    lines.push("");
  }
  return lines.join("\n");
}

function formatTimestamp(value: string) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
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
