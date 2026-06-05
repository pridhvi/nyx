import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Check, Clipboard, Download, RefreshCw, X } from "lucide-react";
import { getReport, listFindings, reportURL, type Finding } from "../api/client";
import { loadReportPins, removeReportPin, saveReportPins, type PinnedAnalystNote } from "../reportPins";
import { useSessionContext } from "../session";

export function Reports() {
  const { selectedSessionID: selected } = useSessionContext();
  const [format, setFormat] = useState("html");
  const [mode, setMode] = useState("technical");
  const [includeSuppressed, setIncludeSuppressed] = useState(false);
  const [executiveSummary, setExecutiveSummary] = useState("");
  const [pinnedNotes, setPinnedNotes] = useState<PinnedAnalystNote[]>([]);
  const [copiedPin, setCopiedPin] = useState("");
  const reportOptions = useMemo(() => ({
    include_suppressed: includeSuppressed,
    executive_summary: executiveSummary,
  }), [executiveSummary, includeSuppressed]);
  const reportQuery = useQuery({
    queryKey: ["report", selected, format, mode, includeSuppressed, executiveSummary],
    queryFn: () => getReport(selected, format, mode, reportOptions),
    enabled: selected !== "" && format !== "pdf",
  });
  const findingsQuery = useQuery({ queryKey: ["report-findings", selected], queryFn: () => listFindings(selected), enabled: selected !== "" });
  const downloadURL = selected ? reportURL(selected, format, mode, reportOptions) : "#";
  const reportContent = reportQuery.data ?? "";
  const findingPreview = useMemo(() => reportFindingPreview(findingsQuery.data ?? [], includeSuppressed), [findingsQuery.data, includeSuppressed]);
  const formatNote = reportFormatNote(format);

  useEffect(() => {
    setPinnedNotes(loadReportPins(selected));
  }, [selected]);

  async function copyPinnedNote(note: PinnedAnalystNote) {
    if (!navigator.clipboard) return;
    await navigator.clipboard.writeText(note.content);
    setCopiedPin(note.id);
    window.setTimeout(() => setCopiedPin((current) => current === note.id ? "" : current), 1400);
  }

  function unpin(noteID: string) {
    const next = removeReportPin(pinnedNotes, noteID);
    setPinnedNotes(next);
    saveReportPins(selected, next);
  }

  return (
    <section className="page">
      <header className="page-header">
        <div>
          <h1>Report Composer</h1>
          <p>Generate executive or technical reports from stored evidence.</p>
        </div>
        <div className="action-row">
          <label className="compact-control">Mode
            <select value={mode} onChange={(event) => setMode(event.target.value)}>
              <option value="technical">Technical</option>
              <option value="executive">Executive</option>
            </select>
          </label>
          <label className="compact-control">Format
            <select value={format} onChange={(event) => setFormat(event.target.value)}>
              <option value="html">HTML</option>
              <option value="md">Markdown</option>
              <option value="pdf">PDF</option>
              <option value="sarif">SARIF</option>
            </select>
          </label>
          <button className="primary" disabled={!selected || format === "pdf"} onClick={() => reportQuery.refetch()}><RefreshCw size={16} />Preview</button>
          <a className={`primary link-button ${selected ? "" : "disabled"}`} href={downloadURL} aria-disabled={!selected}><Download size={16} />Download</a>
        </div>
      </header>
      <section className="panel report-config-panel">
        <div className="report-config-grid">
          <label className="toggle-row">
            <input type="checkbox" checked={includeSuppressed} onChange={(event) => setIncludeSuppressed(event.target.checked)} />
            Include suppressed/dismissed appendix
          </label>
          <div className="format-guidance">
            <strong>{format.toUpperCase()}</strong>
            <span>{formatNote}</span>
          </div>
        </div>
        <label className="report-summary-field">
          Custom Executive Summary Intro
          <textarea value={executiveSummary} onChange={(event) => setExecutiveSummary(event.target.value.slice(0, 4000))} placeholder="Optional client-facing narrative to prepend to the generated executive summary." />
          <span>{executiveSummary.length}/4000 characters</span>
        </label>
      </section>
      <section className="panel findings-preview-panel">
        <div className="panel-heading-row">
          <div>
            <h2>Findings Section Preview</h2>
            <p>{findingPreview.length} findings included in report order</p>
          </div>
        </div>
        {findingPreview.length > 0 ? (
          <ol className="report-finding-preview-list">
            {findingPreview.map((finding, index) => (
              <li key={finding.id}>
                <span className="report-finding-order">{index + 1}</span>
                <span className={`severity ${String(finding.severity).toLowerCase()}`}>{finding.severity}</span>
                <strong>{finding.title}</strong>
                <small>{finding.tool_id}{finding.status ? ` · ${finding.status}` : ""}</small>
              </li>
            ))}
          </ol>
        ) : <p className="compact-empty">No findings match the current report inclusion settings.</p>}
      </section>
      <section className="report-toolbar panel">
        <div>
          <span className="badge">{mode}</span>
          <span className="badge">{format.toUpperCase()}</span>
          <strong>{selected ? "Preview is rendered from stored session evidence" : "Select a session to render a preview"}</strong>
        </div>
        <p>{formatNote}</p>
      </section>
      {pinnedNotes.length > 0 ? (
        <section className="panel pinned-report-panel">
          <div className="panel-heading-row">
            <div>
              <h2>Pinned Analyst Notes</h2>
              <p>{pinnedNotes.length} candidate {pinnedNotes.length === 1 ? "section" : "sections"} from LLM Analyst</p>
            </div>
          </div>
          <div className="pinned-report-list">
            {pinnedNotes.map((note) => (
              <article className="pinned-report-note" key={note.id}>
                <header>
                  <strong>{note.title}</strong>
                  <div className="action-row">
                    <button className="icon-button" type="button" onClick={() => void copyPinnedNote(note)} aria-label={`Copy pinned note ${note.title}`}>
                      {copiedPin === note.id ? <Check size={15} /> : <Clipboard size={15} />}
                    </button>
                    <button className="icon-button" type="button" onClick={() => unpin(note.id)} aria-label={`Unpin ${note.title}`}><X size={15} /></button>
                  </div>
                </header>
                <p>{note.content}</p>
              </article>
            ))}
          </div>
        </section>
      ) : null}
      <div className="report-preview">
        {!selected ? <ReportState title="No Session Selected" message="Choose or create a session before generating a report." /> : null}
        {selected && format === "pdf" ? <ReportState title="PDF Preview Is Download-Only" message="PDF output is generated as a binary file. Use Download to save the report." /> : null}
        {selected && format !== "pdf" && reportQuery.isLoading ? <ReportState title="Generating Preview" message="Nyx is rendering the selected report from stored evidence." /> : null}
        {selected && format !== "pdf" && reportQuery.error ? <ReportState title="Report Error" message={reportQuery.error.message} /> : null}
        {selected && format !== "pdf" && !reportQuery.isLoading && !reportQuery.error && !reportContent.trim() ? <ReportState title="Empty Report" message="The report renderer returned no preview content for this session and format." /> : null}
        {selected && format === "html" && reportContent.trim() ? <iframe title="Report preview" sandbox="" referrerPolicy="no-referrer" srcDoc={reportContent} /> : null}
        {selected && format !== "html" && format !== "pdf" && reportContent.trim() ? <pre>{reportContent}</pre> : null}
      </div>
    </section>
  );
}

function ReportState({ title, message }: { title: string; message: string }) {
  return <div className="report-state"><h2>{title}</h2><p>{message}</p></div>;
}

export function reportFindingPreview(findings: Finding[], includeSuppressed: boolean) {
  const included = includeSuppressed ? findings : findings.filter((finding) => !suppressedStatus(finding.status));
  return [...included].sort((left, right) => {
    const leftSuppressed = suppressedStatus(left.status);
    const rightSuppressed = suppressedStatus(right.status);
    if (leftSuppressed !== rightSuppressed) return leftSuppressed ? 1 : -1;
    const severityDelta = severityRank(right.severity) - severityRank(left.severity);
    if (severityDelta !== 0) return severityDelta;
    return left.title.localeCompare(right.title);
  });
}

export function reportFormatNote(format: string) {
  switch (format) {
    case "sarif":
      return "SARIF is designed for CI/CD and code-scanning import, not human reading.";
    case "pdf":
      return "PDF is download-only; review HTML or Markdown first for faster layout feedback.";
    case "md":
      return "Markdown previews in browser and is easiest to edit after download.";
    default:
      return "HTML previews in browser with the same report options used for download.";
  }
}

function suppressedStatus(status?: string) {
  return status === "suppressed" || status === "false-positive";
}

function severityRank(severity: string) {
  return { critical: 5, high: 4, medium: 3, low: 2, info: 1 }[severity.toLowerCase()] ?? 0;
}
