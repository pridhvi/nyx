import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Download, RefreshCw } from "lucide-react";
import { getReport } from "../api/client";
import { useSessionContext } from "../session";

export function Reports() {
  const { selectedSessionID: selected } = useSessionContext();
  const [format, setFormat] = useState("html");
  const [mode, setMode] = useState("technical");
  const reportQuery = useQuery({
    queryKey: ["report", selected, format, mode],
    queryFn: () => getReport(selected, format, mode),
    enabled: selected !== "" && format !== "pdf",
  });
  const downloadURL = selected ? `/api/sessions/${selected}/report?format=${format}&mode=${mode}` : "#";
  const reportContent = reportQuery.data ?? "";

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
      <section className="report-toolbar panel">
        <div>
          <span className="badge">{mode}</span>
          <span className="badge">{format.toUpperCase()}</span>
          <strong>{selected ? "Preview is rendered from stored session evidence" : "Select a session to render a preview"}</strong>
        </div>
        <p>HTML previews are sandboxed. PDF is generated as a download-only artifact.</p>
      </section>
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
