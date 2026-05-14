import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useParams } from "react-router-dom";
import { Download, RefreshCw } from "lucide-react";
import { getReport, listSessions } from "../api/client";

export function Reports() {
  const params = useParams();
  const sessionsQuery = useQuery({ queryKey: ["sessions"], queryFn: listSessions });
  const selected = params.sessionID ?? sessionsQuery.data?.[0]?.session.id ?? "";
  const [format, setFormat] = useState("html");
  const [mode, setMode] = useState("technical");
  const reportQuery = useQuery({
    queryKey: ["report", selected, format, mode],
    queryFn: () => getReport(selected, format, mode),
    enabled: selected !== "",
  });
  const downloadURL = selected ? `/api/sessions/${selected}/report?format=${format}&mode=${mode}` : "#";

  return (
    <section className="page">
      <header className="page-header">
        <div>
          <h1>Reports</h1>
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
            </select>
          </label>
          <button className="primary" onClick={() => reportQuery.refetch()}><RefreshCw size={16} />Preview</button>
          <a className="primary link-button" href={downloadURL}><Download size={16} />Download</a>
        </div>
      </header>
      <div className="report-preview">
        {format === "html" ? <iframe title="Report preview" srcDoc={reportQuery.data ?? ""} /> : <pre>{reportQuery.data}</pre>}
      </div>
    </section>
  );
}
