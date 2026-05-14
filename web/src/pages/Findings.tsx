import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useParams } from "react-router-dom";
import { listFindings, listSessions } from "../api/client";

export function Findings() {
  const params = useParams();
  const sessionsQuery = useQuery({ queryKey: ["sessions"], queryFn: listSessions });
  const selected = params.sessionID ?? sessionsQuery.data?.[0]?.session.id ?? "";
  const [severity, setSeverity] = useState("");
  const findingsQuery = useQuery({
    queryKey: ["findings-page", selected, severity],
    queryFn: () => listFindings(selected, severity ? { severity } : {}),
    enabled: selected !== "",
  });
  const findings = findingsQuery.data ?? [];

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
      <section className="panel">
        <div className="table-wrap">
          <table>
            <thead>
              <tr><th>Severity</th><th>Type</th><th>Tool</th><th>Title</th><th>CVEs</th><th>Evidence</th></tr>
            </thead>
            <tbody>
              {findings.map((finding) => (
                <tr key={finding.id}>
                  <td><span className={`severity ${finding.severity}`}>{finding.severity}</span></td>
                  <td>{finding.type}</td>
                  <td>{finding.tool_id}</td>
                  <td>{finding.title}<small>{finding.url}</small></td>
                  <td>{(finding.cve_matches ?? []).map((cve) => cve.cve_id).join(", ") || "-"}</td>
                  <td><code>{finding.evidence_normalized || finding.evidence_raw || "-"}</code></td>
                </tr>
              ))}
              {findings.length === 0 ? <tr><td colSpan={6}>No findings for the selected filters.</td></tr> : null}
            </tbody>
          </table>
        </div>
      </section>
    </section>
  );
}
