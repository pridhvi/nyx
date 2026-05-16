import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { listSourceFindings } from "../api/client";
import { useSessionContext } from "../session";

const riskyKinds = new Set(["sql_sink", "ssrf_sink", "deserialization_sink", "secret", "unprotected_route", "file_upload"]);

export function Source() {
  const { selectedSessionID: selected } = useSessionContext();
  const [kind, setKind] = useState("");
  const [state, setState] = useState("");
  const sourceQuery = useQuery({
    queryKey: ["source-findings", selected, kind],
    queryFn: () => listSourceFindings(selected, kind ? { kind } : {}),
    enabled: selected !== "",
  });
  const allFindings = sourceQuery.data ?? [];
  const findings = allFindings.filter((finding) => state === "" || (state === "confirmed" ? finding.confirmed_dynamic : !finding.confirmed_dynamic));
  const kinds = [...new Set(allFindings.map((finding) => finding.kind))].sort();

  return (
    <section className="page wide-page">
      <header className="page-header">
        <div>
          <h1>Source Evidence</h1>
          <p>Static source discoveries used by audit tools and source-aware dynamic adapters.</p>
        </div>
      </header>
      <section className="filter-bar">
        <label className="compact-control">
          Kind
          <select value={kind} onChange={(event) => setKind(event.target.value)}>
            <option value="">All</option>
            {kinds.map((item) => <option key={item} value={item}>{item}</option>)}
          </select>
        </label>
        <label className="compact-control">
          State
          <select value={state} onChange={(event) => setState(event.target.value)}>
            <option value="">All</option>
            <option value="confirmed">Static + Dynamic</option>
            <option value="static">Static Only</option>
          </select>
        </label>
        <span className="badge">{findings.length} visible</span>
        <span className="badge">{allFindings.filter((finding) => finding.confirmed_dynamic).length} confirmed</span>
      </section>
      <section className="panel">
        <div className="table-wrap">
          <table>
            <thead>
              <tr><th>Kind</th><th>Location</th><th>Value</th><th>Method</th><th>State</th></tr>
            </thead>
            <tbody>
              {findings.map((finding) => (
                <tr key={finding.id}>
                  <td><span className={`source-kind ${riskyKinds.has(finding.kind) ? "risky" : ""}`}>{finding.kind}</span></td>
                  <td>{finding.file_path}<small>{finding.language} · line {finding.line_number}</small></td>
                  <td><code>{finding.value || "-"}</code>{finding.context ? <details><summary>Context</summary><pre>{finding.context}</pre></details> : null}</td>
                  <td>{finding.method || "-"}</td>
                  <td>{finding.confirmed_dynamic ? <span className="origin-badge both">Static + Dynamic</span> : <span className="origin-badge static">Static</span>}</td>
                </tr>
              ))}
              {findings.length === 0 ? <tr><td colSpan={5}>No source findings for this session.</td></tr> : null}
            </tbody>
          </table>
        </div>
      </section>
    </section>
  );
}
