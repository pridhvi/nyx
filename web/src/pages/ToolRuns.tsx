import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { getToolRunLog, listToolRuns, type ToolRun } from "../api/client";
import { useSessionContext } from "../session";

export function ToolRuns() {
  const { selectedSessionID } = useSessionContext();
  const [selectedRun, setSelectedRun] = useState<ToolRun | null>(null);
  const [logTab, setLogTab] = useState<"stdout" | "stderr">("stdout");
  const runsQuery = useQuery({ queryKey: ["tool-runs", selectedSessionID], queryFn: () => listToolRuns(selectedSessionID), enabled: selectedSessionID !== "" });
  const stdoutQuery = useQuery({
    queryKey: ["tool-run-log", selectedSessionID, selectedRun?.id, "stdout"],
    queryFn: () => getToolRunLog(selectedSessionID, selectedRun!.id, "stdout"),
    enabled: selectedSessionID !== "" && selectedRun != null,
  });
  const stderrQuery = useQuery({
    queryKey: ["tool-run-log", selectedSessionID, selectedRun?.id, "stderr"],
    queryFn: () => getToolRunLog(selectedSessionID, selectedRun!.id, "stderr"),
    enabled: selectedSessionID !== "" && selectedRun != null,
  });
  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") {
        setSelectedRun(null);
      }
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);
  const runs = runsQuery.data ?? [];
  return (
    <section className="page wide-page">
      <header className="page-header"><div><h1>Evidence Runs</h1><p>Arguments, status, stdout, stderr, duration, and finding counts.</p></div></header>
      <section className="panel">
        <div className="table-wrap">
          <table>
            <thead><tr><th>Tool</th><th>Status</th><th>Findings</th><th>Duration</th><th>Args</th><th>Started</th></tr></thead>
            <tbody>
              {runs.map((run) => (
                <tr key={run.id} onClick={() => { setSelectedRun(run); setLogTab("stdout"); }} className={selectedRun?.id === run.id ? "selected-row" : ""}>
                  <td>{run.tool_id}</td><td><span className={`status ${run.exit_code === 0 ? "completed" : "failed"}`}>{run.exit_code === 0 ? "ok" : `exit ${run.exit_code}`}</span></td><td>{run.finding_count}</td><td>{run.duration_ms}ms</td><td><code>{run.args.join(" ")}</code></td><td>{new Date(run.started_at).toLocaleString()}</td>
                </tr>
              ))}
              {runs.length === 0 ? <tr><td colSpan={6}>No tool runs for the selected session.</td></tr> : null}
            </tbody>
          </table>
        </div>
      </section>
      {selectedRun ? (
        <div className="drawer-backdrop" onMouseDown={() => setSelectedRun(null)}>
          <aside className="drawer finding-detail-panel" onMouseDown={(event) => event.stopPropagation()} aria-label="Tool run logs">
            <div className="detail-header">
              <div>
                <h2>{selectedRun.tool_id}</h2>
                <p>exit {selectedRun.exit_code} · {selectedRun.finding_count} findings · {selectedRun.duration_ms}ms</p>
              </div>
              <button className="secondary" onClick={() => setSelectedRun(null)}>Close</button>
            </div>
            <div className="tab-row">
              <button className={logTab === "stdout" ? "active" : ""} type="button" onClick={() => setLogTab("stdout")}>stdout</button>
              <button className={logTab === "stderr" ? "active" : ""} type="button" onClick={() => setLogTab("stderr")}>stderr</button>
            </div>
            {logTab === "stdout"
              ? <LogPanel title="stdout" value={stdoutQuery.data} loading={stdoutQuery.isLoading} />
              : <LogPanel title="stderr" value={stderrQuery.data} loading={stderrQuery.isLoading} />}
          </aside>
        </div>
      ) : null}
    </section>
  );
}

function LogPanel({ title, value, loading }: { title: string; value?: string | null; loading: boolean }) {
  return (
    <article>
      <h3>{title}</h3>
      {loading ? <pre>Loading...</pre> : null}
      {!loading && value != null ? <pre>{value || "-"}</pre> : null}
      {!loading && value == null ? (
        <div className="empty-state">
          <strong>Raw output not available</strong>
          <p>The log file for this tool run has been deleted or moved. Findings and evidence are still intact.</p>
        </div>
      ) : null}
    </article>
  );
}
