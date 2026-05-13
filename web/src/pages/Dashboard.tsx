import { type FormEvent, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Activity, AlertTriangle, Play, RefreshCw } from "lucide-react";
import { getSessionStats, listFindings, listSessions, startScan } from "../api/client";

export function Dashboard() {
  const queryClient = useQueryClient();
  const [target, setTarget] = useState("");
  const [mode, setMode] = useState("active");
  const [selectedSessionID, setSelectedSessionID] = useState<string | null>(null);

  const sessionsQuery = useQuery({
    queryKey: ["sessions"],
    queryFn: listSessions,
    refetchInterval: 2500,
  });
  const sessions = sessionsQuery.data ?? [];
  const selected = selectedSessionID ?? sessions[0]?.session.id ?? "";
  const statsQuery = useQuery({
    queryKey: ["session-stats", selected],
    queryFn: () => getSessionStats(selected),
    enabled: selected !== "",
    refetchInterval: 2500,
  });
  const findingsQuery = useQuery({
    queryKey: ["findings", selected],
    queryFn: () => listFindings(selected),
    enabled: selected !== "",
    refetchInterval: 2500,
  });
  const scanMutation = useMutation({
    mutationFn: startScan,
    onSuccess: (record) => {
      setSelectedSessionID(record.session.id);
      queryClient.invalidateQueries({ queryKey: ["sessions"] });
    },
  });
  const totals = useMemo(() => {
    return sessions.reduce(
      (acc, record) => {
        if (record.session.status === "running" || record.session.status === "pending") {
          acc.active += 1;
        }
        acc.findings += record.session.finding_count;
        return acc;
      },
      { active: 0, findings: 0 },
    );
  }, [sessions]);

  function submitScan(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!target.trim()) {
      return;
    }
    scanMutation.mutate({ target: target.trim(), mode });
  }

  return (
    <section className="page">
      <header className="page-header">
        <div>
          <h1>Engagement Dashboard</h1>
          <p>Start scoped scans, monitor findings, and review attack paths.</p>
        </div>
        <button className="primary" onClick={() => sessionsQuery.refetch()}><RefreshCw size={16} />Refresh</button>
      </header>
      <div className="metric-grid">
        <article><Activity /><span>Active Sessions</span><strong>{totals.active}</strong></article>
        <article><AlertTriangle /><span>Total Findings</span><strong>{totals.findings}</strong></article>
        <article><Activity /><span>Tool Runs</span><strong>{statsQuery.data?.tool_run_count ?? 0}</strong></article>
      </div>
      <form className="scan-form" onSubmit={submitScan}>
        <label>
          Target
          <input value={target} onChange={(event) => setTarget(event.target.value)} placeholder="https://example.com" />
        </label>
        <label>
          Mode
          <select value={mode} onChange={(event) => setMode(event.target.value)}>
            <option value="passive">Passive</option>
            <option value="active">Active</option>
            <option value="stealth">Stealth</option>
          </select>
        </label>
        <button type="submit" className="primary" disabled={scanMutation.isPending}>
          <Play size={16} />{scanMutation.isPending ? "Starting" : "Start Scan"}
        </button>
      </form>
      {scanMutation.error ? <p className="error-text">{scanMutation.error.message}</p> : null}
      <div className="data-grid">
        <section className="panel">
          <h2>Sessions</h2>
          <div className="table-wrap">
            <table>
              <thead>
                <tr><th>Target</th><th>Status</th><th>Findings</th><th>Created</th></tr>
              </thead>
              <tbody>
                {sessions.map((record) => (
                  <tr
                    key={record.session.id}
                    className={record.session.id === selected ? "selected-row" : ""}
                    onClick={() => setSelectedSessionID(record.session.id)}
                  >
                    <td>{record.session.target_input}</td>
                    <td><span className={`status ${record.session.status}`}>{record.session.status}</span></td>
                    <td>{record.session.finding_count}</td>
                    <td>{new Date(record.session.created_at).toLocaleString()}</td>
                  </tr>
                ))}
                {sessions.length === 0 ? <tr><td colSpan={4}>No sessions yet.</td></tr> : null}
              </tbody>
            </table>
          </div>
        </section>
        <section className="panel">
          <h2>Findings</h2>
          <div className="severity-strip">
            {["critical", "high", "medium", "low", "info"].map((severity) => (
              <span key={severity}>{severity}: {statsQuery.data?.severity_counts?.[severity] ?? 0}</span>
            ))}
          </div>
          <div className="finding-list">
            {(findingsQuery.data ?? []).slice(0, 8).map((finding) => (
              <article key={finding.id} className="finding-item">
                <span className={`severity ${finding.severity}`}>{finding.severity}</span>
                <strong>{finding.title}</strong>
                <small>{finding.tool_id} · {finding.url}</small>
              </article>
            ))}
            {(findingsQuery.data ?? []).length === 0 ? <div className="empty-line">No findings for the selected session.</div> : null}
          </div>
        </section>
      </div>
    </section>
  );
}
