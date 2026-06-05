import { useMemo, useState } from "react";
import { useMutation, useQueries, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { AlertTriangle, Bell, GitCompareArrows, Play, RefreshCw, RotateCcw, Trash2 } from "lucide-react";
import { createMonitorConfig, deleteMonitorConfig, listMonitorConfigs, listMonitorRunChanges, listMonitorRuns, resetMonitorBaseline, runMonitorConfig, updateMonitorConfig, type MonitorConfig, type MonitorRun, type SurfaceChange } from "../api/client";

const scheduleOptions = [
  { label: "Hourly", value: "@hourly" },
  { label: "Daily", value: "@daily" },
  { label: "Weekly", value: "@weekly" },
];

const phaseOptions = [
  { label: "Recon", value: "recon" },
  { label: "Fingerprint", value: "fingerprint" },
  { label: "Enumerate", value: "enumerate" },
  { label: "Vulnerability Scan", value: "vuln_scan" },
];

const alertOptions = [
  { label: "New Finding", value: "new_finding" },
  { label: "Severity Change", value: "finding_severity_changed" },
  { label: "New Host", value: "new_host" },
  { label: "Removed Host", value: "resolved_host" },
  { label: "Technology Change", value: "new_technology" },
  { label: "Finding Resolved", value: "resolved_finding" },
];

const defaultForm = {
  name: "",
  target_input: "",
  schedule: "@daily",
  enabled_phases: ["recon", "fingerprint"],
  alert_on: ["new_finding"],
};

export function Monitor() {
  const queryClient = useQueryClient();
  const [form, setForm] = useState(defaultForm);
  const [selectedConfigID, setSelectedConfigID] = useState("");
  const [selectedRunID, setSelectedRunID] = useState("");
  const configsQuery = useQuery({ queryKey: ["monitor-configs"], queryFn: listMonitorConfigs, refetchInterval: 5000 });
  const selectedConfig = configsQuery.data?.find((config) => config.id === selectedConfigID) ?? configsQuery.data?.[0];
  const runsQuery = useQuery({
    queryKey: ["monitor-runs", selectedConfig?.id],
    queryFn: () => listMonitorRuns(selectedConfig?.id),
    enabled: Boolean(selectedConfig?.id),
    refetchInterval: 5000,
  });
  const selectedRun = runsQuery.data?.find((run) => run.id === selectedRunID) ?? runsQuery.data?.[0];
  const changesQuery = useQuery({
    queryKey: ["monitor-changes", selectedRun?.id],
    queryFn: () => listMonitorRunChanges(selectedRun!.id),
    enabled: Boolean(selectedRun?.id),
  });
  const recentCompletedRuns = useMemo(() => (runsQuery.data ?? []).filter((run) => run.status === "completed").slice(0, 8).reverse(), [runsQuery.data]);
  const trendQueries = useQueries({
    queries: recentCompletedRuns.map((run) => ({
      queryKey: ["monitor-trend-changes", run.id],
      queryFn: () => listMonitorRunChanges(run.id),
      enabled: Boolean(run.id),
    })),
  });
  const createMutation = useMutation({
    mutationFn: () => createMonitorConfig(form),
    onSuccess: (config) => {
      setSelectedConfigID(config.id);
      setForm(defaultForm);
      queryClient.invalidateQueries({ queryKey: ["monitor-configs"] });
    },
  });
  const runMutation = useMutation({
    mutationFn: (configID: string) => runMonitorConfig(configID),
    onSuccess: (result) => {
      setSelectedRunID(result.run.id);
      queryClient.invalidateQueries({ queryKey: ["monitor-runs"] });
      queryClient.invalidateQueries({ queryKey: ["monitor-changes"] });
      queryClient.invalidateQueries({ queryKey: ["sessions"] });
    },
  });
  const toggleMutation = useMutation({
    mutationFn: (config: MonitorConfig) => updateMonitorConfig(config.id, { ...config, enabled: !config.enabled }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["monitor-configs"] }),
  });
  const baselineMutation = useMutation({
    mutationFn: ({ configID, runID }: { configID: string; runID: string }) => resetMonitorBaseline(configID, runID),
    onSuccess: (config) => {
      setSelectedConfigID(config.id);
      queryClient.invalidateQueries({ queryKey: ["monitor-configs"] });
    },
  });
  const deleteMutation = useMutation({
    mutationFn: deleteMonitorConfig,
    onSuccess: () => {
      setSelectedConfigID("");
      queryClient.invalidateQueries({ queryKey: ["monitor-configs"] });
    },
  });
  const operationalSummary = useMemo(() => monitorOperationalSummary(selectedConfig, runsQuery.data ?? []), [runsQuery.data, selectedConfig]);
  const changeGroups = useMemo(() => groupChangesByCategory(changesQuery.data ?? []), [changesQuery.data]);
  const trendPoints = useMemo(() => severityTrend(recentCompletedRuns, trendQueries.map((query) => query.data ?? [])), [recentCompletedRuns, trendQueries]);
  const canCreateMonitor = Boolean(form.target_input.trim()) && form.enabled_phases.length > 0 && form.alert_on.length > 0 && !createMutation.isPending;
  const monitorBlocker = !form.target_input.trim()
    ? "Target is required."
    : form.enabled_phases.length === 0
      ? "Select at least one phase."
      : form.alert_on.length === 0
        ? "Select at least one alert condition."
        : "Ready to create recurring monitor.";

  return (
    <section className="page">
      <header className="page-header">
        <div>
          <h1>Attack Surface Monitor</h1>
          <p>Schedule lightweight recurring scans, baseline the first run, and review drift from later sessions.</p>
        </div>
        <div className="action-row">
          <button className="secondary" onClick={() => configsQuery.refetch()}><RefreshCw size={16} />Refresh</button>
        </div>
      </header>

      <div className="operator-grid">
        <section className="panel monitor-ops-panel">
          <div className="monitor-ops-banner">
            <AlertTriangle size={18} />
            <div>
              <strong>Scheduler runs only while nyx serve is active.</strong>
              <p>Keep the server process running for scheduled windows. Nyx queues one overdue catch-up run on startup, but downtime still means scheduled checks were missed.</p>
            </div>
          </div>
          <div className="monitor-summary-grid">
            <dl>
              <dt>Last Successful Run</dt>
              <dd>{operationalSummary.lastSuccessfulRun ? formatDateTime(operationalSummary.lastSuccessfulRun.completed_at ?? operationalSummary.lastSuccessfulRun.started_at) : "No successful run yet"}</dd>
            </dl>
            <dl className={operationalSummary.missedRuns > 0 ? "warning" : ""}>
              <dt>Missed Scheduled Windows</dt>
              <dd>{operationalSummary.missedRuns > 0 ? `${operationalSummary.missedRuns} likely missed while offline` : "None detected"}</dd>
            </dl>
            <dl>
              <dt>Baseline</dt>
              <dd>{selectedConfig?.baseline_session_id ? selectedConfig.baseline_session_id.slice(0, 8) : "First successful run becomes baseline"}</dd>
            </dl>
            <dl>
              <dt>Severity Trend</dt>
              <dd><SeveritySparkline points={trendPoints} /></dd>
            </dl>
          </div>
        </section>

        <section className="scan-form monitor-form">
          <h2>New Monitor</h2>
          <form className="form-grid" onSubmit={(event) => { event.preventDefault(); createMutation.mutate(); }}>
            <label>Name
              <input value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} placeholder="Production app" />
            </label>
            <label>Target
              <input required value={form.target_input} onChange={(event) => setForm({ ...form, target_input: event.target.value })} placeholder="https://app.example.com" />
            </label>
            <label>Schedule
              <select value={form.schedule} onChange={(event) => setForm({ ...form, schedule: event.target.value })}>
                {scheduleOptions.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
              </select>
              <small>{schedulePreview(form.schedule)}</small>
            </label>
            <label>Custom Cron
              <input value={form.schedule.startsWith("@") ? "" : form.schedule} onChange={(event) => setForm({ ...form, schedule: event.target.value || "@daily" })} placeholder="0 2 * * *" />
            </label>
            <fieldset className="option-fieldset">
              <legend>Phases</legend>
              <div className="checkbox-chip-grid">
                {phaseOptions.map((option) => (
                  <label key={option.value} className={form.enabled_phases.includes(option.value) ? "selected" : ""}>
                    <input type="checkbox" checked={form.enabled_phases.includes(option.value)} onChange={() => setForm({ ...form, enabled_phases: toggleValue(form.enabled_phases, option.value) })} />
                    {option.label}
                  </label>
                ))}
              </div>
            </fieldset>
            <fieldset className="option-fieldset">
              <legend>Alert On</legend>
              <div className="checkbox-chip-grid">
                {alertOptions.map((option) => (
                  <label key={option.value} className={form.alert_on.includes(option.value) ? "selected" : ""}>
                    <input type="checkbox" checked={form.alert_on.includes(option.value)} onChange={() => setForm({ ...form, alert_on: toggleValue(form.alert_on, option.value) })} />
                    {option.label}
                  </label>
                ))}
              </div>
            </fieldset>
            <p className={`form-hint ${canCreateMonitor ? "ready" : "blocked"}`}>{monitorBlocker}</p>
            <button className="primary" type="submit" disabled={!canCreateMonitor}>
              <Bell size={16} />Create Monitor
            </button>
            {createMutation.error ? <p className="form-error">{createMutation.error.message}</p> : null}
          </form>
        </section>

        <section className="panel">
          <h2>Configs</h2>
          <div className="table-wrap">
            <table>
              <thead><tr><th>Name</th><th>Schedule</th><th>Status</th><th>Next</th><th></th></tr></thead>
              <tbody>
                {(configsQuery.data ?? []).map((config) => (
                  <tr key={config.id} className={selectedConfig?.id === config.id ? "selected-row" : ""} onClick={() => setSelectedConfigID(config.id)}>
                    <td><strong>{config.name}</strong><small>{config.target_input}</small></td>
                    <td>{config.schedule}</td>
                    <td><span className={`status ${config.enabled ? "completed" : "paused"}`}>{config.enabled ? "enabled" : "disabled"}</span></td>
                    <td>{config.next_run_at ? new Date(config.next_run_at).toLocaleString() : "-"}</td>
                    <td>
                      <button className="secondary" onClick={(event) => { event.stopPropagation(); toggleMutation.mutate(config); }}>{config.enabled ? "Disable" : "Enable"}</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {(configsQuery.data ?? []).length === 0 ? <p className="empty-line">No monitors configured</p> : null}
          </div>
        </section>

        <section className="panel">
          <h2>Run History</h2>
          {selectedConfig ? (
            <div className="action-row">
              <button className="primary" onClick={() => runMutation.mutate(selectedConfig.id)} disabled={runMutation.isPending}><Play size={16} />Run Now</button>
              <button className="secondary" onClick={() => selectedRun && baselineMutation.mutate({ configID: selectedConfig.id, runID: selectedRun.id })} disabled={!selectedRun?.session_id || selectedRun.status !== "completed" || baselineMutation.isPending}><RotateCcw size={16} />Reset Baseline</button>
              <button className="secondary danger" onClick={() => window.confirm("Delete this monitor?") && deleteMutation.mutate(selectedConfig.id)}><Trash2 size={16} />Delete</button>
            </div>
          ) : null}
          {(runsQuery.data ?? []).length > 0 ? (
            <div className="table-wrap">
              <table>
                <thead><tr><th>Started</th><th>Status</th><th>Session</th><th>Changes</th></tr></thead>
                <tbody>
                  {(runsQuery.data ?? []).map((run) => (
                    <tr key={run.id} className={selectedRun?.id === run.id ? "selected-row" : ""} onClick={() => setSelectedRunID(run.id)}>
                      <td>{new Date(run.started_at).toLocaleString()}</td>
                      <td><span className={`status ${run.status}`}>{run.status}</span>{run.error ? <small>{run.error}</small> : null}</td>
                      <td>{run.session_id ? <Link to={`/sessions/${run.session_id}`}>{run.session_id.slice(0, 8)}</Link> : "-"}</td>
                      <td>{run.changes_found ? "yes" : "no"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : <div className="empty-state compact-empty">No run history for this monitor yet.</div>}
        </section>

        <section className="panel">
          <div className="panel-heading-row">
            <div>
              <h2>Surface Changes</h2>
              <p>{selectedRun ? `Run ${selectedRun.id.slice(0, 8)}` : "Select a monitor run to inspect drift"}</p>
            </div>
            <GitCompareArrows size={18} />
          </div>
          <div className="surface-change-groups">
            {changeGroups.map((group) => (
              <section className="surface-change-group" key={group.id}>
                <header>
                  <strong>{group.title}</strong>
                  <span>{group.changes.length}</span>
                </header>
                <div className="surface-change-list">
                  {group.changes.map((change) => <SurfaceChangeCard change={change} key={change.id} />)}
                </div>
              </section>
            ))}
            {changeGroups.length === 0 ? <p className="empty-line">No changes for the selected run</p> : null}
          </div>
        </section>
      </div>
    </section>
  );
}

export function toggleValue(values: string[], value: string) {
  return values.includes(value) ? values.filter((item) => item !== value) : [...values, value];
}

function SurfaceChangeCard({ change }: { change: SurfaceChange }) {
  return (
    <article className="surface-change-card">
      <div className="surface-change-title">
        <span className={`severity ${change.severity}`}>{change.severity}</span>
        <strong>{change.description}</strong>
      </div>
      <div className="before-after-row">
        <span>
          <small>Before</small>
          <code>{change.previous_value || "Not observed"}</code>
        </span>
        <span>
          <small>After</small>
          <code>{change.current_value || "Not observed"}</code>
        </span>
      </div>
      <span className="event-type">{change.change_type.replace(/_/g, " ")}</span>
    </article>
  );
}

type TrendPoint = {
  id: string;
  label: string;
  rank: number;
};

function SeveritySparkline({ points }: { points: TrendPoint[] }) {
  if (points.length === 0) {
    return <span className="sparkline-empty">No trend yet</span>;
  }
  const width = 160;
  const height = 42;
  const maxRank = 5;
  const coordinates = points.map((point, index) => {
    const x = points.length === 1 ? width / 2 : (index / (points.length - 1)) * width;
    const y = height - (point.rank / maxRank) * (height - 8) - 4;
    return { ...point, x, y };
  });
  const latestRank = points[points.length - 1]?.rank ?? 0;
  return (
    <span className="severity-sparkline" aria-label={`Severity trend ending at ${severityLabel(latestRank)}`}>
      <svg viewBox={`0 0 ${width} ${height}`} role="img">
        <polyline points={coordinates.map((point) => `${point.x},${point.y}`).join(" ")} />
        {coordinates.map((point) => <circle cx={point.x} cy={point.y} key={point.id} r="3" />)}
      </svg>
      <small>{severityLabel(latestRank)}</small>
    </span>
  );
}

export function groupChangesByCategory(changes: SurfaceChange[]) {
  const categories = [
    { id: "new_findings", title: "New Findings", match: (change: SurfaceChange) => change.change_type === "new_finding" },
    { id: "resolved_findings", title: "Resolved Findings", match: (change: SurfaceChange) => change.change_type === "resolved_finding" },
    { id: "severity_changes", title: "Severity Changes", match: (change: SurfaceChange) => change.change_type === "finding_severity_changed" || change.description.toLowerCase().includes("severity") },
    { id: "new_technologies", title: "New Technologies", match: (change: SurfaceChange) => change.change_type === "new_technology" || change.change_type === "service_changed" },
    { id: "disappeared_endpoints", title: "Disappeared Endpoints", match: (change: SurfaceChange) => change.change_type === "resolved_host" || change.change_type === "resolved_service" },
    { id: "new_surface", title: "New Endpoints", match: (change: SurfaceChange) => change.change_type === "new_host" || change.change_type === "new_service" || change.change_type === "endpoint_changed" },
    { id: "other", title: "Other Changes", match: () => true },
  ];
  const remaining = [...changes];
  return categories.map((category) => {
    const selected = remaining.filter(category.match);
    for (const change of selected) {
      const index = remaining.indexOf(change);
      if (index >= 0) {
        remaining.splice(index, 1);
      }
    }
    return {
      id: category.id,
      title: category.title,
      changes: selected.sort((a, b) => severityRank(b.severity) - severityRank(a.severity)),
    };
  }).filter((group) => group.changes.length > 0);
}

export function severityTrend(runs: MonitorRun[], changesByRun: SurfaceChange[][]): TrendPoint[] {
  return runs.map((run, index) => {
    const rank = Math.max(0, ...((changesByRun[index] ?? []).map((change) => severityRank(change.severity))));
    return {
      id: run.id,
      label: formatShortDate(run.completed_at ?? run.started_at),
      rank,
    };
  });
}

export function monitorOperationalSummary(config: MonitorConfig | undefined, runs: MonitorRun[]) {
  const completedRuns = runs.filter((run) => run.status === "completed");
  const lastSuccessfulRun = completedRuns[0];
  return {
    lastSuccessfulRun,
    missedRuns: missedScheduledWindows(config, new Date()),
  };
}

export function missedScheduledWindows(config: MonitorConfig | undefined, now: Date) {
  if (!config?.enabled || !config.next_run_at) {
    return 0;
  }
  const interval = scheduleIntervalMs(config.schedule);
  if (interval === 0) {
    return 0;
  }
  const nextRun = new Date(config.next_run_at);
  const overdueMs = now.getTime() - nextRun.getTime();
  if (!Number.isFinite(overdueMs) || overdueMs < 0) {
    return 0;
  }
  return Math.floor(overdueMs / interval) + 1;
}

function scheduleIntervalMs(schedule: string) {
  if (schedule === "@hourly") return 60 * 60 * 1000;
  if (schedule === "@daily") return 24 * 60 * 60 * 1000;
  if (schedule === "@weekly") return 7 * 24 * 60 * 60 * 1000;
  return 0;
}

function severityRank(severity: string) {
  const rank: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
  return rank[severity] ?? 0;
}

function severityLabel(rank: number) {
  if (rank >= 5) return "critical";
  if (rank >= 4) return "high";
  if (rank >= 3) return "medium";
  if (rank >= 2) return "low";
  if (rank >= 1) return "info";
  return "no changes";
}

function formatDateTime(value: string) {
  return new Date(value).toLocaleString();
}

function formatShortDate(value: string) {
  return new Date(value).toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

function schedulePreview(schedule: string) {
  if (schedule === "@hourly") return "Runs once per hour while nyx serve is active.";
  if (schedule === "@daily") return "Runs once per day while nyx serve is active.";
  if (schedule === "@weekly") return "Runs once per week while nyx serve is active.";
  return `Custom cron: ${schedule || "@daily"}`;
}
