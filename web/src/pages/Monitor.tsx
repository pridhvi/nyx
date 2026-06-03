import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Bell, Play, RefreshCw, Trash2 } from "lucide-react";
import { createMonitorConfig, deleteMonitorConfig, listMonitorConfigs, listMonitorRunChanges, listMonitorRuns, runMonitorConfig, updateMonitorConfig, type MonitorConfig, type SurfaceChange } from "../api/client";

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
  { label: "New Host", value: "new_host" },
  { label: "Removed Host", value: "removed_host" },
  { label: "Technology Change", value: "technology_change" },
  { label: "Finding Resolved", value: "finding_resolved" },
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
  const deleteMutation = useMutation({
    mutationFn: deleteMonitorConfig,
    onSuccess: () => {
      setSelectedConfigID("");
      queryClient.invalidateQueries({ queryKey: ["monitor-configs"] });
    },
  });
  const groupedChanges = useMemo(() => groupChanges(changesQuery.data ?? []), [changesQuery.data]);

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
            <button className="primary" type="submit" disabled={createMutation.isPending || !form.target_input.trim()}>
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
          <h2>Surface Changes</h2>
          <div className="event-list">
            {groupedChanges.map((change) => (
              <article className="event-item" key={change.id}>
                <span className={`severity ${change.severity}`}>{change.severity}</span>
                <div>
                  <strong>{change.description}</strong>
                  <small>{change.previous_value ? `${change.previous_value} -> ` : ""}{change.current_value}</small>
                </div>
                <span className="event-type">{change.change_type.replace(/_/g, " ")}</span>
              </article>
            ))}
            {groupedChanges.length === 0 ? <p className="empty-line">No changes for the selected run</p> : null}
          </div>
        </section>
      </div>
    </section>
  );
}

export function toggleValue(values: string[], value: string) {
  return values.includes(value) ? values.filter((item) => item !== value) : [...values, value];
}

function groupChanges(changes: SurfaceChange[]) {
  const rank: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
  return [...changes].sort((a, b) => (rank[b.severity] ?? 0) - (rank[a.severity] ?? 0));
}
