import { useEffect, useMemo, useState, type MouseEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Activity, AlertTriangle, CheckCircle2, Clock, Loader2, Pause, Play, Radar, Square, TerminalSquare, Trash2, XCircle } from "lucide-react";
import { Link } from "react-router-dom";
import { compareSessions, deleteSession, getScanStatus, getSessionStats, listFindings, listMonitorConfigs, listMonitorRunChanges, listMonitorRuns, listTargets, listToolRuns, listTools, pauseScan, resumeScan, scanEventsURL, stopScan, type ScanEvent, type ToolRun } from "../api/client";
import { useSessionContext } from "../session";
import { severityColorTokens } from "../theme";

const severityOrder = ["critical", "high", "medium", "low", "info"] as const;

const severityColors = severityColorTokens;

const phaseLabels: Record<string, string> = {
  source_analysis: "Source",
  audit: "Audit",
  recon: "Recon",
  fingerprint: "Fingerprint",
  enumerate: "Enumerate",
  vuln_scan: "Vulnerability",
  dynamic: "Dynamic",
  correlation: "Correlation",
};

export function Dashboard() {
  const queryClient = useQueryClient();
  const { sessions, selectedSessionID, setSelectedSessionID, refreshSessions } = useSessionContext();
  const [scanEvents, setScanEvents] = useState<ScanEvent[]>([]);
  const [hoveredRisk, setHoveredRisk] = useState<HoveredRiskMix | null>(null);
  const [baseCompareSessionID, setBaseCompareSessionID] = useState("");
  const selected = selectedSessionID;
  const selectedRecord = sessions.find((record) => record.session.id === selected)?.session;
  const statsQuery = useQuery({
    queryKey: ["session-stats", selected],
    queryFn: () => getSessionStats(selected),
    enabled: selected !== "",
    refetchInterval: 2500,
  });
  const scanStatusQuery = useQuery({
    queryKey: ["scan-status", selected],
    queryFn: () => getScanStatus(selected),
    enabled: selected !== "",
    refetchInterval: 2500,
  });
  const findingsQuery = useQuery({
    queryKey: ["findings", selected],
    queryFn: () => listFindings(selected),
    enabled: selected !== "",
    refetchInterval: 2500,
  });
  const targetsQuery = useQuery({
    queryKey: ["targets", selected],
    queryFn: () => listTargets(selected),
    enabled: selected !== "",
    refetchInterval: 3500,
  });
  const toolRunsQuery = useQuery({
    queryKey: ["tool-runs", selected],
    queryFn: () => listToolRuns(selected),
    enabled: selected !== "",
    refetchInterval: 2500,
  });
  const toolsQuery = useQuery({ queryKey: ["tools"], queryFn: () => listTools(), refetchInterval: 5000 });
  const pauseMutation = useMutation({ mutationFn: () => pauseScan(selected), onSuccess: refreshSessions });
  const resumeMutation = useMutation({ mutationFn: () => resumeScan(selected), onSuccess: refreshSessions });
  const cancelMutation = useMutation({
    mutationFn: () => stopScan(selected),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["sessions"] });
      refreshSessions();
    },
  });
  const deleteMutation = useMutation({
    mutationFn: () => deleteSession(selected),
    onSuccess: () => {
      setSelectedSessionID("");
      queryClient.invalidateQueries({ queryKey: ["sessions"] });
      refreshSessions();
    },
  });
  const totals = useMemo(() => {
    return sessions.reduce(
      (acc, record) => {
        if (record.session.status === "running" || record.session.status === "pending" || record.session.status === "paused") {
          acc.active += 1;
        }
        acc.findings += record.session.finding_count;
        return acc;
      },
      { active: 0, findings: 0 },
    );
  }, [sessions]);
  const lastCompletedSession = useMemo(() => {
    return sessions
      .map((record) => record.session)
      .filter((session) => session.status === "completed")
      .sort((a, b) => new Date(b.completed_at ?? b.started_at ?? b.created_at).getTime() - new Date(a.completed_at ?? a.started_at ?? a.created_at).getTime())[0];
  }, [sessions]);
  const lastCompletedStatsQuery = useQuery({
    queryKey: ["session-stats", lastCompletedSession?.id],
    queryFn: () => getSessionStats(lastCompletedSession?.id ?? ""),
    enabled: Boolean(lastCompletedSession?.id),
    refetchInterval: 5000,
  });
  const monitorConfigsQuery = useQuery({ queryKey: ["monitor-configs"], queryFn: listMonitorConfigs, refetchInterval: 10000 });
  const monitorRunsQuery = useQuery({ queryKey: ["monitor-runs"], queryFn: () => listMonitorRuns(), refetchInterval: 10000 });
  const latestMonitorRun = useMemo(() => {
    return [...(monitorRunsQuery.data ?? [])].sort((a, b) => new Date(b.started_at).getTime() - new Date(a.started_at).getTime())[0];
  }, [monitorRunsQuery.data]);
  const monitorChangesQuery = useQuery({
    queryKey: ["monitor-changes", latestMonitorRun?.id],
    queryFn: () => listMonitorRunChanges(latestMonitorRun?.id ?? ""),
    enabled: Boolean(latestMonitorRun?.id),
    refetchInterval: 10000,
  });
  const newMonitorFindings = useMemo(() => {
    return (monitorChangesQuery.data ?? []).filter((change) => change.change_type === "new_finding" || (change.finding_id && change.change_type.includes("finding"))).length;
  }, [monitorChangesQuery.data]);
  const comparableSessions = useMemo(() => sessions.filter((record) => record.session.id !== selected), [selected, sessions]);
  useEffect(() => {
    if (!baseCompareSessionID || baseCompareSessionID === selected || !comparableSessions.some((record) => record.session.id === baseCompareSessionID)) {
      setBaseCompareSessionID(comparableSessions[0]?.session.id ?? "");
    }
  }, [baseCompareSessionID, comparableSessions, selected]);
  const compareQuery = useQuery({
    queryKey: ["session-compare", selected, baseCompareSessionID],
    queryFn: () => compareSessions(selected, baseCompareSessionID),
    enabled: Boolean(selected && baseCompareSessionID && selected !== baseCompareSessionID),
  });
  const severityData = useMemo(() => {
    return buildRiskMixData(statsQuery.data?.severity_counts);
  }, [statsQuery.data]);
  const severityTotal = useMemo(() => severityData.reduce((total, item) => total + item.value, 0), [severityData]);
  const severitySegments = useMemo(() => buildRiskMixSegments(severityData), [severityData]);
  const severityLabel = useMemo(() => riskMixLabel(severityData), [severityData]);
  const priorityFindings = useMemo(() => {
    const rank: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
    return [...(findingsQuery.data ?? [])].sort((a, b) => (rank[b.severity] ?? 0) - (rank[a.severity] ?? 0)).slice(0, 8);
  }, [findingsQuery.data]);
  const status = scanStatusQuery.data?.status ?? selectedRecord?.status ?? "";
  const isActiveScan = status === "running" || status === "pending" || status === "paused";
  const activeFindingCount = findingsQuery.data?.length ?? scanStatusQuery.data?.finding_count ?? selectedRecord?.finding_count ?? 0;
  const nextActions = useMemo(() => {
    if (!selectedRecord) return ["Start a scoped scan", "Review tool readiness", "Configure local LLM if desired"];
    if (selectedRecord.status === "running" || selectedRecord.status === "pending") return ["Watch active tool nodes", "Pause if scope needs adjustment", "Triage new high-risk findings"];
    if (activeFindingCount > 0) return ["Open triage workspace", "Review attack paths", "Generate a technical report"];
    return ["Review tool logs", "Run a broader profile", "Export the clean session record"];
  }, [activeFindingCount, selectedRecord]);
  const handleRiskPointerMove = (event: MouseEvent<HTMLDivElement>) => {
    const rect = event.currentTarget.getBoundingClientRect();
    const x = event.clientX - rect.left;
    const y = event.clientY - rect.top;
    const segment = riskSegmentAtPoint(severitySegments, x, y, rect.width, rect.height);
    setHoveredRisk(segment ? { segment, anchor: riskTooltipAnchor(x, y, rect.width, rect.height) } : null);
  };

  useEffect(() => {
    if (!selected) {
      setScanEvents([]);
      return;
    }
    setScanEvents([]);
    const socket = new WebSocket(scanEventsURL(selected));
    socket.onmessage = (message) => {
      const event = JSON.parse(message.data) as ScanEvent;
      setScanEvents((current) => [event, ...current.filter((item) => item.at !== event.at || item.type !== event.type)].slice(0, 12));
      if (event.type === "completed" || event.type === "failed" || event.type === "cancelled") {
        window.dispatchEvent(new CustomEvent("nyx-toast", {
          detail: {
            tone: event.type === "completed" ? "success" : "error",
            title: event.type === "completed" ? "Scan completed" : event.type === "failed" ? "Scan failed" : "Scan cancelled",
            message: event.message ?? selectedRecord?.target_input ?? selected,
          },
        }));
      }
      if (event.type === "finding_found" || event.type === "tool_completed" || event.type === "tool_error" || event.type === "completed" || event.type === "failed" || event.type === "cancelled" || event.status === "paused") {
        queryClient.invalidateQueries({ queryKey: ["sessions"] });
        queryClient.invalidateQueries({ queryKey: ["session-stats", selected] });
        queryClient.invalidateQueries({ queryKey: ["findings", selected] });
        queryClient.invalidateQueries({ queryKey: ["tool-runs", selected] });
        queryClient.invalidateQueries({ queryKey: ["scan-status", selected] });
      }
    };
    return () => socket.close();
  }, [queryClient, selected]);

  const progressEvents = useMemo(() => mergeScanEvents(scanEvents, scanStatusQuery.data?.recent_events ?? []), [scanEvents, scanStatusQuery.data?.recent_events]);
  const highLevelEvents = useMemo(() => progressEvents.filter((event) => {
    return ["phase_started", "phase_completed", "tool_completed", "tool_error", "completed", "failed", "cancelled"].includes(event.type) || event.status === "paused" || event.type === "finding_found";
  }).slice(0, 10), [progressEvents]);
  const terminalLines = useMemo(() => {
    const lines = progressEvents.map((event) => event.message ?? event.finding_title ?? `${event.type}${event.tool_id ? ` ${event.tool_id}` : ""}`);
    for (const run of (toolRunsQuery.data ?? []).slice(0, 8)) {
      lines.push(`${run.tool_id}: exit=${run.exit_code} findings=${run.finding_count}`);
    }
    return lines.slice(0, 18);
  }, [progressEvents, toolRunsQuery.data]);
  const pipeline = useMemo(() => {
    if ((scanStatusQuery.data?.tools ?? []).length > 0) {
      const grouped = new Map<string, { id: string; name: string; state: string; count: number; duration?: number }[]>();
      for (const tool of scanStatusQuery.data?.tools ?? []) {
        const latestEvent = progressEvents.find((event) => event.tool_id === tool.tool_id);
        let state = normalizeToolProgressState(tool.status);
        if (latestEvent?.type === "tool_started") state = "running";
        if (latestEvent?.type === "tool_error") state = "error";
        if (latestEvent?.type === "tool_completed") state = latestEvent.status === "failed" ? "error" : "done";
        const phaseTools = grouped.get(tool.phase) ?? [];
        phaseTools.push({ id: tool.tool_id, name: tool.name ?? tool.tool_id, state, count: latestEvent?.finding_count ?? tool.finding_count, duration: latestEvent?.duration_ms ?? tool.duration_ms });
        grouped.set(tool.phase, phaseTools);
      }
      return [...grouped.entries()];
    }
    const selectedTools = new Set(selectedRecord?.enabled_tools ?? []);
    const records = (toolsQuery.data ?? []).filter((tool) => selectedTools.size === 0 || selectedTools.has(tool.id));
    const grouped = new Map<string, { id: string; name: string; state: string; count: number; duration?: number }[]>();
    for (const tool of records) {
      const events = progressEvents.filter((event) => event.tool_id === tool.id);
      const latestRun = latestRunForTool(toolRunsQuery.data ?? [], tool.id);
      const latestEvent = events[0];
      let state = "pending";
      if (latestRun) state = latestRun.exit_code === 0 ? "done" : "error";
      if (latestEvent?.type === "tool_started") state = "running";
      if (latestEvent?.type === "tool_error") state = "error";
      if (latestEvent?.type === "tool_completed") state = latestEvent.status === "failed" ? "error" : "done";
      const count = latestEvent?.finding_count ?? latestRun?.finding_count ?? 0;
      const duration = latestEvent?.duration_ms ?? latestRun?.duration_ms;
      const tools = grouped.get(tool.phase) ?? [];
      tools.push({ id: tool.id, name: tool.name, state, count, duration });
      grouped.set(tool.phase, tools);
    }
    return [...grouped.entries()];
  }, [progressEvents, scanStatusQuery.data?.tools, selectedRecord?.enabled_tools, toolRunsQuery.data, toolsQuery.data]);
  const progressTracks = useMemo(() => {
    if ((scanStatusQuery.data?.phases ?? []).length > 0) {
      return (scanStatusQuery.data?.phases ?? []).map((item) => {
        const completed = progressEvents.some((event) => event.phase === item.phase && event.type === "phase_completed");
        const started = progressEvents.some((event) => event.phase === item.phase && event.type === "phase_started");
        const failed = progressEvents.some((event) => event.phase === item.phase && event.status === "failed");
        return { phase: item.phase, state: failed ? "failed" : completed ? "completed" : started ? "running" : normalizePhaseProgressState(item.status) };
      });
    }
    const phases = selectedRecord?.workload_mode === "dynamic" ? ["recon", "fingerprint", "enumerate", "vuln_scan", "correlation"] : ["source_analysis", "audit", "dynamic", "correlation"];
    return phases.map((phase) => {
      const event = progressEvents.find((item) => item.phase === phase);
      const completed = progressEvents.some((item) => item.phase === phase && item.type === "phase_completed");
      const started = progressEvents.some((item) => item.phase === phase && item.type === "phase_started");
      return { phase, state: completed ? "completed" : started ? "running" : event ? "pending" : "pending" };
    });
  }, [progressEvents, scanStatusQuery.data?.phases, selectedRecord?.workload_mode]);

  return (
    <section className="page">
      <header className="page-header command-header">
        <div>
          <h1>Command Center</h1>
          <p>{selectedRecord ? `${selectedRecord.name || "Untitled engagement"} · ${selectedRecord.workload_mode ?? "dynamic"} workload · ${selectedRecord.target_count} target${selectedRecord.target_count === 1 ? "" : "s"}` : "Start scoped scans, monitor findings, and review attack paths."}</p>
        </div>
        <div className="action-row">
          <Link className="primary link-button" to="/scan"><TerminalSquare size={16} />Quick Scan</Link>
          {selected ? (
            <>
              {status === "running" ? <button className="secondary" onClick={() => pauseMutation.mutate()}><Pause size={16} />Pause</button> : null}
              {status === "running" || status === "pending" ? <button className="secondary danger" onClick={() => window.confirm("Cancel this scan?") && cancelMutation.mutate()}><Square size={16} />Cancel</button> : null}
              {status === "paused" ? <button className="secondary" onClick={() => resumeMutation.mutate()}><Play size={16} />Resume</button> : null}
              <button className="secondary danger" onClick={() => window.confirm("Delete this session and its database?") && deleteMutation.mutate()}><Trash2 size={16} />Delete</button>
            </>
          ) : null}
        </div>
      </header>
      {sessions.length === 0 ? (
        <section className="first-run-panel">
          <div>
            <span className="card-kicker">First Run</span>
            <h2>Create your first Nyx session</h2>
            <p>Start with a scoped quick scan, then come back here for progress, triage, reports, and retest comparisons.</p>
          </div>
          <div className="first-run-actions">
            <Link className="primary link-button" to="/scan"><TerminalSquare size={16} />New Scan</Link>
            <Link className="secondary link-button" to="/settings">Check System Health</Link>
          </div>
        </section>
      ) : null}
      <div className="command-layout">
        <section className="last-scan-card">
          <div>
            <span className="card-kicker">Last Completed Scan</span>
            <h2>{lastCompletedSession ? lastCompletedSession.name || lastCompletedSession.target_input || lastCompletedSession.source_path || "Untitled engagement" : "No Completed Scan Yet"}</h2>
            <p>{lastCompletedSession ? `${formatTimestamp(lastCompletedSession.completed_at ?? lastCompletedSession.started_at ?? lastCompletedSession.created_at)} · ${lastCompletedSession.workload_mode ?? "dynamic"} workload` : "Start a scoped run to populate the dashboard with completed scan history."}</p>
          </div>
          <div className="last-scan-summary">
            <div className="finding-count-display">{lastCompletedStatsQuery.data?.finding_count ?? lastCompletedSession?.finding_count ?? 0}</div>
            <div className="severity-stack" aria-label="Last completed scan severity counts">
              {severityOrder.map((severity) => (
                <span key={severity} className={`severity-count ${severity}`}>{severity}<strong>{lastCompletedStatsQuery.data?.severity_counts?.[severity] ?? 0}</strong></span>
              ))}
            </div>
          </div>
          <div className="monitor-delta-line">
            <span>{(monitorConfigsQuery.data ?? []).filter((config) => config.enabled).length} active monitor{(monitorConfigsQuery.data ?? []).filter((config) => config.enabled).length === 1 ? "" : "s"}</span>
            <strong>{latestMonitorRun ? `${newMonitorFindings} new finding${newMonitorFindings === 1 ? "" : "s"} in latest monitor run` : "No monitor baseline yet"}</strong>
          </div>
          <div className="action-row">
            <Link className="primary link-button" to="/scan"><Radar size={16} />Quick Scan</Link>
            {lastCompletedSession ? <Link className="secondary link-button" to={`/sessions/${lastCompletedSession.id}/findings`}>Review Last Findings</Link> : null}
          </div>
        </section>
        <section className="panel session-compare-panel">
          <div className="panel-heading-row">
            <div>
              <h2>Retest Compare</h2>
              <p className="profile-description">Compare the selected session against an earlier manual run.</p>
            </div>
            <label className="compact-select">Base
              <select value={baseCompareSessionID} onChange={(event) => setBaseCompareSessionID(event.target.value)} disabled={comparableSessions.length === 0}>
                {comparableSessions.map((record) => (
                  <option key={record.session.id} value={record.session.id}>{record.session.name || record.session.target_input || record.session.id}</option>
                ))}
              </select>
            </label>
          </div>
          {selected && baseCompareSessionID && compareQuery.data ? (
            <>
              <div className="compare-metrics">
                <span><strong>{compareQuery.data.new_count}</strong>new</span>
                <span><strong>{compareQuery.data.resolved_count}</strong>resolved</span>
                <span><strong>{compareQuery.data.severity_change_count}</strong>severity changed</span>
              </div>
              <div className="compare-list">
                {compareQuery.data.severity_changes.slice(0, 3).map((change) => (
                  <Link key={change.fingerprint} to={`/sessions/${selected}/findings?finding_id=${change.finding_id}`}>
                    <span className={`severity ${change.to}`}>{change.to}</span>
                    <strong>{change.title}</strong>
                    <small>{change.from} to {change.to} · {change.url || change.tool_id}</small>
                  </Link>
                ))}
                {compareQuery.data.new_findings.slice(0, 3).map((finding) => (
                  <Link key={finding.id} to={`/sessions/${selected}/findings?finding_id=${finding.id}`}>
                    <span className={`severity ${finding.severity}`}>{finding.severity}</span>
                    <strong>{finding.title}</strong>
                    <small>new · {finding.url || finding.tool_id}</small>
                  </Link>
                ))}
                {compareQuery.data.new_count + compareQuery.data.resolved_count + compareQuery.data.severity_change_count === 0 ? <div className="empty-line">No finding changes between these sessions.</div> : null}
              </div>
            </>
          ) : <div className="empty-line">{comparableSessions.length === 0 ? "Run another session to compare retest results." : "Loading comparison."}</div>}
        </section>
        <section className="panel">
          <h2>Next Actions</h2>
          <div className="action-stack">
            {nextActions.map((action, index) => <span key={action}><strong>{index + 1}</strong>{action}</span>)}
          </div>
          <div className="target-strip command-targets">
            {(targetsQuery.data ?? []).slice(0, 8).map((target) => <span key={target.id}>{target.protocol}://{target.host}{target.port ? `:${target.port}` : ""}</span>)}
            {(targetsQuery.data ?? []).length === 0 ? <span>No targets discovered</span> : null}
          </div>
        </section>
        <section className="panel">
          <h2>Selected Risk Mix</h2>
          <div className="chart-panel risk-mix-panel">
            {severityData.length > 0 ? (
              <div className="risk-donut" role="img" aria-label={severityLabel} onMouseMove={handleRiskPointerMove} onMouseLeave={() => setHoveredRisk(null)}>
                <svg className="risk-donut-svg" viewBox="0 0 148 148" aria-hidden="true">
                  <circle className="risk-donut-track" cx="74" cy="74" r="54" />
                  {severitySegments.map((segment) => (
                    <circle
                      key={segment.severity}
                      className="risk-donut-segment"
                      cx="74"
                      cy="74"
                      r="54"
                      stroke={severityColors[segment.severity]}
                      strokeDasharray={`${segment.length} ${segment.gap}`}
                      strokeDashoffset={segment.offset}
                    />
                  ))}
                </svg>
                <div className="risk-donut-hole">
                  <strong>{severityTotal}</strong>
                  <span>findings</span>
                </div>
                {hoveredRisk ? (
                  <div className={`risk-tooltip risk-tooltip-${hoveredRisk.anchor} risk-tooltip-${hoveredRisk.segment.severity}`}>
                    <span aria-hidden="true" />
                    {riskTooltipLabel(hoveredRisk.segment)}
                  </div>
                ) : null}
              </div>
            ) : <div className="empty-line">No severity data yet.</div>}
          </div>
          <div className="severity-strip">
            {severityOrder.map((severity) => (
              <span key={severity}>{severity}: {statsQuery.data?.severity_counts?.[severity] ?? 0}</span>
            ))}
          </div>
        </section>
      </div>
      <div className="metric-grid">
        <article><Activity /><span>Active Sessions</span><strong>{totals.active}</strong></article>
        <article><AlertTriangle /><span>Total Findings</span><strong>{totals.findings}</strong></article>
        <article><Activity /><span>Tool Runs</span><strong>{statsQuery.data?.tool_run_count ?? 0}</strong></article>
        <article><AlertTriangle /><span>Static / Dynamic</span><strong>{statsQuery.data?.static_finding_count ?? 0} / {statsQuery.data?.dynamic_finding_count ?? 0}</strong></article>
        <article><Activity /><span>Source Findings</span><strong>{statsQuery.data?.source_finding_count ?? 0}</strong></article>
        <article><AlertTriangle /><span>Confirmed By Both</span><strong>{statsQuery.data?.confirmed_by_both ?? 0}</strong></article>
      </div>
      <div className="data-grid">
        <section className="panel">
          <h2>Sessions</h2>
          <div className="session-grid scroll-panel" tabIndex={0}>
            {sessions.map((record) => (
              <article
                key={record.session.id}
                className={`session-card ${record.session.id === selected ? "selected" : ""}`}
                onClick={() => setSelectedSessionID(record.session.id)}
              >
                <div>
                  <strong className="session-host">{record.session.name || record.session.target_input || record.session.source_path || "Untitled engagement"}</strong>
                  <div className="session-meta">{record.session.workload_mode ?? "dynamic"} · {record.session.target_count} target{record.session.target_count === 1 ? "" : "s"} · {new Date(record.session.created_at).toLocaleString()}</div>
                </div>
                <SeverityBar counts={record.session.id === selected ? statsQuery.data?.severity_counts : undefined} total={record.session.finding_count} />
                <div className="session-footer">
                  <span className={`status ${record.session.status}`}>{record.session.status}</span>
                  <span className="finding-count"><span>{record.session.finding_count}</span> findings</span>
                </div>
              </article>
            ))}
            {sessions.length === 0 ? <div className="empty-line">No sessions yet.</div> : null}
          </div>
        </section>
        <section className="panel">
          <div className="panel-heading-row">
            <h2>Priority Findings</h2>
            {selected && activeFindingCount > 0 ? <Link to={`/sessions/${selected}/findings`}>View all</Link> : null}
          </div>
          <div className="target-strip">
            {(targetsQuery.data ?? []).slice(0, 6).map((target) => <span key={target.id}>{target.protocol}://{target.host}{target.port ? `:${target.port}` : ""}</span>)}
          </div>
          <div className="finding-list scroll-panel" tabIndex={0}>
            {priorityFindings.map((finding) => (
              <article key={finding.id} className="finding-item">
                <span className={`severity ${finding.severity}`}>{finding.severity}</span>
                <strong>{finding.title}</strong>
                <small>{finding.tool_id} · {finding.url}</small>
              </article>
            ))}
            {(findingsQuery.data ?? []).length === 0 ? <div className="empty-line">No findings for the selected session. Run a broader profile or open tool logs if this was unexpected.</div> : null}
          </div>
        </section>
      </div>
      <section className="panel event-panel">
        <div className="panel-heading-row">
          <div>
            <h2>{isActiveScan ? "Live Phase Progress" : "Latest Phase Progress"}</h2>
            <p className="profile-description">Phase state is primary. Tool-level rows and terminal output are available below for debugging.</p>
          </div>
          <span className={`status ${status || "pending"}`}>{status || "no session"}</span>
        </div>
        <div className="phase-progress-grid">
          {progressTracks.map((track) => <PhaseProgressCard key={track.phase} track={track} />)}
        </div>
        <div className="live-progress-grid">
          <div className="recent-events">
            <h3>Recent Events</h3>
            <div className="event-list">
              {highLevelEvents.map((event) => (
                <article key={`${event.type}-${event.at}-${event.tool_id ?? ""}-${event.finding_id ?? ""}`} className={`event-item ${eventTone(event)}`}>
                  <span className={`event-type ${event.type}`}>{event.status === "paused" ? "paused" : event.type.replace("_", " ")}</span>
                  <strong>{event.message ?? event.finding_title ?? event.tool_id ?? event.status ?? "Scan event"}</strong>
                  <small>{new Date(event.at).toLocaleTimeString()}{event.tool_id ? ` · ${event.tool_id}` : ""}</small>
                </article>
              ))}
              {highLevelEvents.length === 0 ? <div className="empty-line">No live events for the selected session.</div> : null}
            </div>
          </div>
          <details className="debug-disclosure">
            <summary>Tool pipeline details</summary>
            <div className="pipeline">
              {pipeline.map(([phase, tools]) => (
                <div className="pipeline-phase" key={phase}>
                  <div className="pipeline-phase-label">{phaseLabels[phase] ?? phase}</div>
                  <div className="pipeline-tools">
                    {tools.map((tool) => (
                      <article className={`tool-progress-row ${tool.state}`} key={tool.id}>
                        <span className="tool-progress-icon">{statusIcon(tool.state)}</span>
                        <div>
                          <strong>{tool.id}</strong>
                          <small>{tool.name}</small>
                        </div>
                        <span className="tool-progress-meta">{tool.count} finding{tool.count === 1 ? "" : "s"}{tool.duration ? ` · ${formatDuration(tool.duration)}` : ""}</span>
                      </article>
                    ))}
                  </div>
                </div>
              ))}
              {pipeline.length === 0 ? <div className="empty-line">No tool pipeline is available for the selected session.</div> : null}
            </div>
          </details>
        </div>
      </section>
      <details className="panel terminal-feed debug-disclosure" open={isActiveScan || undefined}>
        <summary>Live Terminal Feed</summary>
        <pre>{terminalLines.length > 0 ? terminalLines.join("\n") : "No terminal output for the selected session yet."}</pre>
      </details>
    </section>
  );
}

type RiskMixDatum = {
  severity: string;
  value: number;
};

type RiskMixSegment = {
  severity: string;
  value: number;
  length: string;
  gap: string;
  offset: string;
  startDegrees: number;
  endDegrees: number;
  title: string;
};

type HoveredRiskMix = {
  segment: RiskMixSegment;
  anchor: string;
};

export function buildRiskMixData(counts: Record<string, number> = {}): RiskMixDatum[] {
  return severityOrder.map((severity) => ({
    severity,
    value: counts[severity] ?? 0,
  })).filter((item) => item.value > 0);
}

export function buildRiskMixSegments(data: RiskMixDatum[]): RiskMixSegment[] {
  const total = data.reduce((sum, item) => sum + item.value, 0);
  if (total <= 0) return [];
  const circumference = 2 * Math.PI * 54;
  let cursor = 0;
  let degreesCursor = 0;
  return data.map((item) => {
    const length = (item.value / total) * circumference;
    const degrees = (item.value / total) * 360;
    const segment = {
      severity: item.severity,
      value: item.value,
      length: length.toFixed(2),
      gap: (circumference - length).toFixed(2),
      offset: (-cursor).toFixed(2),
      startDegrees: degreesCursor,
      endDegrees: degreesCursor + degrees,
      title: `${item.severity}: ${item.value} finding${item.value === 1 ? "" : "s"}`,
    };
    cursor += length;
    degreesCursor += degrees;
    return segment;
  });
}

export function riskTooltipLabel(segment: Pick<RiskMixSegment, "severity" | "value">) {
  return `${segment.severity}: ${segment.value} finding${segment.value === 1 ? "" : "s"}`;
}

export function riskTooltipAnchor(x: number, y: number, width = 148, height = 148) {
  const angle = Math.atan2(y - height / 2, x - width / 2) * 180 / Math.PI;
  if (angle >= -22.5 && angle < 22.5) return "right";
  if (angle >= 22.5 && angle < 67.5) return "bottom-right";
  if (angle >= 67.5 && angle < 112.5) return "bottom";
  if (angle >= 112.5 && angle < 157.5) return "bottom-left";
  if (angle >= 157.5 || angle < -157.5) return "left";
  if (angle >= -157.5 && angle < -112.5) return "top-left";
  if (angle >= -112.5 && angle < -67.5) return "top";
  return "top-right";
}

export function riskSegmentAtPoint(segments: RiskMixSegment[], x: number, y: number, width = 148, height = 148): RiskMixSegment | null {
  if (segments.length === 0) return null;
  const size = Math.min(width, height);
  const centerX = width / 2;
  const centerY = height / 2;
  const radius = Math.hypot(x - centerX, y - centerY);
  const innerRadius = size * 0.27;
  const outerRadius = size * 0.47;
  if (radius < innerRadius || radius > outerRadius) return null;
  const angle = (Math.atan2(y - centerY, x - centerX) * 180 / Math.PI + 90 + 360) % 360;
  return segments.find((segment) => angle >= segment.startDegrees && angle < segment.endDegrees) ?? segments[segments.length - 1];
}

export function riskMixLabel(data: RiskMixDatum[]) {
  if (data.length === 0) return "No severity data yet.";
  return `Selected risk mix: ${data.map((item) => `${item.value} ${item.severity}`).join(", ")}.`;
}

function latestRunForTool(runs: ToolRun[], toolID: string) {
  return runs.filter((run) => run.tool_id === toolID).sort((a, b) => new Date(b.started_at).getTime() - new Date(a.started_at).getTime())[0];
}

function mergeScanEvents(primary: ScanEvent[], fallback: ScanEvent[]) {
  const seen = new Set<string>();
  return [...primary, ...fallback].filter((event) => {
    const key = `${event.type}:${event.at}:${event.tool_id ?? ""}:${event.finding_id ?? ""}:${event.phase ?? ""}`;
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  }).sort((a, b) => new Date(b.at).getTime() - new Date(a.at).getTime());
}

function normalizeToolProgressState(status: string) {
  if (status === "completed") return "done";
  if (status === "failed") return "error";
  if (status === "running") return "running";
  return "pending";
}

function normalizePhaseProgressState(status: string) {
  if (status === "failed") return "failed";
  if (status === "completed") return "completed";
  if (status === "running") return "running";
  return "pending";
}

function SeverityBar({ counts, total }: { counts?: Record<string, number>; total: number }) {
  const values = severityOrder.map((severity) => ({ severity, value: counts?.[severity] ?? 0 }));
  const known = values.reduce((sum, item) => sum + item.value, 0);
  if (known === 0 && total > 0) {
    return (
      <svg className="sev-bar" viewBox="0 0 100 5" preserveAspectRatio="none" aria-hidden="true">
        <rect className="sev-bar-seg sev-info" x="0" y="0" width="100" height="5" rx="2.5" />
      </svg>
    );
  }
  let cursor = 0;
  return (
    <svg className="sev-bar" viewBox="0 0 100 5" preserveAspectRatio="none" aria-hidden="true">
      {values.map((item) => {
        if (item.value <= 0 || known <= 0) return null;
        const width = (item.value / known) * 100;
        const x = cursor;
        cursor += width;
        return <rect key={item.severity} className={`sev-bar-seg sev-${item.severity}`} x={x.toFixed(2)} y="0" width={width.toFixed(2)} height="5" rx="2.5" />;
      })}
    </svg>
  );
}

function eventTone(event: ScanEvent) {
  if (event.type === "failed" || event.type === "tool_error" || event.type === "cancelled") return "error";
  if (event.type === "auth_status" && (event.status === "invalid" || event.status === "failed")) return "warning";
  if (event.type === "auth_status" && (event.status === "valid" || event.status === "refreshed")) return "success";
  if (event.type === "completed" || event.type === "tool_completed" || event.type === "phase_completed") return "success";
  if (event.type === "finding_found" || event.status === "paused") return "warning";
  return "running";
}

function PhaseProgressCard({ track }: { track: { phase: string; state: string } }) {
  const stateLabel = track.state === "completed" || track.state === "done"
    ? "done"
    : track.state === "failed" || track.state === "error"
      ? "failed"
      : track.state === "running"
        ? "running"
        : "queued";
  return (
    <article className={`phase-progress-card ${stateLabel}`}>
      <span className="phase-progress-icon">{statusIcon(track.state)}</span>
      <div>
        <strong>{phaseLabels[track.phase] ?? track.phase.replace("_", " ")}</strong>
        <small>{stateLabel}</small>
      </div>
    </article>
  );
}

function statusIcon(state: string) {
  if (state === "completed" || state === "done") return <CheckCircle2 size={14} />;
  if (state === "running") return <Loader2 className="spin-icon" size={14} />;
  if (state === "error" || state === "failed") return <XCircle size={14} />;
  return <Clock size={14} />;
}

function formatTimestamp(value: string) {
  return new Date(value).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

function formatDuration(durationMS: number) {
  if (durationMS >= 1000) {
    return `${(durationMS / 1000).toFixed(1)}s`;
  }
  return `${durationMS}ms`;
}
