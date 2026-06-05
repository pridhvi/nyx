import { type FormEvent, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, CircleDashed, List, PackagePlus, RefreshCw, SquareStack, Upload, XCircle } from "lucide-react";
import { createPlugin, deletePlugin, effectiveConfig, listPlugins, listTools, updatePlugin, uploadPluginBinary, type ToolRecord } from "../api/client";
import { useSessionContext } from "../session";

export function Tools() {
  const queryClient = useQueryClient();
  const { selectedSessionID } = useSessionContext();
  const toolsQuery = useQuery({ queryKey: ["tools", selectedSessionID], queryFn: () => listTools(selectedSessionID || undefined) });
  const pluginsQuery = useQuery({ queryKey: ["plugins"], queryFn: listPlugins });
  const configQuery = useQuery({ queryKey: ["effective-config"], queryFn: effectiveConfig });
  const [pluginName, setPluginName] = useState("");
  const [pluginBinary, setPluginBinary] = useState("");
  const [pluginPhase, setPluginPhase] = useState("vuln_scan");
  const [pluginDescription, setPluginDescription] = useState("");
  const [pluginHomepageURL, setPluginHomepageURL] = useState("");
  const [toolFilter, setToolFilter] = useState("all");
  const [viewMode, setViewMode] = useState<"table" | "cards">("table");
  const [selectedToolID, setSelectedToolID] = useState("");
  const createMutation = useMutation({
    mutationFn: () => createPlugin({ name: pluginName, binary: pluginBinary, phase: pluginPhase, description: pluginDescription, homepage_url: pluginHomepageURL, enabled: true }),
    onSuccess: () => {
      setPluginName("");
      setPluginBinary("");
      setPluginDescription("");
      setPluginHomepageURL("");
      queryClient.invalidateQueries({ queryKey: ["plugins"] });
      queryClient.invalidateQueries({ queryKey: ["tools"] });
    },
  });
  const uploadMutation = useMutation({
    mutationFn: uploadPluginBinary,
    onSuccess: (result) => setPluginBinary(result.binary),
  });

  function submitPlugin(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (pluginName.trim() && pluginBinary.trim()) {
      createMutation.mutate();
    }
  }
  const tools = toolsQuery.data ?? [];
  const visibleTools = tools.filter((tool) => toolFilter === "all" || (toolFilter === "ready" ? tool.installed : !tool.installed));
  const selectedTool = tools.find((tool) => tool.id === selectedToolID) ?? visibleTools[0];
  const readyCount = tools.filter((tool) => tool.installed).length;
  const toolGroups = useMemo(() => [
    { label: "Ready", value: readyCount, detail: "installed or built in" },
    { label: "Missing", value: tools.length - readyCount, detail: "optional subprocess tools" },
    { label: "Built-in", value: tools.filter((tool) => tool.kind === "builtin_http").length, detail: "no binary needed" },
    { label: "Subprocess", value: tools.filter((tool) => tool.kind === "subprocess").length, detail: "external adapters" },
    { label: "Ran in Session", value: tools.filter((tool) => tool.last_run).length, detail: "selected-session evidence" },
  ], [readyCount, tools]);
  const authEnabled = Boolean(configQuery.data?.server.auth_enabled);

  return (
    <section className="page wide-page">
      <header className="page-header">
        <div>
          <h1>Tools</h1>
          <p>Inventory, install status, last run state, and global plugin tools.</p>
        </div>
        <button className="primary" onClick={() => toolsQuery.refetch()}><RefreshCw size={16} />Refresh</button>
      </header>
      <section className="panel">
        <div className="graph-toolbar">
          <div>
            <h2>Registered Tools</h2>
            <p className="profile-description">Grouped readiness comes first; raw binary, version, dependency, and last-run details are available below for troubleshooting.</p>
          </div>
          <div className="tab-row">
            <button className={toolFilter === "all" ? "active" : ""} type="button" onClick={() => setToolFilter("all")}>All {tools.length}</button>
            <button className={toolFilter === "ready" ? "active" : ""} type="button" onClick={() => setToolFilter("ready")}>Ready {readyCount}</button>
            <button className={toolFilter === "missing" ? "active" : ""} type="button" onClick={() => setToolFilter("missing")}>Missing {tools.length - readyCount}</button>
          </div>
        </div>
        <div className="tool-summary-grid">
          {toolGroups.map((group) => (
            <article key={group.label}>
              <span>{group.label}</span>
              <strong>{group.value}</strong>
              <small>{group.detail}</small>
            </article>
          ))}
        </div>
        <div className="tool-view-toolbar">
          <strong>{viewMode === "table" ? "Compact Table" : "Tool Cards"}</strong>
          <div className="tab-row" aria-label="Tool inventory view mode">
            <button className={viewMode === "table" ? "active" : ""} type="button" onClick={() => setViewMode("table")}><List size={14} />Table</button>
            <button className={viewMode === "cards" ? "active" : ""} type="button" onClick={() => setViewMode("cards")}><SquareStack size={14} />Cards</button>
          </div>
        </div>
        {viewMode === "table" ? (
          <div className="tool-inventory-workspace">
            <div className="table-wrap compact-tool-table">
              <table>
                <thead><tr><th>Status</th><th>Tool</th><th>Phase</th><th>Version</th><th>Path</th><th>Last Run</th></tr></thead>
                <tbody>
                  {visibleTools.map((tool) => (
                    <tr key={tool.id} className={selectedTool?.id === tool.id ? "selected-row" : ""}>
                      <td><ToolStatusBadge tool={tool} /></td>
                      <td><button className="table-link-button" onClick={() => setSelectedToolID(tool.id)}><strong>{tool.id}</strong><small>{tool.name}</small></button></td>
                      <td>{phaseLabel(tool.phase)}</td>
                      <td>{tool.version || "-"}</td>
                      <td><code>{tool.binary_path || (tool.kind === "builtin_http" ? "built in" : "-")}</code></td>
                      <td>{tool.last_run ? <span className={`status ${tool.last_run.exit_code === 0 ? "completed" : "failed"}`}>{tool.last_run.exit_code === 0 ? "ok" : `exit ${tool.last_run.exit_code}`}</span> : "-"}</td>
                    </tr>
                  ))}
                  {visibleTools.length === 0 ? <tr><td colSpan={6}>No tools match this filter.</td></tr> : null}
                </tbody>
              </table>
            </div>
            <ToolDetailPanel tool={selectedTool} />
          </div>
        ) : (
          <div className="tool-card-list">
            {visibleTools.map((tool) => (
              <ToolCard key={tool.id} tool={tool} onSelect={() => setSelectedToolID(tool.id)} selected={selectedTool?.id === tool.id} />
            ))}
            {visibleTools.length === 0 ? <div className="empty-state">No tools match this filter.</div> : null}
          </div>
        )}
        <details className="raw-config raw-inventory">
          <summary>Raw inventory table</summary>
          <div className="table-wrap">
            <table>
              <thead><tr><th>Status</th><th>Tool</th><th>Phase</th><th>Kind</th><th>Binary</th><th>Version</th><th>Last Run</th></tr></thead>
              <tbody>
                {visibleTools.map((tool) => (
                  <tr key={tool.id}>
                    <td><span className={`status ${tool.installed ? "completed" : "failed"} icon-status`}>{tool.installed ? <CheckCircle2 size={14} /> : <XCircle size={14} />}{tool.installed ? "ready" : "missing"}</span></td>
                    <td><strong>{tool.id}</strong><small>{tool.name}</small><small>{tool.depends_on.length ? `depends: ${tool.depends_on.join(", ")}` : tool.install_hint}</small></td>
                    <td>{tool.phase}</td>
                    <td>{kindLabel(tool)}</td>
                    <td><code>{tool.binary_path || "-"}</code></td>
                    <td>{tool.version || "-"}</td>
                    <td>{tool.last_run ? <span className={`status ${tool.last_run.exit_code === 0 ? "completed" : "failed"}`}>{tool.last_run.exit_code === 0 ? "ok" : `exit ${tool.last_run.exit_code}`}</span> : "-"}</td>
                  </tr>
                ))}
                {visibleTools.length === 0 ? <tr><td colSpan={7}>No tools match this filter.</td></tr> : null}
              </tbody>
            </table>
          </div>
        </details>
      </section>
      <section className="panel global-plugins-panel">
        <h2>Global Plugins</h2>
        <p className="profile-description">
          Global plugin registration is host-privileged and requires Nyx API-key authentication to be configured. {authEnabled ? "Your browser session can authorize these actions after API-key login." : "Set NYX_API_KEY or server.api_key, then log in from the browser to manage global plugins."}
        </p>
        <form className="scan-form plugin-form" onSubmit={submitPlugin}>
          <label>Name <span className="required-mark">Required</span><input value={pluginName} onChange={(event) => setPluginName(event.target.value)} placeholder="my-scanner" required /></label>
          <label>Phase
            <select value={pluginPhase} onChange={(event) => setPluginPhase(event.target.value)}>
              <option value="recon">Recon</option><option value="fingerprint">Fingerprint</option><option value="enumerate">Enumeration</option><option value="vuln_scan">Vulnerability</option>
            </select>
          </label>
          <label>Binary<input value={pluginBinary} onChange={(event) => setPluginBinary(event.target.value)} placeholder="/path/to/plugin" /></label>
          <label className="secondary file-button"><Upload size={16} />Upload Binary<input type="file" onChange={(event) => event.target.files?.[0] && uploadMutation.mutate(event.target.files[0])} /></label>
          <label>Description<input value={pluginDescription} onChange={(event) => setPluginDescription(event.target.value)} placeholder="What this plugin checks" /></label>
          <label>Homepage URL<input value={pluginHomepageURL} onChange={(event) => setPluginHomepageURL(event.target.value)} placeholder="https://github.com/org/tool" /></label>
          <div className="form-actions">
            <button className="primary compact-button" disabled={!authEnabled || !pluginName.trim() || !pluginBinary.trim() || createMutation.isPending}><PackagePlus size={16} />Register</button>
          </div>
        </form>
        {createMutation.error ? <p className="error-text">{createMutation.error.message}</p> : null}
        {uploadMutation.error ? <p className="error-text">{uploadMutation.error.message}</p> : null}
        {uploadMutation.isPending ? <p className="profile-description">Installing uploaded binary into managed plugin storage.</p> : null}
        <div className="table-wrap">
          <table>
            <thead><tr><th>Name</th><th>Phase</th><th>Description</th><th>Binary</th><th>Status</th><th>Action</th></tr></thead>
            <tbody>
              {(pluginsQuery.data ?? []).map((plugin) => (
                <tr key={plugin.id}>
                  <td><strong>{plugin.name}</strong><small>{plugin.homepage_url}</small></td>
                  <td>{plugin.phase}</td>
                  <td>{plugin.description || "-"}</td>
                  <td><code>{plugin.binary}</code>{plugin.sha256 ? <small>SHA-256 {plugin.sha256.slice(0, 16)}...</small> : <small>SHA-256 not recorded</small>}</td>
                  <td>{plugin.enabled ? "enabled" : "disabled"}</td>
                  <td className="action-row"><button className="secondary" disabled={!authEnabled} onClick={() => updatePlugin(plugin.id, { enabled: !plugin.enabled }).then(() => {
                    queryClient.invalidateQueries({ queryKey: ["plugins"] });
                    queryClient.invalidateQueries({ queryKey: ["tools"] });
                  })}>{plugin.enabled ? "Disable" : "Enable"}</button><button className="secondary danger" disabled={!authEnabled} onClick={() => window.confirm("Delete this global plugin?") && deletePlugin(plugin.id).then(() => {
                    queryClient.invalidateQueries({ queryKey: ["plugins"] });
                    queryClient.invalidateQueries({ queryKey: ["tools"] });
                  })}>Delete</button></td>
                </tr>
              ))}
              {(pluginsQuery.data ?? []).length === 0 ? <tr><td colSpan={6}>No global plugins registered.</td></tr> : null}
            </tbody>
          </table>
        </div>
      </section>
    </section>
  );
}

function ToolStatusBadge({ tool }: { tool: ToolRecord }) {
  const state = toolInstallState(tool);
  if (state === "ready") {
    return <span className="status completed icon-status"><CheckCircle2 size={14} />ready</span>;
  }
  if (state === "optional") {
    return <span className="status paused icon-status"><CircleDashed size={14} />optional</span>;
  }
  return <span className="status failed icon-status"><XCircle size={14} />missing</span>;
}

function ToolDetailPanel({ tool }: { tool: ToolRecord | undefined }) {
  if (!tool) {
    return <aside className="tool-detail-panel empty-state">Select a tool to inspect details.</aside>;
  }
  return (
    <aside className={`tool-detail-panel ${tool.installed ? "ready" : "missing"}`} aria-label="Tool Details">
      <div>
        <ToolStatusBadge tool={tool} />
        <h2>Tool Details</h2>
      </div>
      <h3>{tool.id}</h3>
      <p>{tool.description || tool.name}</p>
      <dl>
        <dt>Name</dt><dd>{tool.name}</dd>
        <dt>Phase</dt><dd>{phaseLabel(tool.phase)}</dd>
        <dt>Kind</dt><dd>{kindLabel(tool)}</dd>
        <dt>Version</dt><dd>{tool.version || "-"}</dd>
        <dt>Path</dt><dd><code>{tool.binary_path || (tool.kind === "builtin_http" ? "built in" : "-")}</code></dd>
        <dt>Dependencies</dt><dd>{tool.depends_on.length ? tool.depends_on.join(", ") : "none"}</dd>
      </dl>
      {tool.install_hint ? <p className="tool-install-hint">{tool.install_hint}</p> : null}
      {tool.homepage_url ? <a href={tool.homepage_url} target="_blank" rel="noreferrer">Open homepage</a> : null}
    </aside>
  );
}

function ToolCard({ tool, selected, onSelect }: { tool: ToolRecord; selected: boolean; onSelect: () => void }) {
  return (
    <article className={`tool-inventory-card ${tool.installed ? "ready" : "missing"} ${selected ? "selected" : ""}`}>
      <div>
        <ToolStatusBadge tool={tool} />
        <strong>{tool.id}</strong>
        <small>{tool.name}</small>
      </div>
      <dl>
        <dt>Phase</dt><dd>{phaseLabel(tool.phase)}</dd>
        <dt>Kind</dt><dd>{kindLabel(tool)}</dd>
        <dt>Binary</dt><dd><code>{tool.binary_path || "-"}</code></dd>
        <dt>Version</dt><dd>{tool.version || "-"}</dd>
      </dl>
      {tool.depends_on.length ? <p>Depends on {tool.depends_on.join(", ")}</p> : tool.install_hint ? <p>{tool.install_hint}</p> : null}
      <button className="secondary" type="button" onClick={onSelect}>Show Details</button>
    </article>
  );
}

export function toolInstallState(tool: ToolRecord) {
  if (tool.installed) {
    return "ready";
  }
  return tool.default_enabled ? "missing" : "optional";
}

export function compactToolRows(tools: ToolRecord[]) {
  return tools.map((tool) => ({
    id: tool.id,
    name: tool.name,
    phase: phaseLabel(tool.phase),
    version: tool.version || "-",
    path: tool.binary_path || (tool.kind === "builtin_http" ? "built in" : "-"),
    status: toolInstallState(tool),
  }));
}

function kindLabel(tool: ToolRecord) {
  if (tool.kind === "builtin_http") {
    return "built in";
  }
  if (tool.kind === "subprocess") {
    return "subprocess";
  }
  return "plugin";
}

function phaseLabel(phase: string) {
  const labels: Record<string, string> = {
    recon: "Recon",
    fingerprint: "Fingerprint",
    enumerate: "Enumeration",
    vuln_scan: "Vulnerability",
    audit: "Static audit",
  };
  return labels[phase] ?? phase;
}
