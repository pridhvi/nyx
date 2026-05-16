import { type FormEvent, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, PackagePlus, RefreshCw, Upload, XCircle } from "lucide-react";
import { createPlugin, deletePlugin, listPlugins, listTools, updatePlugin, uploadPluginBinary, type ToolRecord } from "../api/client";

export function Tools() {
  const queryClient = useQueryClient();
  const toolsQuery = useQuery({ queryKey: ["tools"], queryFn: () => listTools() });
  const pluginsQuery = useQuery({ queryKey: ["plugins"], queryFn: listPlugins });
  const [pluginName, setPluginName] = useState("");
  const [pluginBinary, setPluginBinary] = useState("");
  const [pluginPhase, setPluginPhase] = useState("vuln_scan");
  const [pluginDescription, setPluginDescription] = useState("");
  const [pluginHomepageURL, setPluginHomepageURL] = useState("");
  const [toolFilter, setToolFilter] = useState("all");
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
  const readyCount = tools.filter((tool) => tool.installed).length;

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
          <h2>Registered Tools</h2>
          <div className="tab-row">
            <button className={toolFilter === "all" ? "active" : ""} type="button" onClick={() => setToolFilter("all")}>All {tools.length}</button>
            <button className={toolFilter === "ready" ? "active" : ""} type="button" onClick={() => setToolFilter("ready")}>Ready {readyCount}</button>
            <button className={toolFilter === "missing" ? "active" : ""} type="button" onClick={() => setToolFilter("missing")}>Missing {tools.length - readyCount}</button>
          </div>
        </div>
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
      </section>
      <section className="panel">
        <h2>Global Plugins</h2>
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
          <button className="primary" disabled={!pluginName.trim() || !pluginBinary.trim() || createMutation.isPending}><PackagePlus size={16} />Register</button>
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
                  <td><code>{plugin.binary}</code></td>
                  <td>{plugin.enabled ? "enabled" : "disabled"}</td>
                  <td className="action-row"><button className="secondary" onClick={() => updatePlugin(plugin.id, { enabled: !plugin.enabled }).then(() => {
                    queryClient.invalidateQueries({ queryKey: ["plugins"] });
                    queryClient.invalidateQueries({ queryKey: ["tools"] });
                  })}>{plugin.enabled ? "Disable" : "Enable"}</button><button className="secondary danger" onClick={() => window.confirm("Delete this global plugin?") && deletePlugin(plugin.id).then(() => {
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

function kindLabel(tool: ToolRecord) {
  if (tool.kind === "builtin_http") {
    return "built in";
  }
  if (tool.kind === "subprocess") {
    return "subprocess";
  }
  return "plugin";
}
