import { useQuery } from "@tanstack/react-query";
import { effectiveConfig, listPlugins, listTools } from "../api/client";

export function Settings() {
  const configQuery = useQuery({ queryKey: ["effective-config"], queryFn: effectiveConfig });
  const toolsQuery = useQuery({ queryKey: ["tools"], queryFn: () => listTools() });
  const pluginsQuery = useQuery({ queryKey: ["plugins"], queryFn: listPlugins });
  const cfg = configQuery.data;
  const tools = toolsQuery.data ?? [];
  const installed = tools.filter((tool) => tool.installed).length;
  const missing = tools.length - installed;
  return (
    <section className="page">
      <header className="page-header">
        <div>
          <h1>System Health</h1>
          <p>Read-only effective configuration and environment health.</p>
        </div>
      </header>
      <div className="settings-grid">
        <section className="panel">
          <h2>Storage</h2>
          <dl>
            <dt>Session Storage</dt><dd>{cfg?.database.session_dir_status ?? cfg?.database.session_dir}</dd>
            <dt>Scan Profiles</dt><dd>{cfg?.paths?.scan_profiles}</dd>
            <dt>Plugin Registry</dt><dd>{cfg?.paths?.plugin_registry}</dd>
            <dt>Disk Readiness</dt><dd>{cfg?.database.session_dir_status ?? "unknown"}</dd>
          </dl>
        </section>
        <section className="panel">
          <h2>Server</h2>
          <dl>
            <dt>Host</dt><dd>{cfg?.server.host}</dd>
            <dt>Port</dt><dd>{cfg?.server.port}</dd>
            <dt>Auth</dt><dd>{cfg?.server.auth_enabled ? "enabled" : "disabled"}</dd>
            <dt>API Base</dt><dd>same-origin /api</dd>
            <dt>WebSocket</dt><dd>{cfg?.paths?.session_events_ws}</dd>
          </dl>
        </section>
        <section className="panel">
          <h2>LLM</h2>
          <dl><dt>Enabled</dt><dd>{cfg?.llm.enabled ? "yes" : "no"}</dd><dt>Endpoint</dt><dd>{cfg?.llm.base_url || "not configured"}</dd><dt>Model</dt><dd>{cfg?.llm.model || "not configured"}</dd><dt>API Key</dt><dd>{cfg?.llm.api_key_set ? "set" : "not set"}</dd></dl>
        </section>
        <section className="panel">
          <h2>Tools</h2>
          <dl><dt>Installed</dt><dd>{installed}</dd><dt>Missing</dt><dd>{missing}</dd><dt>Configured Paths</dt><dd>{Object.keys(cfg?.tools ?? {}).length}</dd></dl>
          <details className="raw-config">
            <summary>Raw tool configuration</summary>
            <pre>{JSON.stringify(cfg?.tools ?? {}, null, 2)}</pre>
          </details>
        </section>
        <section className="panel">
          <h2>Plugins</h2>
          <dl><dt>Global Plugins</dt><dd>{pluginsQuery.data?.length ?? 0}</dd><dt>Managed Bin</dt><dd>{cfg?.paths?.plugin_bin_dir}</dd></dl>
        </section>
        <section className="panel">
          <h2>Frontend</h2>
          <dl><dt>Theme</dt><dd>{localStorage.getItem("nyx-theme") ?? "dark"}</dd><dt>Assets</dt><dd>embedded in Go binary when built</dd><dt>Platform</dt><dd>{cfg?.runtime.goos}/{cfg?.runtime.goarch}</dd></dl>
        </section>
        <section className="panel">
          <h2>CVE</h2>
          <details className="raw-config">
            <summary>Raw CVE configuration</summary>
            <pre>{JSON.stringify(cfg?.cve ?? {}, null, 2)}</pre>
          </details>
        </section>
      </div>
    </section>
  );
}
