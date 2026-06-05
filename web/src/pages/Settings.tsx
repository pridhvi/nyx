import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Check, Clipboard } from "lucide-react";
import { effectiveConfig, listPlugins, listTools } from "../api/client";

export function Settings() {
  const configQuery = useQuery({ queryKey: ["effective-config"], queryFn: effectiveConfig });
  const toolsQuery = useQuery({ queryKey: ["tools"], queryFn: () => listTools() });
  const pluginsQuery = useQuery({ queryKey: ["plugins"], queryFn: listPlugins });
  const [uiTheme, setUITheme] = useState(() => localStorage.getItem("nyx-theme") ?? document.documentElement.dataset.theme ?? "dark");
  const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">("idle");
  const cfg = configQuery.data;
  const tools = toolsQuery.data ?? [];
  const installed = tools.filter((tool) => tool.installed).length;
  const missing = tools.length - installed;

  useEffect(() => {
    function syncTheme(event?: Event) {
      const detail = event instanceof CustomEvent && typeof event.detail === "string" ? event.detail : "";
      setUITheme(detail || localStorage.getItem("nyx-theme") || document.documentElement.dataset.theme || "dark");
    }
    window.addEventListener("nyx-theme-change", syncTheme);
    window.addEventListener("storage", syncTheme);
    syncTheme();
    return () => {
      window.removeEventListener("nyx-theme-change", syncTheme);
      window.removeEventListener("storage", syncTheme);
    };
  }, []);

  async function copyConfig() {
    if (!cfg || !navigator.clipboard) {
      setCopyState("failed");
      return;
    }
    try {
      await navigator.clipboard.writeText(sanitizedConfigForCopy(cfg));
      setCopyState("copied");
      window.setTimeout(() => setCopyState("idle"), 1800);
    } catch {
      setCopyState("failed");
    }
  }

  return (
    <section className="page">
      <header className="page-header">
        <div>
          <h1>System Health</h1>
          <p>Read-only effective configuration and environment health.</p>
        </div>
      </header>
      <div className="settings-grid">
        <section className="panel effective-config-panel">
          <div className="panel-heading-row">
            <div>
              <h2>Effective Config</h2>
              <p>Sanitized runtime configuration for debugging and support handoff.</p>
            </div>
            <button className="secondary" type="button" onClick={() => void copyConfig()} disabled={!cfg}>
              {copyState === "copied" ? <Check size={16} /> : <Clipboard size={16} />}
              {copyState === "copied" ? "Copied Config" : copyState === "failed" ? "Copy Failed" : "Copy Sanitized Config"}
            </button>
          </div>
          <details className="raw-config">
            <summary>Raw effective config</summary>
            <pre>{cfg ? sanitizedConfigForCopy(cfg) : "{}"}</pre>
          </details>
        </section>
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
          <dl><dt>Current UI Theme</dt><dd>{uiTheme}</dd><dt>Assets</dt><dd>embedded in Go binary when built</dd><dt>Platform</dt><dd>{cfg?.runtime.goos}/{cfg?.runtime.goarch}</dd></dl>
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

export function sanitizedConfigForCopy(config: unknown) {
  return JSON.stringify(redactConfigValue(config), null, 2);
}

function redactConfigValue(value: unknown, key = ""): unknown {
  if (isSensitiveConfigKey(key) && typeof value !== "boolean") {
    return "[REDACTED]";
  }
  if (Array.isArray(value)) {
    return value.map((item) => redactConfigValue(item, key));
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([entryKey, entryValue]) => [entryKey, redactConfigValue(entryValue, entryKey)]));
  }
  return value;
}

function isSensitiveConfigKey(key: string) {
  return /(^|[_-])(api[_-]?key|authorization|bearer|cookie|password|secret|token)([_-]|$)/i.test(key);
}
