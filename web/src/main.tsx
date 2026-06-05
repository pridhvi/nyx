import React, { Suspense, lazy, useEffect, useMemo, useRef, useState } from "react";
import ReactDOM from "react-dom/client";
import { QueryClient, QueryClientProvider, useQuery } from "@tanstack/react-query";
import { BrowserRouter, Link, NavLink, Route, Routes, useLocation } from "react-router-dom";
import { Bot, Boxes, FileCode2, FileText, Menu, Moon, MoreHorizontal, Network, PackageSearch, Radar, RefreshCw, Search, Settings as SettingsIcon, Shield, Sparkles, Sun, TerminalSquare, Wrench, X } from "lucide-react";
import { authExpiredEvent, listCVEs, listFindings, listSourceFindings, login as loginAPI, type CVEMatch, type Finding, type SessionRecord, type SourceFinding } from "./api/client";
import { scopedSessionPath } from "./sessionRoutes";
import { SessionProvider, useSessionContext } from "./session";
import "./styles.css";

const queryClient = new QueryClient();
const Dashboard = lazy(() => import("./pages/Dashboard").then((module) => ({ default: module.Dashboard })));
const ScanBuilder = lazy(() => import("./pages/ScanBuilder").then((module) => ({ default: module.ScanBuilder })));
const Monitor = lazy(() => import("./pages/Monitor").then((module) => ({ default: module.Monitor })));
const PowerFeatures = lazy(() => import("./pages/PowerFeatures").then((module) => ({ default: module.PowerFeatures })));
const Findings = lazy(() => import("./pages/Findings").then((module) => ({ default: module.Findings })));
const Source = lazy(() => import("./pages/Source").then((module) => ({ default: module.Source })));
const Tools = lazy(() => import("./pages/Tools").then((module) => ({ default: module.Tools })));
const ToolRuns = lazy(() => import("./pages/ToolRuns").then((module) => ({ default: module.ToolRuns })));
const AttackGraph = lazy(() => import("./pages/AttackGraph").then((module) => ({ default: module.AttackGraph })));
const CVEs = lazy(() => import("./pages/CVEs").then((module) => ({ default: module.CVEs })));
const LLMChat = lazy(() => import("./pages/LLMChat").then((module) => ({ default: module.LLMChat })));
const Reports = lazy(() => import("./pages/Reports").then((module) => ({ default: module.Reports })));
const Settings = lazy(() => import("./pages/Settings").then((module) => ({ default: module.Settings })));

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthGate>
        <BrowserRouter>
          <SessionProvider>
            <OperatorShell />
          </SessionProvider>
        </BrowserRouter>
      </AuthGate>
    </QueryClientProvider>
  );
}

function AuthGate({ children }: { children: React.ReactNode }) {
  const [state, setState] = useState<"checking" | "ready" | "required">("checking");
  const [apiKey, setAPIKey] = useState("");
  const [error, setError] = useState("");
  const stateRef = useRef(state);

  useEffect(() => {
    stateRef.current = state;
  }, [state]);

  useEffect(() => {
    function handleAuthExpired() {
      if (stateRef.current !== "ready") {
        return;
      }
      queryClient.clear();
      setAPIKey("");
      setError("Session expired — please log in again");
      setState("required");
    }
    window.addEventListener(authExpiredEvent, handleAuthExpired);
    return () => window.removeEventListener(authExpiredEvent, handleAuthExpired);
  }, []);

  useEffect(() => {
    let active = true;
    fetch("/api/health", { credentials: "same-origin" })
      .then((response) => {
        if (!active) {
          return;
        }
        if (response.status === 401) {
          setState("required");
          return;
        }
        if (response.ok) {
          setState("ready");
          return;
        }
        setError(response.statusText);
        setState("required");
      })
      .catch((err) => {
        if (!active) {
          return;
        }
        setError(err instanceof Error ? err.message : "Unable to reach API");
        setState("required");
      });
    return () => {
      active = false;
    };
  }, []);

  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    try {
      await loginAPI(apiKey);
      queryClient.clear();
      setAPIKey("");
      setState("ready");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed");
    }
  }

  if (state === "checking") {
    return <section className="auth-screen"><div className="auth-panel">Checking API access</div></section>;
  }
  if (state === "required") {
    return (
      <section className="auth-screen">
        <form className="auth-panel" onSubmit={submit}>
          <div className="brand auth-brand"><img src="/nyx-logo.png" alt="" />Nyx</div>
          <label>API Key
            <input
              autoFocus
              type="password"
              value={apiKey}
              onChange={(event) => setAPIKey(event.target.value)}
              placeholder="Enter API key"
              autoComplete="current-password"
            />
          </label>
          {error ? <p className="form-error">{error}</p> : null}
          <button className="primary" type="submit" disabled={!apiKey.trim()}>Unlock Console</button>
        </form>
      </section>
    );
  }
  return children;
}

function OperatorShell() {
  const { sessions, sessionsLoading, sessionsError, selectedSessionID, selected, setSelectedSessionID, refreshSessions } = useSessionContext();
  const [theme, setTheme] = useState(() => localStorage.getItem("nyx-theme") ?? "dark");
  const [navOpen, setNavOpen] = useState(false);
  const [actionsOpen, setActionsOpen] = useState(false);
  const [searchOpen, setSearchOpen] = useState(false);
  const [toasts, setToasts] = useState<ToastMessage[]>([]);
  const location = useLocation();
  const scoped = (suffix: string) => scopedSessionPath(selectedSessionID, suffix);
  const selectedSession = selected?.session;
  const commandCenterPath = selectedSessionID ? scoped("") : "/";

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem("nyx-theme", theme);
    window.dispatchEvent(new CustomEvent("nyx-theme-change", { detail: theme }));
  }, [theme]);

  function toggleTheme() {
    const nextTheme = theme === "dark" ? "light" : "dark";
    localStorage.setItem("nyx-theme", nextTheme);
    setTheme(nextTheme);
  }

  useEffect(() => {
    setNavOpen(false);
    setActionsOpen(false);
  }, [location.pathname]);

  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setSearchOpen(true);
        return;
      }
      if (!isTypingTarget(event.target)) {
        if (event.key === "/") {
          event.preventDefault();
          setSearchOpen(true);
          return;
        }
        if (event.key.toLowerCase() === "n") {
          window.history.pushState(null, "", "/scan");
          window.dispatchEvent(new PopStateEvent("popstate"));
          return;
        }
        if (event.key.toLowerCase() === "t" && selectedSessionID) {
          window.history.pushState(null, "", scopedSessionPath(selectedSessionID, "/findings"));
          window.dispatchEvent(new PopStateEvent("popstate"));
          return;
        }
      }
      if (event.key !== "Escape") {
        return;
      }
      setNavOpen(false);
      setActionsOpen(false);
      setSearchOpen(false);
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [selectedSessionID]);

  useEffect(() => {
    function onToast(event: Event) {
      const detail = event instanceof CustomEvent ? event.detail as Partial<ToastMessage> : {};
      const toast: ToastMessage = {
        id: crypto.randomUUID(),
        tone: detail.tone ?? "info",
        title: detail.title ?? "Nyx update",
        message: detail.message ?? "",
      };
      setToasts((current) => [toast, ...current].slice(0, 4));
      window.setTimeout(() => setToasts((current) => current.filter((item) => item.id !== toast.id)), 5200);
    }
    window.addEventListener("nyx-toast", onToast);
    return () => window.removeEventListener("nyx-toast", onToast);
  }, []);

  const navGroups = [
    { label: "Command", items: [{ to: scoped(""), label: "Command Center", icon: Shield, active: location.pathname === scoped("") }] },
    { label: "Build", items: [{ to: "/scan", label: "Scan Builder", icon: TerminalSquare }, { to: "/monitor", label: "Monitor", icon: Radar }, { to: scoped("/power"), label: "Power Features", icon: Sparkles }] },
    { label: "Triage", items: [{ to: scoped("/findings"), label: "Findings", icon: Search }, { to: scoped("/source"), label: "Source", icon: FileCode2 }] },
    { label: "Evidence", items: [{ to: scoped("/runs"), label: "Tool Runs", icon: PackageSearch }, { to: scoped("/tools"), label: "Tools", icon: Wrench }] },
    { label: "Attack Paths", items: [{ to: scoped("/graph"), label: "Attack Paths", icon: Network }, { to: scoped("/cves"), label: "CVEs", icon: Boxes }] },
    { label: "Analyst", items: [{ to: scoped("/llm"), label: "LLM Analyst", icon: Bot }] },
    { label: "Export", items: [{ to: scoped("/report"), label: "Reports", icon: FileText }] },
    { label: "System", items: [{ to: "/settings", label: "Settings", icon: SettingsIcon }] },
  ];

  return (
    <div className="shell">
      <aside className={`sidebar ${navOpen ? "open" : ""}`}>
        <Link className="brand" to={commandCenterPath} aria-label="Go to Command Center"><img src="/nyx-logo.png" alt="" /><span>Nyx</span></Link>
        <nav aria-label="Primary">
          {navGroups.map((group) => (
            <div className="nav-section" key={group.label}>
              <span className="nav-group-label">{group.label}</span>
              {group.items.map((item) => {
                const Icon = item.icon;
                return (
                  <NavLink key={item.to} to={item.to} end={item.to === "/" || item.to === scoped("")} className={({ isActive }) => ("active" in item && item.active) || isActive ? "active" : ""}>
                    <Icon size={17} /><span>{item.label}</span>
                  </NavLink>
                );
              })}
            </div>
          ))}
        </nav>
      </aside>
      {navOpen ? <button className="nav-scrim" aria-label="Close navigation" onClick={() => setNavOpen(false)} /> : null}
      <main>
        <header className="topbar">
          <button className="icon-button mobile-menu" aria-label="Open navigation" onClick={() => setNavOpen(true)}><Menu size={18} /></button>
          <label className="session-select">Session
            <select value={selectedSessionID} onChange={(event) => setSelectedSessionID(event.target.value)}>
              <option value="">No session</option>
              {sessions.map((record) => <option key={record.session.id} value={record.session.id}>{record.session.name || record.session.target_input} · {record.session.status}</option>)}
            </select>
          </label>
          <div className="session-strip" aria-label="Selected session summary">
            <span className={`status ${selectedSession?.status ?? "pending"}`}>{selectedSession?.status ?? "no session"}</span>
            {selectedSession ? (
              <>
                <span>{selectedSession.workload_mode ?? "dynamic"}</span>
                <span>{selectedSession.target_count} target{selectedSession.target_count === 1 ? "" : "s"}</span>
                <span>{selectedSession.finding_count} findings</span>
              </>
            ) : null}
          </div>
          <button className="icon-button mobile-actions-button" aria-label={actionsOpen ? "Close page actions" : "Open page actions"} aria-expanded={actionsOpen} aria-controls="topbar-actions" onClick={() => setActionsOpen((open) => !open)}><MoreHorizontal size={18} /></button>
          <div id="topbar-actions" className={`topbar-actions ${actionsOpen ? "open" : ""}`}>
            <button className="secondary topbar-search" type="button" onClick={() => setSearchOpen(true)} title="Search current session"><Search size={16} />Search</button>
            <Link className="secondary link-button topbar-action" to={selectedSessionID ? scoped("/findings") : "/scan"}>{selectedSessionID ? "Triage" : "New Scan"}</Link>
            <button
              className={`theme-toggle ${theme === "light" ? "light" : "dark"}`}
              type="button"
              role="switch"
              aria-checked={theme === "light"}
              aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} mode`}
              onClick={toggleTheme}
            >
              <span className="theme-toggle-icon moon"><Moon size={16} /></span>
              <span className="theme-toggle-track" aria-hidden="true">
                <span className="theme-toggle-thumb" />
              </span>
              <span className="theme-toggle-icon sun"><Sun size={16} /></span>
            </button>
            <button className="secondary" onClick={refreshSessions} title="Refresh session list" aria-label="Refresh session list"><RefreshCw size={16} />Refresh</button>
          </div>
          {navOpen ? <button className="icon-button close-mobile-nav" aria-label="Close navigation" onClick={() => setNavOpen(false)}><X size={18} /></button> : null}
        </header>
        <div className="shortcut-strip" aria-label="Keyboard shortcuts">
          <span><kbd>/</kbd> Search</span>
          <span><kbd>N</kbd> New scan</span>
          <span><kbd>T</kbd> Triage</span>
        </div>
        {sessionsError ? (
          <section className="app-alert error">
            <div><strong>Session API unavailable</strong><span>{sessionsError}</span></div>
            <button className="secondary" type="button" onClick={refreshSessions}><RefreshCw size={16} />Retry</button>
          </section>
        ) : null}
        {sessionsLoading ? <RouteSkeleton label="Loading sessions" /> : null}
        <RouteErrorBoundary key={location.pathname}>
          <Suspense fallback={<RouteSkeleton label="Loading workspace" />}>
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/scan" element={<ScanBuilder />} />
              <Route path="/monitor" element={<Monitor />} />
              <Route path="/power" element={<PowerFeatures />} />
              <Route path="/sessions/:sessionID/power" element={<PowerFeatures />} />
              <Route path="/tools" element={<Tools />} />
              <Route path="/settings" element={<Settings />} />
              <Route path="/sessions/:sessionID" element={<Dashboard />} />
              <Route path="/findings" element={<Findings />} />
              <Route path="/sessions/:sessionID/findings" element={<Findings />} />
              <Route path="/source" element={<Source />} />
              <Route path="/sessions/:sessionID/source" element={<Source />} />
              <Route path="/sessions/:sessionID/tools" element={<Tools />} />
              <Route path="/runs" element={<ToolRuns />} />
              <Route path="/sessions/:sessionID/runs" element={<ToolRuns />} />
              <Route path="/graph" element={<AttackGraph />} />
              <Route path="/sessions/:sessionID/graph" element={<AttackGraph />} />
              <Route path="/cves" element={<CVEs />} />
              <Route path="/sessions/:sessionID/cves" element={<CVEs />} />
              <Route path="/llm" element={<LLMChat />} />
              <Route path="/sessions/:sessionID/llm" element={<LLMChat />} />
              <Route path="/reports" element={<Reports />} />
              <Route path="/sessions/:sessionID/report" element={<Reports />} />
              <Route path="/sessions/:sessionID/reports" element={<Reports />} />
            </Routes>
          </Suspense>
        </RouteErrorBoundary>
        <GlobalSearchOverlay open={searchOpen} onClose={() => setSearchOpen(false)} />
        <ToastCenter toasts={toasts} onDismiss={(id) => setToasts((current) => current.filter((toast) => toast.id !== id))} />
      </main>
    </div>
  );
}

type ToastMessage = {
  id: string;
  tone: "info" | "success" | "warning" | "error";
  title: string;
  message: string;
};

function ToastCenter({ toasts, onDismiss }: { toasts: ToastMessage[]; onDismiss: (id: string) => void }) {
  return (
    <div className="toast-center" aria-live="polite" aria-relevant="additions">
      {toasts.map((toast) => (
        <article key={toast.id} className={`toast ${toast.tone}`}>
          <div><strong>{toast.title}</strong>{toast.message ? <span>{toast.message}</span> : null}</div>
          <button className="icon-button" type="button" aria-label="Dismiss notification" onClick={() => onDismiss(toast.id)}><X size={14} /></button>
        </article>
      ))}
    </div>
  );
}

function GlobalSearchOverlay({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { sessions, selectedSessionID } = useSessionContext();
  const [query, setQuery] = useState("");
  const inputRef = useRef<HTMLInputElement | null>(null);
  const findingsQuery = useQuery({ queryKey: ["global-search-findings", selectedSessionID], queryFn: () => listFindings(selectedSessionID), enabled: open && Boolean(selectedSessionID) });
  const sourceQuery = useQuery({ queryKey: ["global-search-source", selectedSessionID], queryFn: () => listSourceFindings(selectedSessionID), enabled: open && Boolean(selectedSessionID) });
  const cvesQuery = useQuery({ queryKey: ["global-search-cves", selectedSessionID], queryFn: () => listCVEs(selectedSessionID), enabled: open && Boolean(selectedSessionID) });

  useEffect(() => {
    if (!open) return;
    setQuery("");
    window.setTimeout(() => inputRef.current?.focus(), 0);
  }, [open]);

  const results = useMemo(() => buildGlobalSearchResults(query, selectedSessionID, sessions, findingsQuery.data ?? [], sourceQuery.data ?? [], cvesQuery.data ?? []), [cvesQuery.data, findingsQuery.data, query, selectedSessionID, sessions, sourceQuery.data]);
  if (!open) return null;
  return (
    <div className="search-overlay" role="dialog" aria-modal="true" aria-label="Global search">
      <button className="modal-scrim" type="button" aria-label="Close search" onClick={onClose} />
      <section className="search-modal">
        <div className="search-box">
          <Search size={18} />
          <input ref={inputRef} value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search findings, CVEs, URLs, OWASP categories, source findings, sessions" />
          <button className="icon-button" type="button" aria-label="Close search" onClick={onClose}><X size={16} /></button>
        </div>
        <div className="search-results">
          {results.map((result) => (
            <Link key={`${result.kind}-${result.id}`} to={result.to} onClick={onClose}>
              <span>{result.kind}</span>
              <strong>{result.title}</strong>
              <small>{result.detail}</small>
            </Link>
          ))}
          {results.length === 0 ? <div className="empty-line">{query.trim() ? "No matching session data." : "Type to search the selected session and session history."}</div> : null}
        </div>
      </section>
    </div>
  );
}

type SearchResult = {
  id: string;
  kind: string;
  title: string;
  detail: string;
  to: string;
  haystack: string;
};

export function buildGlobalSearchResults(query: string, selectedSessionID: string, sessions: SessionRecord[], findings: Finding[], sourceFindings: SourceFinding[], cves: CVEMatch[]) {
  const rows: SearchResult[] = [
    ...sessions.map((record) => ({
      id: record.session.id,
      kind: "session",
      title: record.session.name || record.session.target_input || record.session.source_path || record.session.id,
      detail: `${record.session.status} · ${record.session.finding_count} findings`,
      to: `/sessions/${record.session.id}`,
      haystack: [record.session.name, record.session.target_input, record.session.source_path, record.session.status].join(" "),
    })),
    ...findings.map((finding) => ({
      id: finding.id,
      kind: "finding",
      title: finding.title,
      detail: `${finding.severity} · ${finding.tool_id} · ${finding.url}`,
      to: `/sessions/${selectedSessionID}/findings?finding_id=${finding.id}`,
      haystack: [finding.title, finding.description, finding.url, finding.tool_id, finding.type, finding.severity, ...(finding.tags ?? [])].join(" "),
    })),
    ...sourceFindings.map((finding) => ({
      id: finding.id,
      kind: "source",
      title: finding.value || finding.kind,
      detail: `${finding.kind} · ${finding.file_path}:${finding.line_number}`,
      to: `/sessions/${selectedSessionID}/source`,
      haystack: [finding.value, finding.kind, finding.language, finding.framework, finding.file_path, finding.context, finding.notes].join(" "),
    })),
    ...cves.map((cve) => ({
      id: cve.id,
      kind: "cve",
      title: cve.cve_id,
      detail: `${cve.package_name || "component"} · CVSS ${cve.cvss_v3_score || "n/a"}`,
      to: `/sessions/${selectedSessionID}/cves`,
      haystack: [cve.cve_id, cve.package_name, cve.package_version, cve.affected_version, cve.fixed_version, cve.description, cve.source].join(" "),
    })),
  ];
  const needle = query.trim().toLowerCase();
  return (needle ? rows.filter((row) => `${row.title} ${row.detail} ${row.haystack}`.toLowerCase().includes(needle)) : rows).slice(0, 18);
}

function RouteSkeleton({ label }: { label: string }) {
  return (
    <section className="route-skeleton" aria-label={label}>
      <span />
      <span />
      <span />
    </section>
  );
}

function isTypingTarget(target: EventTarget | null) {
  if (!(target instanceof HTMLElement)) return false;
  const tag = target.tagName.toLowerCase();
  return tag === "input" || tag === "textarea" || tag === "select" || target.isContentEditable;
}

class RouteErrorBoundary extends React.Component<{ children: React.ReactNode }, { error: Error | null }> {
  state: { error: Error | null } = { error: null };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  render() {
    if (this.state.error) {
      return (
        <section className="panel route-loading">
          <h2>Page failed to load</h2>
          <p>{this.state.error.message}</p>
          <button className="primary" onClick={() => window.location.reload()}>Reload</button>
        </section>
      );
    }
    return this.props.children;
  }
}

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
