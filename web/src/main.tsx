import React, { Suspense, lazy, useEffect, useState } from "react";
import ReactDOM from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Link, NavLink, Route, Routes, useLocation } from "react-router-dom";
import { Bot, Boxes, FileCode2, FileText, Menu, Moon, MoreHorizontal, Network, PackageSearch, Radar, RefreshCw, Search, Settings as SettingsIcon, Shield, Sparkles, Sun, TerminalSquare, Wrench, X } from "lucide-react";
import { login as loginAPI } from "./api/client";
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
  const { sessions, selectedSessionID, selected, setSelectedSessionID, refreshSessions } = useSessionContext();
  const [theme, setTheme] = useState(() => localStorage.getItem("nyx-theme") ?? "dark");
  const [navOpen, setNavOpen] = useState(false);
  const [actionsOpen, setActionsOpen] = useState(false);
  const location = useLocation();
  const scoped = (suffix: string) => scopedSessionPath(selectedSessionID, suffix);
  const selectedSession = selected?.session;
  const commandCenterPath = selectedSessionID ? scoped("") : "/";

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem("nyx-theme", theme);
  }, [theme]);

  useEffect(() => {
    setNavOpen(false);
    setActionsOpen(false);
  }, [location.pathname]);

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
          <button className="icon-button mobile-actions-button" aria-label="Open page actions" aria-expanded={actionsOpen} onClick={() => setActionsOpen((open) => !open)}><MoreHorizontal size={18} /></button>
          <div className={`topbar-actions ${actionsOpen ? "open" : ""}`}>
            <Link className="secondary link-button topbar-action" to={selectedSessionID ? scoped("/findings") : "/scan"}>{selectedSessionID ? "Triage" : "New Scan"}</Link>
            <button className="icon-button theme-toggle" aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} mode`} onClick={() => setTheme(theme === "dark" ? "light" : "dark")}>
              {theme === "dark" ? <Sun size={18} /> : <Moon size={18} />}
            </button>
            <button className="secondary" onClick={refreshSessions} title="Refresh session list" aria-label="Refresh session list"><RefreshCw size={16} />Refresh</button>
          </div>
          {navOpen ? <button className="icon-button close-mobile-nav" aria-label="Close navigation" onClick={() => setNavOpen(false)}><X size={18} /></button> : null}
        </header>
        <RouteErrorBoundary key={location.pathname}>
          <Suspense fallback={<section className="panel route-loading">Loading</section>}>
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
      </main>
    </div>
  );
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
