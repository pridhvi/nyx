import React, { Suspense, lazy, useEffect, useState } from "react";
import ReactDOM from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, NavLink, Route, Routes, useLocation } from "react-router-dom";
import { Bot, FileCode2, FileText, Moon, Network, PackageSearch, Search, Settings as SettingsIcon, Shield, Sun, TerminalSquare, Wrench } from "lucide-react";
import { scopedSessionPath } from "./sessionRoutes";
import { SessionProvider, useSessionContext } from "./session";
import "./styles.css";

const queryClient = new QueryClient();
const Dashboard = lazy(() => import("./pages/Dashboard").then((module) => ({ default: module.Dashboard })));
const ScanBuilder = lazy(() => import("./pages/ScanBuilder").then((module) => ({ default: module.ScanBuilder })));
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
      <BrowserRouter>
        <SessionProvider>
          <OperatorShell />
        </SessionProvider>
      </BrowserRouter>
    </QueryClientProvider>
  );
}

function OperatorShell() {
  const { sessions, selectedSessionID, selected, setSelectedSessionID, refreshSessions } = useSessionContext();
  const [theme, setTheme] = useState(() => localStorage.getItem("nox-theme") ?? "dark");
  const location = useLocation();
  const scoped = (suffix: string) => scopedSessionPath(selectedSessionID, suffix);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem("nox-theme", theme);
  }, [theme]);

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand"><img src="/nox-logo.svg" alt="" />Nox</div>
        <nav>
          <NavLink to={scoped("")}><Shield size={18} />Dashboard</NavLink>
          <NavLink to="/scan"><TerminalSquare size={18} />Scan Builder</NavLink>
          <NavLink to={scoped("/findings")}><Search size={18} />Findings</NavLink>
          <NavLink to={scoped("/source")}><FileCode2 size={18} />Source</NavLink>
          <NavLink to={scoped("/tools")}><Wrench size={18} />Tools</NavLink>
          <NavLink to={scoped("/runs")}><PackageSearch size={18} />Tool Runs</NavLink>
          <NavLink to={scoped("/graph")}><Network size={18} />Attack Graph</NavLink>
          <NavLink to={scoped("/cves")}><Shield size={18} />CVEs</NavLink>
          <NavLink to={scoped("/llm")}><Bot size={18} />LLM</NavLink>
          <NavLink to={scoped("/report")}><FileText size={18} />Reports</NavLink>
          <NavLink to="/settings"><SettingsIcon size={18} />Settings</NavLink>
        </nav>
      </aside>
      <main>
        <header className="topbar">
          <label>Session
            <select value={selectedSessionID} onChange={(event) => setSelectedSessionID(event.target.value)}>
              <option value="">No session</option>
              {sessions.map((record) => <option key={record.session.id} value={record.session.id}>{record.session.name || record.session.target_input} · {record.session.status}</option>)}
            </select>
          </label>
          <span className={`status ${selected?.session.status ?? "pending"}`}>{selected?.session.status ?? "no session"}</span>
          <button className="icon-button theme-toggle" aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} mode`} onClick={() => setTheme(theme === "dark" ? "light" : "dark")}>
            {theme === "dark" ? <Sun size={18} /> : <Moon size={18} />}
          </button>
          <button className="secondary" onClick={refreshSessions}>Refresh</button>
        </header>
        <RouteErrorBoundary key={location.pathname}>
          <Suspense fallback={<section className="panel route-loading">Loading</section>}>
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/scan" element={<ScanBuilder />} />
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
