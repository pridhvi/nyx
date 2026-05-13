import React from "react";
import ReactDOM from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, NavLink, Route, Routes } from "react-router-dom";
import { Shield, Network, MessageSquare, FileText } from "lucide-react";
import { Dashboard } from "./pages/Dashboard";
import { AttackGraph } from "./pages/AttackGraph";
import { LLMChat } from "./pages/LLMChat";
import { Reports } from "./pages/Reports";
import "./styles.css";

const queryClient = new QueryClient();

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <div className="shell">
          <aside className="sidebar">
            <div className="brand">Nox</div>
            <nav>
              <NavLink to="/"><Shield size={18} />Dashboard</NavLink>
              <NavLink to="/graph"><Network size={18} />Attack Graph</NavLink>
              <NavLink to="/llm"><MessageSquare size={18} />LLM</NavLink>
              <NavLink to="/reports"><FileText size={18} />Reports</NavLink>
            </nav>
          </aside>
          <main>
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/graph" element={<AttackGraph />} />
              <Route path="/llm" element={<LLMChat />} />
              <Route path="/reports" element={<Reports />} />
            </Routes>
          </main>
        </div>
      </BrowserRouter>
    </QueryClientProvider>
  );
}

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);

