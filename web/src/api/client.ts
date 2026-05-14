export type SessionStatus = "pending" | "running" | "completed" | "failed" | "cancelled";

export type Session = {
  id: string;
  name: string;
  status: SessionStatus;
  mode: string;
  target_input: string;
  target_count: number;
  finding_count: number;
  llm_model?: string;
  llm_base_url?: string;
  created_at: string;
  started_at?: string;
  completed_at?: string;
};

export type SessionRecord = {
  session: Session;
  db_path: string;
};

export type Technology = {
  id: string;
  target_id: string;
  name: string;
  version: string;
  category: string;
  confidence: number;
  source_tool: string;
};

export type Target = {
  id: string;
  host: string;
  ip?: string;
  port: number;
  protocol: string;
  is_alive: boolean;
  discovered_by: string;
  technologies?: Technology[];
};

export type CVEMatch = {
  id: string;
  finding_id: string;
  technology_id?: string;
  cve_id: string;
  cvss_v3_score: number;
  description: string;
  patch_available: boolean;
  exploit_available: boolean;
  source: string;
};

export type Finding = {
  id: string;
  session_id: string;
  target_id: string;
  tool_id: string;
  type: string;
  severity: string;
  confidence: number;
  cvss_score: number;
  title: string;
  description: string;
  remediation: string;
  url: string;
  evidence_raw?: string;
  evidence_normalized?: string;
  cve_matches?: CVEMatch[];
  created_at: string;
};

export type AttackStep = {
  order: number;
  description: string;
  finding_id?: string;
  tool_suggested?: string;
};

export type AttackVector = {
  id: string;
  title: string;
  description: string;
  narrative: string;
  owasp_category: string;
  severity: string;
  confidence: number;
  steps: AttackStep[];
  prereq_finding_ids: string[];
};

export type ToolRun = {
  id: string;
  tool_id: string;
  exit_code: number;
  duration_ms: number;
  finding_count: number;
  started_at: string;
};

export type LLMToolCall = {
  id?: string;
  name: string;
  arguments?: string;
  result?: string;
  error?: string;
};

export type LLMMessage = {
  role: string;
  content: string;
  tool_calls?: LLMToolCall[];
};

export type LLMAnalysis = {
  id: string;
  session_id: string;
  model_id: string;
  prompt_summary: string;
  messages: LLMMessage[];
  total_tokens: number;
  created_at: string;
};

export type SessionStats = {
  session_id: string;
  target_count: number;
  finding_count: number;
  tool_run_count: number;
  severity_counts: Record<string, number>;
};

export type StartScanRequest = {
  target: string;
  name?: string;
  mode: string;
  out_of_scope?: string[];
  enabled_phases?: string[];
  llm_model?: string;
  llm_base_url?: string;
};

export type ScanEventType =
  | "queued"
  | "running"
  | "tool_started"
  | "tool_completed"
  | "tool_error"
  | "phase_started"
  | "phase_completed"
  | "finding_found"
  | "failed"
  | "completed"
  | "cancelled";

export type ScanEvent = {
  type: ScanEventType;
  session_id: string;
  target_id?: string;
  tool_id?: string;
  phase?: string;
  finding_id?: string;
  finding_title?: string;
  severity?: string;
  status?: string;
  message?: string;
  finding_count?: number;
  duration_ms?: number;
  at: string;
};

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
    ...init,
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({ error: response.statusText }));
    throw new Error(payload.error ?? response.statusText);
  }
  return response.json() as Promise<T>;
}

export function listSessions() {
  return api<SessionRecord[]>("/api/sessions");
}

export function getSession(sessionID: string) {
  return api<Session>(`/api/sessions/${sessionID}`);
}

export function getSessionStats(sessionID: string) {
  return api<SessionStats>(`/api/sessions/${sessionID}/stats`);
}

export function listTargets(sessionID: string) {
  return api<Target[]>(`/api/sessions/${sessionID}/targets`);
}

export function listFindings(sessionID: string, params: Record<string, string> = {}) {
  const search = new URLSearchParams(params);
  const suffix = search.toString() ? `?${search}` : "";
  return api<Finding[]>(`/api/sessions/${sessionID}/findings${suffix}`);
}

export function listToolRuns(sessionID: string) {
  return api<ToolRun[]>(`/api/sessions/${sessionID}/tool-runs`);
}

export function listVectors(sessionID: string) {
  return api<AttackVector[]>(`/api/sessions/${sessionID}/vectors`);
}

export function listCVEs(sessionID: string) {
  return api<CVEMatch[]>(`/api/sessions/${sessionID}/cves`);
}

export function llmHistory(sessionID: string) {
  return api<LLMAnalysis[]>(`/api/sessions/${sessionID}/llm/history`);
}

export function llmAnalyse(sessionID: string) {
  return api<LLMAnalysis>(`/api/sessions/${sessionID}/llm/analyse`, { method: "POST", body: "{}" });
}

export function llmChat(sessionID: string, message: string) {
  return api<LLMAnalysis>(`/api/sessions/${sessionID}/llm/chat`, {
    method: "POST",
    body: JSON.stringify({ message }),
  });
}

export async function getReport(sessionID: string, format: string, mode: string) {
  const response = await fetch(`/api/sessions/${sessionID}/report?format=${encodeURIComponent(format)}&mode=${encodeURIComponent(mode)}`);
  if (!response.ok) {
    throw new Error(await response.text());
  }
  return response.text();
}

export function startScan(request: StartScanRequest) {
  return api<SessionRecord>("/api/scan/start", {
    method: "POST",
    body: JSON.stringify(request),
  });
}

export function scanEventsURL(sessionID: string) {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${protocol}//${window.location.host}/api/scan/${sessionID}/events`;
}
