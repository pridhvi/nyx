export type SessionStatus = "pending" | "running" | "paused" | "completed" | "failed" | "cancelled";

export type Session = {
  id: string;
  name: string;
  status: SessionStatus;
  mode: string;
  workload_mode?: "dynamic" | "static" | "combined";
  target_input: string;
  source_path?: string;
  in_scope?: string[];
  out_of_scope?: string[];
  enabled_phases?: string[];
  enabled_tools?: string[];
  tool_parameters?: Record<string, Record<string, unknown>>;
  runner_options?: RunnerOptions;
  target_count: number;
  finding_count: number;
  llm_model?: string;
  llm_base_url?: string;
  created_at: string;
  started_at?: string;
  completed_at?: string;
};

export type RunnerOptions = {
  concurrency?: number;
  per_tool_concurrency?: number;
  tool_timeout_seconds?: number;
  tool_delay_ms?: number;
  rate_limit?: string;
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
  session_id?: string;
  finding_id: string;
  technology_id?: string;
  package_name?: string;
  package_version?: string;
  cve_id: string;
  cvss_v3_score: number;
  description: string;
  patch_available: boolean;
  exploit_available: boolean;
  source: string;
  references?: string[];
};

export type HTTPEvidence = {
  request_raw: string;
  response_raw: string;
  status_code: number;
  response_time: number;
};

export type Finding = {
  id: string;
  session_id: string;
  target_id?: string;
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
  http_evidence?: HTTPEvidence;
  cve_matches?: CVEMatch[];
  code_context?: string;
  flow_summary?: string;
  status?: string;
  notes?: string;
  created_at: string;
};

export type SourceFinding = {
  id: string;
  session_id: string;
  kind: string;
  language: string;
  framework: string;
  file_path: string;
  line_number: number;
  value: string;
  method?: string;
  context?: string;
  notes?: string;
  confirmed_dynamic?: boolean;
  created_at: string;
};

export type AttackGraphEdge = {
  id: string;
  session_id: string;
  from_id: string;
  to_id: string;
  relation: "enables" | "amplifies" | "requires" | "confirms";
  confidence: number;
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
  llm_reviewed?: boolean;
  llm_notes?: string;
};

export type ToolRun = {
  id: string;
  session_id: string;
  target_id?: string;
  tool_id: string;
  args: string[];
  stdout_path: string;
  stderr_path: string;
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
  static_finding_count: number;
  dynamic_finding_count: number;
  confirmed_by_both: number;
  source_finding_count: number;
  tool_run_count: number;
  severity_counts: Record<string, number>;
};

export type StartScanRequest = {
  target: string;
  targets?: string[];
  source_path?: string;
  name?: string;
  mode: string;
  out_of_scope?: string[];
  enabled_phases?: string[];
  tools?: string[];
  tool_parameters?: Record<string, Record<string, unknown>>;
  concurrency?: number;
  per_tool_concurrency?: number;
  tool_timeout_seconds?: number;
  tool_delay_ms?: number;
  rate_limit?: string;
  llm_model?: string;
  llm_base_url?: string;
};

export type ScanProfileRecord = {
  id: string;
  name: string;
  description: string;
  request: StartScanRequest;
  created_at: string;
  updated_at: string;
};

export type ToolParameter = {
  name: string;
  label: string;
  type: "string" | "number" | "boolean" | "enum" | "path" | "list";
  default?: unknown;
  options?: string[];
  description?: string;
};

export type ToolRecord = {
  id: string;
  name: string;
  description: string;
  homepage_url: string;
  phase: string;
  depends_on: string[];
  kind: "builtin_http" | "subprocess" | "plugin";
  default_enabled: boolean;
  installed: boolean;
  binary_path: string;
  version: string;
  install_hint: string;
  parameters: ToolParameter[];
  last_run?: ToolRun;
};

export type PluginRecord = {
  id: string;
  name: string;
  binary: string;
  phase: string;
  description: string;
  homepage_url: string;
  enabled: boolean;
  created_at: string;
  updated_at: string;
};

export type LLMModelsResponse = {
  models: string[];
};

export type EffectiveConfig = {
  database: { session_dir: string };
  server: { host: string; port: number; auth_enabled: boolean };
  llm: { enabled: boolean; configured: boolean; provider: string; base_url: string; model: string; api_key_set: boolean; max_tokens: number; temperature: number };
  scan: Record<string, unknown>;
  cve: Record<string, unknown>;
  tools: Record<string, string>;
  plugins: string[];
  paths: Record<string, string>;
  runtime: Record<string, string>;
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

export function listSourceFindings(sessionID: string, params: Record<string, string> = {}) {
  const search = new URLSearchParams(params);
  const suffix = search.toString() ? `?${search}` : "";
  return api<SourceFinding[]>(`/api/sessions/${sessionID}/source-findings${suffix}`);
}

export function updateFinding(sessionID: string, findingID: string, payload: { severity?: string; remediation?: string }) {
  return api<Finding>(`/api/sessions/${sessionID}/findings/${findingID}`, {
    method: "PATCH",
    body: JSON.stringify(payload),
  });
}

export function listToolRuns(sessionID: string) {
  return api<ToolRun[]>(`/api/sessions/${sessionID}/tool-runs`);
}

export async function getToolRunLog(sessionID: string, runID: string, stream: "stdout" | "stderr") {
  const response = await fetch(`/api/sessions/${sessionID}/tool-runs/${runID}/${stream}`);
  if (response.status === 404) {
    return null;
  }
  if (!response.ok) {
    throw new Error(response.statusText);
  }
  return response.text();
}

export function listTools(sessionID?: string) {
  const suffix = sessionID ? `?session_id=${encodeURIComponent(sessionID)}` : "";
  return api<ToolRecord[]>(`/api/tools${suffix}`);
}

export function effectiveConfig() {
  return api<EffectiveConfig>("/api/config/effective");
}

export function listScanProfiles() {
  return api<ScanProfileRecord[]>("/api/scan-profiles");
}

export function createScanProfile(payload: { name: string; description?: string; request: StartScanRequest }) {
  return api<ScanProfileRecord>("/api/scan-profiles", { method: "POST", body: JSON.stringify(payload) });
}

export function deleteScanProfile(profileID: string) {
  return api<{ deleted: string }>(`/api/scan-profiles/${profileID}`, { method: "DELETE" });
}

export function listPlugins() {
  return api<PluginRecord[]>("/api/plugins");
}

export function createPlugin(payload: { name?: string; binary: string; phase?: string; description?: string; homepage_url?: string; enabled?: boolean }) {
  return api<PluginRecord>("/api/plugins", { method: "POST", body: JSON.stringify(payload) });
}

export function updatePlugin(pluginID: string, payload: { name?: string; binary?: string; phase?: string; description?: string; homepage_url?: string; enabled?: boolean }) {
  return api<PluginRecord>(`/api/plugins/${pluginID}`, { method: "PATCH", body: JSON.stringify(payload) });
}

export function deletePlugin(pluginID: string) {
  return api<{ deleted: string }>(`/api/plugins/${pluginID}`, { method: "DELETE" });
}

export async function uploadPluginBinary(file: File) {
  const body = new FormData();
  body.set("binary", file);
  const response = await fetch("/api/plugins/upload", { method: "POST", body });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({ error: response.statusText }));
    throw new Error(payload.error ?? response.statusText);
  }
  return response.json() as Promise<{ binary: string }>;
}

export function listVectors(sessionID: string) {
  return api<AttackVector[]>(`/api/sessions/${sessionID}/vectors`);
}

export function listAttackGraphEdges(sessionID: string) {
  return api<AttackGraphEdge[]>(`/api/sessions/${sessionID}/attack-graph-edges`);
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

export function listLLMModels(baseURL: string) {
  return api<LLMModelsResponse>("/api/llm/models", { method: "POST", body: JSON.stringify({ base_url: baseURL }) });
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

export function pauseScan(sessionID: string) {
  return api<{ status: string }>(`/api/scan/${sessionID}/pause`, { method: "POST", body: "{}" });
}

export function resumeScan(sessionID: string) {
  return api<{ status: string }>(`/api/scan/${sessionID}/resume`, { method: "POST", body: "{}" });
}

export function stopScan(sessionID: string) {
  return api<{ status: string }>(`/api/scan/${sessionID}/stop`, { method: "POST", body: "{}" });
}

export function deleteSession(sessionID: string) {
  return api<{ deleted: string }>(`/api/sessions/${sessionID}`, { method: "DELETE" });
}

export function scanEventsURL(sessionID: string) {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${protocol}//${window.location.host}/api/scan/${sessionID}/events`;
}
