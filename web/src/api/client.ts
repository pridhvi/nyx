type SessionStatus = "pending" | "running" | "paused" | "completed" | "failed" | "cancelled";

type Session = {
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

type RunnerOptions = {
  concurrency?: number;
  per_tool_concurrency?: number;
  tool_timeout_seconds?: number;
  tool_delay_ms?: number;
  rate_limit?: string;
  evasion_profile?: string;
  jitter_ms?: number;
  proxy_url?: string;
  user_agent_profile?: string;
  header_profile?: string;
  adaptive_backoff?: boolean;
  max_backoff_seconds?: number;
};

export type SessionRecord = {
  session: Session;
  db_path: string;
};

type Technology = {
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

export type FindingStatus = "open" | "confirmed" | "false-positive" | "suppressed" | "wont-fix";

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

type HTTPEvidence = {
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
  status?: FindingStatus;
  notes?: string;
  tags?: string[];
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

type AttackStep = {
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

type LLMToolCall = {
  id?: string;
  name: string;
  arguments?: string;
  result?: string;
  error?: string;
};

export type LLMMessage = {
  role: string;
  content: string;
  reasoning_content?: string;
  raw_content?: string;
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

export type ScanPhaseProgress = {
  phase: string;
  status: "pending" | "running" | "completed" | "failed";
  started_at?: string;
  completed_at?: string;
  tool_count: number;
  running_tools: number;
  completed_tools: number;
  failed_tools: number;
  finding_count: number;
  duration_ms?: number;
};

export type ScanToolProgress = {
  tool_id: string;
  name?: string;
  phase: string;
  status: "pending" | "running" | "completed" | "failed";
  finding_count: number;
  duration_ms?: number;
  started_at?: string;
  completed_at?: string;
};

export type ScanStatus = {
  id: string;
  status: SessionStatus;
  target_count: number;
  finding_count: number;
  started_at?: string;
  completed_at?: string;
  current_phase?: string;
  active_tools?: string[];
  phases: ScanPhaseProgress[];
  tools: ScanToolProgress[];
  recent_events?: ScanEvent[];
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
  route_seeds?: string[];
  auth_headers?: Record<string, string>;
  auth_cookies?: Record<string, string>;
  auth_cookie_header?: string;
  auth_profile?: Record<string, unknown>;
  secondary_auth_headers?: Record<string, string>;
  secondary_auth_cookies?: Record<string, string>;
  secondary_auth_cookie_header?: string;
  evasion_profile?: string;
  jitter_ms?: number;
  proxy_url?: string;
  user_agent_profile?: string;
  header_profile?: string;
  adaptive_backoff?: boolean;
  max_backoff_seconds?: number;
  llm_model?: string;
  llm_base_url?: string;
};

export type Payload = {
  id: string;
  finding_id: string;
  session_id: string;
  payload_type: string;
  payload: string;
  context: string;
  target_waf?: string;
  target_db?: string;
  bypass_technique?: string;
  confidence: number;
  validated: boolean;
  validated_response?: string;
  rank: number;
  created_at: string;
};

export type PayloadValidationResult = {
  payload_id: string;
  validated: boolean;
  evidence: string;
};

export type CredentialFinding = {
  id: string;
  session_id: string;
  target_id?: string;
  finding_id?: string;
  credential_type: string;
  username: string;
  password: string;
  service: string;
  url: string;
  valid: boolean;
  lockout_detected: boolean;
  evidence: string;
  created_at: string;
};

export type OSINTFinding = {
  id: string;
  session_id: string;
  kind: string;
  value: string;
  source: string;
  confidence: number;
  target_id?: string;
  metadata?: Record<string, unknown>;
  created_at: string;
};

export type ProviderStatus = {
  id: string;
  session_id: string;
  provider: string;
  module: string;
  status: "configured" | "skipped" | "ok" | "error";
  message: string;
  metadata?: Record<string, unknown>;
  created_at: string;
};

export type ADEntity = {
  id: string;
  session_id: string;
  entity_type: string;
  name: string;
  domain: string;
  sid: string;
  distinguished_name: string;
  metadata?: Record<string, unknown>;
  created_at: string;
};

export type ADRelationship = {
  id: string;
  session_id: string;
  from_entity_id: string;
  to_entity_id: string;
  relation: string;
  metadata?: Record<string, unknown>;
  created_at: string;
};

export type BlockEvent = {
  id: string;
  session_id: string;
  target_id?: string;
  tool_id: string;
  url: string;
  status_code: number;
  signal: string;
  response_snippet: string;
  backoff_ms: number;
  created_at: string;
};

export type PoCResult = {
  id: string;
  session_id: string;
  finding_id: string;
  target_id?: string;
  poc_type: string;
  status: string;
  payload_id?: string;
  evidence: string;
  impact_narrative: string;
  created_at: string;
  completed_at?: string;
};

export type PowerCallback = {
  id: string;
  session_id: string;
  finding_id?: string;
  provider: string;
  token: string;
  url: string;
  received: boolean;
  source_ip?: string;
  raw_event?: string;
  created_at: string;
  updated_at: string;
};

export type BurpRESTResult = {
  available: boolean;
  action: string;
  message: string;
  count?: number;
};

export type BurpStatusResponse = {
  configured: boolean;
  available: boolean;
  result: BurpRESTResult;
  config?: Record<string, unknown>;
};

export type ScanProfileRecord = {
  id: string;
  name: string;
  description: string;
  request: StartScanRequest;
  created_at: string;
  updated_at: string;
};

type MonitorNotificationConfig = {
  slack_webhook_url?: string;
  discord_webhook_url?: string;
  email?: string;
};

export type MonitorConfig = {
  id: string;
  name: string;
  target_input: string;
  in_scope?: string[];
  out_of_scope?: string[];
  schedule: string;
  enabled_phases?: string[];
  enabled_tools?: string[];
  tool_parameters?: Record<string, Record<string, unknown>>;
  runner_options?: RunnerOptions;
  alert_on?: string[];
  notification_config?: MonitorNotificationConfig;
  baseline_session_id?: string;
  last_run_at?: string;
  next_run_at?: string;
  enabled: boolean;
  created_at: string;
  updated_at: string;
};

export type MonitorRun = {
  id: string;
  config_id: string;
  session_id?: string;
  status: "running" | "completed" | "failed";
  changes_found: boolean;
  error?: string;
  started_at: string;
  completed_at?: string;
};

export type SurfaceChange = {
  id: string;
  monitor_run_id: string;
  session_id: string;
  change_type: string;
  severity: string;
  description: string;
  previous_value?: string;
  current_value?: string;
  target_id?: string;
  finding_id?: string;
  alerted: boolean;
  created_at: string;
};

type ToolParameter = {
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
  sha256?: string;
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

export type SourceRoot = {
  path: string;
  label: string;
};

export type SourceRootResponse = {
  roots: SourceRoot[];
};

export type SourceDirectory = {
  name: string;
  path: string;
};

export type SourceDirectoryResponse = {
  path: string;
  parent_path?: string;
  directories: SourceDirectory[];
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
  power?: Record<string, unknown>;
};

type ScanEventType =
  | "queued"
  | "running"
  | "tool_started"
  | "tool_completed"
  | "tool_error"
  | "phase_started"
  | "phase_completed"
  | "finding_found"
  | "auth_status"
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

export const authExpiredEvent = "nyx-auth-expired";

function notifyAuthExpired(response: Response) {
  if (response.status !== 401 || typeof window === "undefined") {
    return;
  }
  window.dispatchEvent(new CustomEvent(authExpiredEvent));
}

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...init,
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
  });
  if (!response.ok) {
    notifyAuthExpired(response);
    const payload = await response.json().catch(() => ({ error: response.statusText }));
    throw new Error(payload.error ?? response.statusText);
  }
  return response.json() as Promise<T>;
}

export function login(apiKey: string) {
  return api<{ authenticated: boolean; auth_enabled: boolean; expires_at?: string }>("/api/auth/login", {
    method: "POST",
    body: JSON.stringify({ api_key: apiKey }),
  });
}

export function listSessions() {
  return api<SessionRecord[]>("/api/sessions");
}

export function getSessionStats(sessionID: string) {
  return api<SessionStats>(`/api/sessions/${sessionID}/stats`);
}

export function getScanStatus(sessionID: string) {
  return api<ScanStatus>(`/api/scan/${sessionID}/status`);
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

export function listPayloads(sessionID: string) {
  return api<Payload[]>(`/api/sessions/${sessionID}/payloads`);
}

export function generatePayloads(sessionID: string, findingID: string, force_regenerate = false) {
  return api<Payload[]>(`/api/sessions/${sessionID}/findings/${findingID}/generate-payloads`, { method: "POST", body: JSON.stringify({ force_regenerate }) });
}

export function validatePayload(sessionID: string, payloadID: string, confirm = true) {
  return api<PayloadValidationResult>(`/api/sessions/${sessionID}/payloads/${payloadID}/validate`, { method: "POST", body: JSON.stringify({ confirm }) });
}

export function listCredentials(sessionID: string) {
  return api<CredentialFinding[]>(`/api/sessions/${sessionID}/credentials`);
}

export function testCredentials(sessionID: string, payload: { mode: string; username?: string; password?: string; service?: string; url?: string; confirm?: boolean; max_attempts?: number; delay_ms?: number; store_secret?: boolean }) {
  return api<CredentialFinding[]>(`/api/sessions/${sessionID}/credentials/test`, { method: "POST", body: JSON.stringify(payload) });
}

export function listOSINT(sessionID: string) {
  return api<OSINTFinding[]>(`/api/sessions/${sessionID}/osint`);
}

export function runOSINT(sessionID: string, providers: string[] = []) {
  return api<OSINTFinding[]>(`/api/sessions/${sessionID}/osint/run`, { method: "POST", body: JSON.stringify({ providers }) });
}

export function listProviderStatuses(sessionID: string, provider = "") {
  const suffix = provider ? `?provider=${encodeURIComponent(provider)}` : "";
  return api<ProviderStatus[]>(`/api/sessions/${sessionID}/provider-statuses${suffix}`);
}

export function listADEntities(sessionID: string) {
  return api<ADEntity[]>(`/api/sessions/${sessionID}/ad/entities`);
}

export function listADRelationships(sessionID: string) {
  return api<ADRelationship[]>(`/api/sessions/${sessionID}/ad/relationships`);
}

export function listBlockEvents(sessionID: string) {
  return api<BlockEvent[]>(`/api/sessions/${sessionID}/block-events`);
}

export function listPoCResults(sessionID: string) {
  return api<PoCResult[]>(`/api/sessions/${sessionID}/poc-results`);
}

export function runPoC(sessionID: string, findingID: string, confirm = true, extra: Record<string, unknown> = {}) {
  return api<PoCResult>(`/api/sessions/${sessionID}/findings/${findingID}/poc/run`, { method: "POST", body: JSON.stringify({ confirm, ...extra }) });
}

export function listPowerCallbacks(sessionID: string) {
  return api<PowerCallback[]>(`/api/sessions/${sessionID}/callbacks`);
}

export function runADKerberoast(sessionID: string, payload: { domain?: string; spn?: string; confirm?: boolean; allow_public?: boolean }) {
  return api<Record<string, unknown>>(`/api/sessions/${sessionID}/ad/kerberoast`, { method: "POST", body: JSON.stringify(payload) });
}

export function getBurpStatus(sessionID: string) {
  return api<BurpStatusResponse>(`/api/sessions/${sessionID}/burp/status`);
}

export function pushBurpScope(sessionID: string) {
  return api<BurpRESTResult>(`/api/sessions/${sessionID}/burp/push-scope`, { method: "POST", body: "{}" });
}

export function pullBurpIssues(sessionID: string) {
  return api<Finding[]>(`/api/sessions/${sessionID}/burp/pull-issues`, { method: "POST", body: "{}" });
}

export function updateFinding(sessionID: string, findingID: string, payload: { severity?: string; remediation?: string; status?: FindingStatus }) {
  return api<Finding>(`/api/sessions/${sessionID}/findings/${findingID}`, {
    method: "PATCH",
    body: JSON.stringify(payload),
  });
}

export function listToolRuns(sessionID: string) {
  return api<ToolRun[]>(`/api/sessions/${sessionID}/tool-runs`);
}

export async function getToolRunLog(sessionID: string, runID: string, stream: "stdout" | "stderr") {
  const response = await fetch(`/api/sessions/${sessionID}/tool-runs/${runID}/${stream}`, { credentials: "same-origin" });
  if (response.status === 404) {
    return null;
  }
  if (!response.ok) {
    notifyAuthExpired(response);
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

export function listSourceRoots() {
  return api<SourceRootResponse>("/api/source-roots");
}

export function listSourceDirectories(path: string) {
  return api<SourceDirectoryResponse>(`/api/source-dirs?path=${encodeURIComponent(path)}`);
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

export function listMonitorConfigs() {
  return api<MonitorConfig[]>("/api/monitor/configs");
}

export function createMonitorConfig(payload: Partial<MonitorConfig>) {
  return api<MonitorConfig>("/api/monitor/configs", { method: "POST", body: JSON.stringify(payload) });
}

export function updateMonitorConfig(configID: string, payload: Partial<MonitorConfig>) {
  return api<MonitorConfig>(`/api/monitor/configs/${configID}`, { method: "PUT", body: JSON.stringify(payload) });
}

export function deleteMonitorConfig(configID: string) {
  return api<{ deleted: boolean }>(`/api/monitor/configs/${configID}`, { method: "DELETE" });
}

export function runMonitorConfig(configID: string) {
  return api<{ run: MonitorRun; changes: SurfaceChange[] }>(`/api/monitor/configs/${configID}/run`, { method: "POST", body: "{}" });
}

export function listMonitorRuns(configID?: string) {
  const suffix = configID ? `?config_id=${encodeURIComponent(configID)}` : "";
  return api<MonitorRun[]>(`/api/monitor/runs${suffix}`);
}

export function listMonitorRunChanges(runID: string) {
  return api<SurfaceChange[]>(`/api/monitor/runs/${runID}/changes`);
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
  const response = await fetch("/api/plugins/upload", { method: "POST", body, credentials: "same-origin" });
  if (!response.ok) {
    notifyAuthExpired(response);
    const payload = await response.json().catch(() => ({ error: response.statusText }));
    throw new Error(payload.error ?? response.statusText);
  }
  return response.json() as Promise<{ binary: string; sha256: string }>;
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
  const response = await fetch(`/api/sessions/${sessionID}/report?format=${encodeURIComponent(format)}&mode=${encodeURIComponent(mode)}`, {
    credentials: "same-origin",
  });
  if (!response.ok) {
    notifyAuthExpired(response);
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
