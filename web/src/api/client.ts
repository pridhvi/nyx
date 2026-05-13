export type SessionStatus = "pending" | "running" | "completed" | "failed" | "cancelled";

export type Session = {
  id: string;
  name: string;
  status: SessionStatus;
  mode: string;
  target_input: string;
  target_count: number;
  finding_count: number;
  created_at: string;
  started_at?: string;
  completed_at?: string;
};

export type SessionRecord = {
  session: Session;
  db_path: string;
};

export type Finding = {
  id: string;
  tool_id: string;
  severity: string;
  title: string;
  url: string;
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

export function getSessionStats(sessionID: string) {
  return api<SessionStats>(`/api/sessions/${sessionID}/stats`);
}

export function listFindings(sessionID: string) {
  return api<Finding[]>(`/api/sessions/${sessionID}/findings`);
}

export function startScan(request: StartScanRequest) {
  return api<SessionRecord>("/api/scan/start", {
    method: "POST",
    body: JSON.stringify(request),
  });
}

