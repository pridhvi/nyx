import type { ScanProfileRecord, StartScanRequest } from "./api/client";

export type ScanProfile = {
  id: string;
  name: string;
  description: string;
  builtIn?: boolean;
  request: Partial<StartScanRequest>;
};

const builtinProfiles: ScanProfile[] = [
  {
    id: "builtin-passive-recon",
    name: "Passive recon",
    description: "Low-noise discovery and HTTP validation.",
    builtIn: true,
    request: {
      mode: "passive",
      enabled_phases: ["recon", "fingerprint"],
      tools: ["http-probe", "security-headers", "whois", "waybackurls"],
      concurrency: 3,
      per_tool_concurrency: 1,
      tool_timeout_seconds: 45,
      tool_delay_ms: 100,
      rate_limit: "passive",
    },
  },
  {
    id: "builtin-web-active",
    name: "Web app active",
    description: "Balanced active scan for common web app issues.",
    builtIn: true,
    request: {
      mode: "active",
      enabled_phases: ["fingerprint", "enumerate", "vuln_scan"],
      tools: ["http-probe", "security-headers", "ffuf", "arjun", "cors-check", "reflected-xss-check", "sqli-check", "open-redirect-check", "upload-check", "xxe-fuzz", "nuclei-vuln", "dalfox", "sqlmap"],
      concurrency: 4,
      per_tool_concurrency: 1,
      tool_timeout_seconds: 90,
      tool_delay_ms: 50,
      rate_limit: "balanced",
      tool_parameters: {
        "nuclei-vuln": { severity: "low,medium,high,critical" },
        sqlmap: { level: 1, risk: 1 },
      },
    },
  },
  {
    id: "builtin-deep-vuln",
    name: "Deep vuln scan",
    description: "Higher-coverage active scan with stricter pacing.",
    builtIn: true,
    request: {
      mode: "active",
      enabled_phases: ["recon", "fingerprint", "enumerate", "vuln_scan"],
      tools: ["http-probe", "security-headers", "subfinder", "dnsx", "httpx", "whatweb", "nuclei-tech", "ffuf", "arjun", "linkfinder", "js-secret-scan", "cors-check", "reflected-xss-check", "sqli-check", "open-redirect-check", "upload-check", "xxe-fuzz", "nuclei-vuln", "dalfox", "sqlmap", "nikto"],
      concurrency: 3,
      per_tool_concurrency: 1,
      tool_timeout_seconds: 180,
      tool_delay_ms: 150,
      rate_limit: "deep",
      tool_parameters: {
        "nuclei-vuln": { severity: "medium,high,critical" },
        sqlmap: { level: 2, risk: 1 },
      },
    },
  },
];

export function apiProfiles(records: ScanProfileRecord[]): ScanProfile[] {
  return records.map((record) => ({
    id: record.id,
    name: record.name,
    description: record.description || "Saved scan builder preset.",
    request: record.request,
  }));
}

export function allProfiles(customProfiles: ScanProfileRecord[]) {
  return [...builtinProfiles, ...apiProfiles(customProfiles)];
}

export function buildCustomProfileRequest(name: string, request: StartScanRequest): { name: string; description: string; request: StartScanRequest } {
  const trimmed = name.trim();
  return {
    name: trimmed,
    description: "Saved scan builder preset.",
    request: {
      target: "",
      source_path: request.source_path,
      mode: request.mode,
      enabled_phases: request.enabled_phases ?? [],
      tools: request.tools ?? [],
      tool_parameters: request.tool_parameters ?? {},
      concurrency: request.concurrency,
      per_tool_concurrency: request.per_tool_concurrency,
      tool_timeout_seconds: request.tool_timeout_seconds,
      tool_delay_ms: request.tool_delay_ms,
      rate_limit: request.rate_limit,
      llm_model: request.llm_model,
      llm_base_url: request.llm_base_url,
    },
  };
}

export function cleanToolParameters(params: Record<string, Record<string, unknown>>) {
  const cleaned: Record<string, Record<string, unknown>> = {};
  for (const [toolID, values] of Object.entries(params)) {
    const toolValues: Record<string, unknown> = {};
    for (const [name, value] of Object.entries(values)) {
      if (value === "" || value == null) {
        continue;
      }
      if (Array.isArray(value) && value.length === 0) {
        continue;
      }
      toolValues[name] = value;
    }
    if (Object.keys(toolValues).length > 0) {
      cleaned[toolID] = toolValues;
    }
  }
  return cleaned;
}

export function splitLines(value: string) {
  return value.split(/\n|,/).map((item) => item.trim()).filter(Boolean);
}

export function splitArgs(value: string) {
  return value.split(/\s+/).map((item) => item.trim()).filter(Boolean);
}
