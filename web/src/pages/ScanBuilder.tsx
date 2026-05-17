import { type ChangeEvent, type FormEvent, type ReactNode, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, CircleHelp, Download, Play, Save, Settings, ShieldCheck, Trash2, Upload, XCircle } from "lucide-react";
import { createScanProfile, deleteScanProfile, listLLMModels, listScanProfiles, listTools, startScan, type StartScanRequest, type ToolRecord } from "../api/client";
import { allProfiles, buildCustomProfileRequest, cleanToolParameters, splitArgs, splitLines, type ScanProfile } from "../scanProfiles";
import { useSessionContext } from "../session";

const phases = [
  { id: "recon", label: "Recon", description: "Discover hosts, services, and reachable HTTP surfaces." },
  { id: "fingerprint", label: "Fingerprint", description: "Identify technologies, frameworks, TLS posture, and API surfaces." },
  { id: "enumerate", label: "Enumerate", description: "Find paths, parameters, scripts, secrets, CORS behavior, and storage exposure." },
  { id: "vuln_scan", label: "Vulnerability Scan", description: "Run active checks for injection, XSS, SSRF, JWT, OAuth, SSTI, XXE, and known CVEs." },
];

const modeDescriptions: Record<string, string> = {
  passive: "Passive avoids active fuzzing and favors low-noise discovery.",
  active: "Active enables scanners and probes that may send more requests.",
  stealth: "Stealth keeps the selected scope but uses conservative pacing where adapters support it.",
};

const runtimeHelp: Record<string, string> = {
  concurrency: "Maximum number of adapter tasks Nox may run at once.",
  perToolConcurrency: "Maximum concurrent runs of the same tool across targets.",
  timeout: "Per-tool timeout passed to adapters that support runtime overrides.",
  delay: "Delay before each tool execution, useful for pacing active scans.",
  rateLimit: "Operator label persisted with the run; adapters can use it as a policy hint.",
};

export function ScanBuilder() {
  const queryClient = useQueryClient();
  const { setSelectedSessionID } = useSessionContext();
  const toolsQuery = useQuery({ queryKey: ["tools"], queryFn: () => listTools() });
  const profilesQuery = useQuery({ queryKey: ["scan-profiles"], queryFn: listScanProfiles });
  const tools = toolsQuery.data ?? [];
  const [targets, setTargets] = useState("");
  const [sourcePath, setSourcePath] = useState("");
  const [name, setName] = useState("");
  const [mode, setMode] = useState("active");
  const [outOfScope, setOutOfScope] = useState("");
  const [selectedPhases, setSelectedPhases] = useState<string[]>([]);
  const [selectedTools, setSelectedTools] = useState<string[]>([]);
  const [llmBaseURL, setLLMBaseURL] = useState("");
  const [llmModel, setLLMModel] = useState("");
  const [concurrency, setConcurrency] = useState(4);
  const [perToolConcurrency, setPerToolConcurrency] = useState(1);
  const [timeout, setTimeout] = useState(60);
  const [delay, setDelay] = useState(0);
  const [rateLimit, setRateLimit] = useState("");
  const [evasionProfile, setEvasionProfile] = useState("normal");
  const [jitterMS, setJitterMS] = useState(0);
  const [proxyURL, setProxyURL] = useState("");
  const [adaptiveBackoff, setAdaptiveBackoff] = useState(false);
  const [params, setParams] = useState<Record<string, Record<string, unknown>>>({});
  const [selectedProfileID, setSelectedProfileID] = useState("");
  const [profileName, setProfileName] = useState("");
  const [llmStatus, setLLMStatus] = useState<"idle" | "checking" | "success" | "error">("idle");
  const [llmMessage, setLLMMessage] = useState("");
  const [configuredTool, setConfiguredTool] = useState<ToolRecord | null>(null);

  const selectedToolRecords = useMemo(() => tools.filter((tool) => selectedTools.includes(tool.id)), [selectedTools, tools]);
  const toolByID = useMemo(() => new Map(tools.map((tool) => [tool.id, tool])), [tools]);
  const installedSelectedTools = selectedToolRecords.filter((tool) => tool.installed);
  const selectedEnabledPhaseCount = selectedPhases.length;
  const parsedTargets = useMemo(() => splitTargets(targets), [targets]);
  const hasSource = sourcePath.trim() !== "";
  const hasTargets = targets.trim() !== "";
  const workloadMode = hasTargets && hasSource ? "combined" : hasSource ? "static" : "dynamic";
  const targetError = !hasTargets && !hasSource ? "Add at least one target or source repository." : hasTargets && parsedTargets.length === 0 ? "Enter valid http:// or https:// targets, separated by commas or new lines." : "";
  const phaseError = hasTargets && selectedEnabledPhaseCount === 0 ? "Select at least one scan phase." : "";
  const toolError = hasTargets && selectedTools.length === 0 ? "Select at least one tool." : hasTargets && installedSelectedTools.length === 0 ? "Select at least one installed or built-in tool." : "";
  const canStartBase = !targetError && !phaseError && !toolError;

  const mutation = useMutation({
    mutationFn: startScan,
    onSuccess: (record) => {
      queryClient.invalidateQueries({ queryKey: ["sessions"] });
      setSelectedSessionID(record.session.id);
    },
  });
  const createProfileMutation = useMutation({
    mutationFn: () => createScanProfile(buildCustomProfileRequest(profileName, currentRequest())),
    onSuccess: () => {
      setProfileName("");
      queryClient.invalidateQueries({ queryKey: ["scan-profiles"] });
    },
  });
  const deleteProfileMutation = useMutation({
    mutationFn: (profileID: string) => deleteScanProfile(profileID),
    onSuccess: () => {
      setSelectedProfileID("");
      queryClient.invalidateQueries({ queryKey: ["scan-profiles"] });
    },
  });
  const modelsMutation = useMutation({
    mutationFn: () => listLLMModels(llmBaseURL),
    onSuccess: (result) => {
      setLLMStatus("success");
      setLLMMessage(`${result.models.length} model${result.models.length === 1 ? "" : "s"} available.`);
      if (!llmModel && result.models.length > 0) {
        setLLMModel(result.models[0]);
      }
    },
    onMutate: () => {
      setLLMStatus("checking");
      setLLMMessage("Checking model endpoint.");
    },
    onError: () => {
      setLLMStatus("error");
      setLLMMessage("Could not connect to the model endpoint.");
    },
  });

  function togglePhase(phase: string) {
    setSelectedPhases((current) => {
      if (current.includes(phase)) {
        setSelectedTools((tools) => tools.filter((toolID) => toolByID.get(toolID)?.phase !== phase));
        return current.filter((item) => item !== phase);
      }
      return [...current, phase];
    });
  }

  function toggleTool(tool: ToolRecord) {
    if (!selectedPhases.includes(tool.phase)) {
      return;
    }
    setSelectedTools((current) => {
      if (current.includes(tool.id)) {
        return current.filter((item) => item !== tool.id);
      }
      const next = collectToolWithDependencies(tool.id, new Set(current));
      const neededPhases = [...next].map((toolID) => toolByID.get(toolID)?.phase).filter(Boolean) as string[];
      setSelectedPhases((phases) => [...new Set([...phases, ...neededPhases])]);
      return [...next];
    });
  }

  function collectToolWithDependencies(toolID: string, next: Set<string>) {
    const tool = toolByID.get(toolID);
    if (!tool || next.has(toolID)) {
      return next;
    }
    next.add(toolID);
    for (const depID of tool.depends_on) {
      collectToolWithDependencies(depID, next);
    }
    return next;
  }

  function setToolParam(toolID: string, name: string, value: unknown) {
    setParams((current) => ({ ...current, [toolID]: { ...(current[toolID] ?? {}), [name]: value } }));
  }

  function currentRequest(): StartScanRequest {
    return {
      target: parsedTargets.join("\n"),
      targets: parsedTargets,
      source_path: sourcePath.trim() || undefined,
      name,
      mode,
      out_of_scope: splitLines(outOfScope),
      enabled_phases: selectedPhases,
      tools: selectedTools,
      tool_parameters: cleanToolParameters(params),
      concurrency,
      per_tool_concurrency: perToolConcurrency,
      tool_timeout_seconds: timeout,
      tool_delay_ms: delay,
      rate_limit: rateLimit,
      evasion_profile: evasionProfile,
      jitter_ms: jitterMS,
      proxy_url: proxyURL,
      adaptive_backoff: adaptiveBackoff,
      llm_base_url: llmBaseURL,
      llm_model: llmModel,
    };
  }

  function applyProfile(profile: ScanProfile) {
    const request = profile.request;
    if (request.mode) {
      setMode(request.mode);
    }
    setSelectedPhases(request.enabled_phases ?? []);
    setSelectedTools(request.tools ?? []);
    setParams(request.tool_parameters ?? {});
    setConcurrency(request.concurrency ?? 4);
    setPerToolConcurrency(request.per_tool_concurrency ?? 1);
    setTimeout(request.tool_timeout_seconds ?? 60);
    setDelay(request.tool_delay_ms ?? 0);
    setRateLimit(request.rate_limit ?? "");
    setEvasionProfile(request.evasion_profile ?? "normal");
    setJitterMS(request.jitter_ms ?? 0);
    setProxyURL(request.proxy_url ?? "");
    setAdaptiveBackoff(Boolean(request.adaptive_backoff));
    setLLMBaseURL(request.llm_base_url ?? "");
    setLLMModel(request.llm_model ?? "");
    if (request.target || request.targets?.length) {
      setTargets(request.targets?.join("\n") ?? request.target ?? "");
    }
    setSourcePath(request.source_path ?? "");
  }

  function saveProfile() {
    if (!profileName.trim()) {
      return;
    }
    createProfileMutation.mutate();
  }

  function deleteSelectedProfile() {
    if (selectedProfile && !selectedProfile.builtIn) {
      deleteProfileMutation.mutate(selectedProfile.id);
    }
  }

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!canStartBase) {
      return;
    }
    mutation.mutate(currentRequest());
  }

  function exportProfiles() {
    const blob = new Blob([JSON.stringify(profilesQuery.data ?? [], null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = "scan-profiles.json";
    anchor.click();
    URL.revokeObjectURL(url);
  }

  async function importProfiles(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;
    const text = await file.text();
    const parsed = JSON.parse(text) as unknown;
    const records = Array.isArray(parsed) ? parsed : [parsed];
    await Promise.all(records.map((record) => {
      const item = record as { name?: string; description?: string; request?: StartScanRequest };
      if (!item.name || !item.request) return Promise.resolve();
      return createScanProfile({ name: item.name, description: item.description, request: item.request });
    }));
    queryClient.invalidateQueries({ queryKey: ["scan-profiles"] });
    event.target.value = "";
  }

  const profiles = allProfiles(profilesQuery.data ?? []);
  const selectedProfile = profiles.find((profile) => profile.id === selectedProfileID);
  const canStart = canStartBase && !mutation.isPending;
  const llmModels = modelsMutation.data?.models ?? [];

  return (
    <section className="page wide-page">
      <header className="page-header">
        <div>
          <h1>Scan Builder</h1>
          <p>Configure scope, phases, tools, runtime options, and per-scan parameters.</p>
        </div>
      </header>
      <form className="builder-workspace" onSubmit={submit}>
        <aside className="builder-rail" aria-label="Scan builder sections">
          {["Scope", "Profiles", "Runtime", "LLM", "Phases", "Tools", "Launch"].map((item) => <a key={item} href={`#${item.toLowerCase()}`}>{item}</a>)}
        </aside>
        <div className="builder-main">
        <section className="panel span-2" id="profiles">
          <h2>Profiles</h2>
          <div className="profile-bar">
            <label>Preset
              <select value={selectedProfileID} onChange={(event) => setSelectedProfileID(event.target.value)}>
                <option value="">Choose a profile</option>
                {profiles.map((profile) => <option key={profile.id} value={profile.id}>{profile.name}</option>)}
              </select>
            </label>
            <button className="secondary" type="button" disabled={!selectedProfile} onClick={() => selectedProfile && applyProfile(selectedProfile)}>Apply</button>
            <label>Save Current As
              <input value={profileName} onChange={(event) => setProfileName(event.target.value)} placeholder="Profile name" />
            </label>
            <button className="secondary" type="button" disabled={!profileName.trim() || createProfileMutation.isPending} onClick={saveProfile}><Save size={16} />Save</button>
            <button className="secondary" type="button" disabled={!selectedProfile || selectedProfile.builtIn || deleteProfileMutation.isPending} onClick={deleteSelectedProfile}><Trash2 size={16} />Delete</button>
            <button className="secondary" type="button" onClick={exportProfiles}><Download size={16} />Export</button>
            <label className="secondary file-button"><Upload size={16} />Import<input type="file" accept="application/json,.json" onChange={importProfiles} /></label>
          </div>
          {createProfileMutation.error ? <p className="error-text">{createProfileMutation.error.message}</p> : null}
          {selectedProfile ? <p className="profile-description">{selectedProfile.description}</p> : null}
        </section>
        <section className="panel" id="scope">
          <h2>Scope <span className={`origin-badge ${workloadMode === "combined" ? "both" : workloadMode === "static" ? "static" : "dynamic"}`}>{workloadMode}</span></h2>
          <div className="form-grid">
            <label className="span-2">Targets {sourcePath.trim() ? null : <Required />}<textarea value={targets} onChange={(event) => setTargets(event.target.value)} rows={4} placeholder={"https://example.com\nhttps://example.org"} required={!sourcePath.trim()} /></label>
            {targetError ? <p className="field-error span-2">{targetError}</p> : null}
            <label className="span-2">Source Repository <input value={sourcePath} onChange={(event) => setSourcePath(event.target.value)} placeholder="/path/to/repository" /></label>
            <label>Name<input value={name} onChange={(event) => setName(event.target.value)} placeholder="Engagement name" /></label>
            <label>Mode
              <span className="inline-help-control">
                <select value={mode} onChange={(event) => setMode(event.target.value)}><option value="passive">Passive</option><option value="active">Active</option><option value="stealth">Stealth</option></select>
                <InfoTip text={modeDescriptions[mode]} />
              </span>
            </label>
            <label>Out of Scope<textarea value={outOfScope} onChange={(event) => setOutOfScope(event.target.value)} rows={3} placeholder="one host or CIDR per line" /></label>
          </div>
        </section>
        <section className="panel" id="runtime">
          <h2>Runtime</h2>
          <div className="form-grid compact">
            <HelpLabel label="Concurrency" help={runtimeHelp.concurrency}><input type="number" min={1} value={concurrency} onChange={(event) => setConcurrency(Number(event.target.value))} /></HelpLabel>
            <HelpLabel label="Per Tool" help={runtimeHelp.perToolConcurrency}><input type="number" min={1} value={perToolConcurrency} onChange={(event) => setPerToolConcurrency(Number(event.target.value))} /></HelpLabel>
            <HelpLabel label="Timeout Seconds" help={runtimeHelp.timeout}><input type="number" min={0} value={timeout} onChange={(event) => setTimeout(Number(event.target.value))} /></HelpLabel>
            <HelpLabel label="Delay MS" help={runtimeHelp.delay}><input type="number" min={0} value={delay} onChange={(event) => setDelay(Number(event.target.value))} /></HelpLabel>
            <HelpLabel label="Rate Limit" help={runtimeHelp.rateLimit}><input value={rateLimit} onChange={(event) => setRateLimit(event.target.value)} placeholder="optional label" /></HelpLabel>
            <label>Evasion Profile
              <select value={evasionProfile} onChange={(event) => setEvasionProfile(event.target.value)}>
                <option value="normal">Normal</option>
                <option value="safe">Safe</option>
                <option value="stealth">Stealth</option>
                <option value="custom">Custom</option>
              </select>
            </label>
            <label>Jitter MS<input type="number" min={0} value={jitterMS} onChange={(event) => setJitterMS(Number(event.target.value))} /></label>
            <label>Proxy URL<input value={proxyURL} onChange={(event) => setProxyURL(event.target.value)} placeholder="http://127.0.0.1:8080" /></label>
            <label className="checkbox-row"><input type="checkbox" checked={adaptiveBackoff} onChange={(event) => setAdaptiveBackoff(event.target.checked)} />Adaptive backoff</label>
          </div>
        </section>
        <section className="panel" id="llm">
          <h2>LLM</h2>
          <div className="form-grid">
            <label>Base URL<input value={llmBaseURL} onChange={(event) => setLLMBaseURL(event.target.value)} placeholder="http://localhost:11434/v1" /></label>
            <label>Model
              {llmModels.length > 0 ? <select value={llmModel} onChange={(event) => setLLMModel(event.target.value)}>{llmModels.map((model) => <option key={model} value={model}>{model}</option>)}</select>
                : <input value={llmModel} onChange={(event) => setLLMModel(event.target.value)} placeholder="llama3:8b" />}
            </label>
          </div>
          <div className="llm-actions">
            <button className="secondary" type="button" disabled={!llmBaseURL.trim() || modelsMutation.isPending} onClick={() => modelsMutation.mutate()}>{modelsMutation.isPending ? "Checking" : "Check Connection"}</button>
            {llmStatus !== "idle" ? <span className={`llm-state ${llmStatus}`}>{llmStatus === "checking" ? <span className="spinner" /> : llmStatus === "success" ? <CheckCircle2 size={16} /> : <XCircle size={16} />}{llmMessage}</span> : null}
          </div>
        </section>
        <section className="panel span-2" id="phases">
          <h2>Phases {hasTargets ? <Required /> : null}</h2>
          <div className="phase-grid">
            {phases.map((phase) => (
              <label key={phase.id} className={`phase-option ${selectedPhases.includes(phase.id) ? "selected" : ""}`}>
                <input type="checkbox" checked={selectedPhases.includes(phase.id)} onChange={() => togglePhase(phase.id)} />
                <span><strong>{phase.label}</strong><small>{phase.description}</small></span>
              </label>
            ))}
          </div>
          {phaseError ? <p className="field-error">{phaseError}</p> : null}
        </section>
        <section className="panel span-2" id="tools">
          <h2>Tools {hasTargets ? <Required /> : null}</h2>
          <div className="tool-phase-grid">
            {phases.map((phase) => (
              <article key={phase.id} className={!selectedPhases.includes(phase.id) ? "disabled-tool-phase" : ""}>
                <h3>{phase.label}</h3>
                {tools.filter((tool) => tool.phase === phase.id).map((tool) => (
                  <div key={tool.id} className={`tool-check ${tool.installed ? tool.kind : "missing"} ${selectedTools.includes(tool.id) ? "selected" : ""}`}>
                    <label>
                      <input type="checkbox" disabled={!selectedPhases.includes(phase.id) || !tool.installed} checked={selectedTools.includes(tool.id)} onChange={() => toggleTool(tool)} />
                      {tool.installed ? <CheckCircle2 size={16} /> : <XCircle size={16} />}
                      <span className="tool-copy">
                        <span className="tool-name-row">
                          <strong className="tool-name" title={tool.id}>{tool.id}</strong>
                          <InfoTip text={`${tool.name}. ${tool.description || tool.install_hint}${tool.homepage_url ? ` ${tool.homepage_url}` : ""}`} />
                        </span>
                        <small>{toolStatus(tool)}</small>
                      </span>
                    </label>
                    <button className="icon-button tool-config-button" type="button" disabled={!selectedPhases.includes(phase.id) || tool.parameters.length === 0} onClick={() => setConfiguredTool(tool)} aria-label={`Configure ${tool.id}`} title={tool.parameters.length === 0 ? "No configurable parameters" : `Configure ${tool.id}`}><Settings size={16} /></button>
                  </div>
                ))}
              </article>
            ))}
          </div>
          {toolError ? <p className="field-error">{toolError}</p> : null}
          <p className="profile-description">Selecting a tool automatically selects required dependency tools when available.</p>
        </section>
        <section className="panel span-2 action-panel launch-panel" id="launch">
          <div className="launch-summary">
            <span className={`origin-badge ${workloadMode === "combined" ? "both" : workloadMode === "static" ? "static" : "dynamic"}`}>{workloadMode}</span>
            <span>{parsedTargets.length} target{parsedTargets.length === 1 ? "" : "s"}</span>
            <span>{selectedTools.length} tool{selectedTools.length === 1 ? "" : "s"}</span>
            <span>{selectedPhases.length} phase{selectedPhases.length === 1 ? "" : "s"}</span>
            {targetError || phaseError || toolError ? <strong>{targetError || phaseError || toolError}</strong> : <strong>Ready to launch with scope validation.</strong>}
          </div>
          {mutation.error ? <p className="error-text">{mutation.error.message}</p> : null}
          <button className="primary" type="submit" disabled={!canStart}><Play size={16} />{mutation.isPending ? "Starting" : "Start Scan"}</button>
          <span><ShieldCheck size={16} /> {workloadMode === "combined" ? "Combined mode runs audit first, then source-aware dynamic adapters in one session." : workloadMode === "static" ? "Static audit runs without executing repository code." : "Scope validation is enforced before adapters run."}</span>
        </section>
        </div>
      </form>
      {configuredTool ? (
        <div className="modal-backdrop" role="dialog" aria-modal="true">
          <div className="modal">
            <header><h2>Configure {configuredTool.id}</h2><button className="icon-button" type="button" onClick={() => setConfiguredTool(null)}>×</button></header>
            <ToolParameters tool={configuredTool} values={params[configuredTool.id] ?? {}} onChange={(name, value) => setToolParam(configuredTool.id, name, value)} />
            <footer><button className="primary" type="button" onClick={() => setConfiguredTool(null)}>Save</button></footer>
          </div>
        </div>
      ) : null}
    </section>
  );
}

function ToolParameters({ tool, values, onChange }: { tool: ToolRecord; values: Record<string, unknown>; onChange: (name: string, value: unknown) => void }) {
  return (
    <article className="parameter-card">
      <h3>{tool.id}</h3>
      {tool.parameters.map((param) => (
        <label key={param.name}>{param.label}
          {param.type === "enum" ? <select value={String(values[param.name] ?? "")} onChange={(event) => onChange(param.name, event.target.value)}><option value="">Default</option>{(param.options ?? []).map((option) => <option key={option} value={option}>{option}</option>)}</select>
            : param.type === "boolean" ? <input type="checkbox" checked={Boolean(values[param.name])} onChange={(event) => onChange(param.name, event.target.checked)} />
              : <input value={Array.isArray(values[param.name]) ? (values[param.name] as string[]).join(" ") : String(values[param.name] ?? "")} type={param.type === "number" ? "number" : "text"} onChange={(event) => onChange(param.name, param.type === "number" ? Number(event.target.value) : param.type === "list" ? splitArgs(event.target.value) : event.target.value)} />}
        </label>
      ))}
      {tool.parameters.length === 0 ? <p className="empty-line">No configurable parameters for this tool.</p> : null}
    </article>
  );
}

function HelpLabel({ label, help, children }: { label: string; help: string; children: ReactNode }) {
  return (
    <label>{label}
      <span className="inline-help-control">
        {children}
        <InfoTip text={help} />
      </span>
    </label>
  );
}

function InfoTip({ text }: { text: string }) {
  return <span className="info-tip" aria-label={text}><CircleHelp size={16} /><span className="tooltip">{text}</span></span>;
}

function toolStatus(tool: ToolRecord) {
  if (!tool.installed) {
    return "not installed";
  }
  if (tool.kind === "builtin_http") {
    return "built-in";
  }
  return "installed";
}

function Required() {
  return <span className="required-mark">Required</span>;
}

function splitTargets(value: string) {
  return [...new Set(value.split(/[\n,]+/).map((item) => item.trim()).filter((item) => /^https?:\/\/[^/\s]+/i.test(item)))];
}
