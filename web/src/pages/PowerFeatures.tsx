import { useMemo, useState } from "react";
import type React from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, CircleAlert, CircleDashed, FlaskConical, KeyRound, Network, PlugZap, Radar, ShieldAlert, Sparkles } from "lucide-react";
import { effectiveConfig, generatePayloads, getBurpStatus, listADEntities, listADRelationships, listBlockEvents, listCredentials, listFindings, listOSINT, listPayloads, listPoCResults, listPowerCallbacks, listProviderStatuses, pullBurpIssues, pushBurpScope, runADKerberoast, runOSINT, runPoC, testCredentials, validatePayload, type BlockEvent, type BurpStatusResponse, type CredentialFinding, type Payload, type PowerCallback, type ProviderStatus } from "../api/client";
import { useSessionContext } from "../session";

const tabs = ["payloads", "credentials", "osint", "ad", "poc", "callbacks", "burp", "evasion"] as const;
type PowerTab = (typeof tabs)[number];
type ActiveActionKind = "credential" | "poc" | "payload_validation" | "osint" | "kerberoast" | "burp_push" | "burp_pull";

const operationGroups: { title: string; tabs: PowerTab[] }[] = [
  { title: "Payload Operations", tabs: ["payloads"] },
  { title: "Credential Operations", tabs: ["credentials"] },
  { title: "OSINT", tabs: ["osint"] },
  { title: "AD/BloodHound", tabs: ["ad"] },
  { title: "PoC", tabs: ["poc", "callbacks"] },
  { title: "Burp Integration", tabs: ["burp"] },
  { title: "Request Behavior", tabs: ["evasion"] },
];
const featureCopy: Record<(typeof tabs)[number], { label: string; title: string; description: string }> = {
  payloads: {
    label: "Payloads",
    title: "Payload Generation",
    description: "Generate context-aware payload candidates from a finding, then validate only safe marker-based classes when active validation is enabled.",
  },
  credentials: {
    label: "Credentials",
    title: "Credential Testing",
    description: "Run fixture-safe default checks or correlate credential evidence while preserving redaction and lockout-aware limits.",
  },
  osint: {
    label: "OSINT",
    title: "OSINT Expansion",
    description: "Query configured passive providers, record skipped-provider status when keys are absent, and keep discovered assets scoped.",
  },
  ad: {
    label: "Active Directory",
    title: "Active Directory Review",
    description: "Record safe AD/internal network evidence, relationships, relay-risk context, and gated Kerberoast requests without cracking hashes.",
  },
  poc: {
    label: "PoC Evidence",
    title: "PoC Evidence",
    description: "Create non-destructive proof records for supported safe classes and link impact evidence back to findings and callbacks.",
  },
  callbacks: {
    label: "Callbacks",
    title: "Callback Evidence",
    description: "Track callback tokens and received events for SSRF, XXE, and redirect validation without exfiltrating sensitive data.",
  },
  burp: {
    label: "Burp Sync",
    title: "Burp Integration",
    description: "Check Burp REST availability, push scoped targets, and pull imported issues when a Burp provider is configured.",
  },
  evasion: {
    label: "Request Behavior",
    title: "Request Behavior",
    description: "Review block and adaptive-backoff events created by paced or proxied scanner actions.",
  },
};

export function PowerFeatures() {
  const queryClient = useQueryClient();
  const { selectedSessionID } = useSessionContext();
  const [tab, setTab] = useState<(typeof tabs)[number]>("payloads");
  const [findingID, setFindingID] = useState("");
  const [credentialURL, setCredentialURL] = useState("");
  const [credentialUser, setCredentialUser] = useState("admin");
  const [credentialPass, setCredentialPass] = useState("password");
  const [providers, setProviders] = useState("github,shodan,securitytrails");
  const [kerberoastSPN, setKerberoastSPN] = useState("");
  const [pendingAction, setPendingAction] = useState<ActiveActionKind | null>(null);
  const [pendingPayloadID, setPendingPayloadID] = useState("");
  const [blockTypeFilter, setBlockTypeFilter] = useState("all");
  const [blockTimeRange, setBlockTimeRange] = useState("all");
  const enabled = Boolean(selectedSessionID);
  const findingsQuery = useQuery({ queryKey: ["findings", selectedSessionID], queryFn: () => listFindings(selectedSessionID), enabled });
  const payloadsQuery = useQuery({ queryKey: ["payloads", selectedSessionID], queryFn: () => listPayloads(selectedSessionID), enabled });
  const credentialsQuery = useQuery({ queryKey: ["credentials", selectedSessionID], queryFn: () => listCredentials(selectedSessionID), enabled });
  const osintQuery = useQuery({ queryKey: ["osint", selectedSessionID], queryFn: () => listOSINT(selectedSessionID), enabled });
  const providersQuery = useQuery({ queryKey: ["provider-statuses", selectedSessionID], queryFn: () => listProviderStatuses(selectedSessionID), enabled });
  const adQuery = useQuery({ queryKey: ["ad-entities", selectedSessionID], queryFn: () => listADEntities(selectedSessionID), enabled });
  const adRelationshipsQuery = useQuery({ queryKey: ["ad-relationships", selectedSessionID], queryFn: () => listADRelationships(selectedSessionID), enabled });
  const pocQuery = useQuery({ queryKey: ["poc-results", selectedSessionID], queryFn: () => listPoCResults(selectedSessionID), enabled });
  const callbacksQuery = useQuery({ queryKey: ["callbacks", selectedSessionID], queryFn: () => listPowerCallbacks(selectedSessionID), enabled });
  const blockQuery = useQuery({ queryKey: ["block-events", selectedSessionID], queryFn: () => listBlockEvents(selectedSessionID), enabled });
  const configQuery = useQuery({ queryKey: ["effective-config"], queryFn: effectiveConfig });
  const powerConfig = powerState(configQuery.data?.power);
  const providerStrip = useMemo(() => providerStatusStrip(providersQuery.data ?? []), [providersQuery.data]);
  const filteredBlocks = useMemo(() => filterBlockEvents(blockQuery.data ?? [], blockTypeFilter, blockTimeRange, new Date()), [blockQuery.data, blockTimeRange, blockTypeFilter]);
  const activeReview = activeActionReview(pendingAction, {
    findingID: findingID || findingsQuery.data?.[0]?.id || "",
    credentialURL,
    credentialUser,
    credentialPass,
    providers,
    kerberoastSPN,
    powerConfig,
  });
  const generateMutation = useMutation({
    mutationFn: () => generatePayloads(selectedSessionID, findingID || findingsQuery.data?.[0]?.id || ""),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["payloads", selectedSessionID] }),
  });
  const validateMutation = useMutation({
    mutationFn: (payloadID: string) => validatePayload(selectedSessionID, payloadID, true),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["payloads", selectedSessionID] }),
  });
  const credMutation = useMutation({
    mutationFn: () => testCredentials(selectedSessionID, { mode: credentialURL ? "defaults" : "correlate", username: credentialUser, password: credentialPass, url: credentialURL, confirm: Boolean(credentialURL), max_attempts: 3 }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["credentials", selectedSessionID] }),
  });
  const osintMutation = useMutation({
    mutationFn: () => runOSINT(selectedSessionID, providers.split(",").map((provider) => provider.trim()).filter(Boolean)),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["osint", selectedSessionID] });
      queryClient.invalidateQueries({ queryKey: ["provider-statuses", selectedSessionID] });
    },
  });
  const pocMutation = useMutation({
    mutationFn: () => runPoC(selectedSessionID, findingID || findingsQuery.data?.[0]?.id || "", true),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["poc-results", selectedSessionID] });
      queryClient.invalidateQueries({ queryKey: ["callbacks", selectedSessionID] });
    },
  });
  const kerberoastMutation = useMutation({
    mutationFn: () => runADKerberoast(selectedSessionID, { spn: kerberoastSPN, confirm: true }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["ad-entities", selectedSessionID] }),
  });
  const burpStatusMutation = useMutation({ mutationFn: () => getBurpStatus(selectedSessionID) });
  const burpPushMutation = useMutation({ mutationFn: () => pushBurpScope(selectedSessionID) });
  const burpPullMutation = useMutation({
    mutationFn: () => pullBurpIssues(selectedSessionID),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["findings", selectedSessionID] }),
  });
  const featureStatus = [
    { label: "Payloads", value: payloadsQuery.data?.length ?? 0, detail: "generated candidates" },
    { label: "Credentials", value: credentialsQuery.data?.length ?? 0, detail: "stored records" },
    { label: "Callbacks", value: callbacksQuery.data?.length ?? 0, detail: "evidence events" },
    { label: "PoC", value: pocQuery.data?.length ?? 0, detail: "proof records" },
    { label: "Providers", value: providersQuery.data?.length ?? 0, detail: "passive statuses" },
  ];
  const runReviewedAction = () => {
    const action = pendingAction;
    setPendingAction(null);
    if (action === "credential") {
      credMutation.mutate();
    } else if (action === "poc") {
      pocMutation.mutate();
    } else if (action === "payload_validation" && pendingPayloadID) {
      validateMutation.mutate(pendingPayloadID);
      setPendingPayloadID("");
    } else if (action === "osint") {
      osintMutation.mutate();
    } else if (action === "kerberoast") {
      kerberoastMutation.mutate();
    } else if (action === "burp_push") {
      burpPushMutation.mutate();
    } else if (action === "burp_pull") {
      burpPullMutation.mutate();
    }
  };

  return (
    <section className="page power-page">
      <header className="page-header">
        <div>
          <h1>Power Features</h1>
          <p>Operator-triggered advanced modules. Active actions stay explicit and API-key protected.</p>
        </div>
      </header>
      {!selectedSessionID ? <section className="empty-state">Select a session to inspect power-feature records.</section> : null}
      <ProviderStatusStrip statuses={providerStrip} />
      <OperationGroups activeTab={tab} onSelect={setTab} />
      <section className="power-summary-grid" aria-label="Power feature status">
        {featureStatus.map((item) => (
          <article key={item.label}>
            <span>{item.label}</span>
            <strong>{item.value}</strong>
            <small>{item.detail}</small>
          </article>
        ))}
      </section>
      <section className="panel safety-panel">
        <div className="safety-heading">
          <h2><ShieldAlert size={18} />Safety Controls</h2>
          <span className={`status ${powerConfig.activeValidation ? "completed" : "paused"}`}>{powerConfig.activeValidation ? "active validation enabled" : "active validation disabled"}</span>
        </div>
        <div className="safety-grid">
          <span><strong>{powerConfig.maxAttempts}</strong><small>credential attempts per user</small></span>
          <span><strong>{powerConfig.callbackProvider}</strong><small>callback provider</small></span>
          <span><strong>redacted</strong><small>provider secrets and credential material</small></span>
        </div>
        <p className="warning-text">Active validation, credential checks, AD requests, and Burp sync remain manual, scope-checked actions. Server-side API-key enforcement still applies.</p>
      </section>
      {activeReview ? <ActiveActionReviewPanel review={activeReview} onCancel={() => { setPendingAction(null); setPendingPayloadID(""); }} onConfirm={runReviewedAction} /> : null}
      <section className="panel">
        {tab === "payloads" ? (
          <FeatureSection icon={<Sparkles size={17} />} title={featureCopy.payloads.title} description={featureCopy.payloads.description} action={<ActionControls value={findingID} onChange={setFindingID} onRun={() => generateMutation.mutate()} label="Generate" disabled={!enabled || generateMutation.isPending} />}>
            <RecordTable rows={payloadRows(payloadsQuery.data ?? [])} headers={["Type", "Payload", "State", "Bypass", "Confidence", "Action"]} actions={(payloadsQuery.data ?? []).map((item) => item.validated ? null : <button className="secondary" title={powerConfig.activeValidation ? "Review this safe marker validation before it runs" : "Enable power.active_validation.enabled before validation"} onClick={() => { setPendingPayloadID(item.id); setPendingAction("payload_validation"); }} disabled={validateMutation.isPending || !powerConfig.activeValidation}>Review</button>)} />
          </FeatureSection>
        ) : null}
        {tab === "credentials" ? (
          <FeatureSection icon={<KeyRound size={17} />} title={featureCopy.credentials.title} description={featureCopy.credentials.description} action={<div className="action-row power-credential-controls"><input value={credentialURL} onChange={(event) => setCredentialURL(event.target.value)} placeholder="Login URL for confirmed checks" /><input value={credentialUser} onChange={(event) => setCredentialUser(event.target.value)} placeholder="Username" /><input value={credentialPass} onChange={(event) => setCredentialPass(event.target.value)} placeholder="Password" /><button className="primary" onClick={() => setPendingAction("credential")} disabled={!enabled || credMutation.isPending}>Review Run</button></div>}>
            <RecordTable rows={credentialRows(credentialsQuery.data ?? [])} headers={["Type", "Username", "Password", "Status", "Evidence"]} />
          </FeatureSection>
        ) : null}
        {tab === "osint" ? (
          <FeatureSection icon={<Radar size={17} />} title={featureCopy.osint.title} description={featureCopy.osint.description} action={<div className="action-row"><input value={providers} onChange={(event) => setProviders(event.target.value)} placeholder="Providers" /><button className="primary" onClick={() => setPendingAction("osint")} disabled={!enabled || osintMutation.isPending}>Review Providers</button></div>}>
            <RecordTable rows={providerStatusRows(providersQuery.data ?? [])} headers={["Provider", "Module", "Status", "Message"]} />
            <RecordTable rows={(osintQuery.data ?? []).map((item) => [item.kind, item.value, item.source, `${Math.round(item.confidence * 100)}%`])} headers={["Kind", "Value", "Source", "Confidence"]} />
          </FeatureSection>
        ) : null}
        {tab === "ad" ? (
          <FeatureSection icon={<Network size={17} />} title={featureCopy.ad.title} description={featureCopy.ad.description} action={<div className="action-row"><input value={kerberoastSPN} onChange={(event) => setKerberoastSPN(event.target.value)} placeholder="Optional SPN to record" /><button className="primary" onClick={() => setPendingAction("kerberoast")} disabled={!enabled || kerberoastMutation.isPending}>Review Kerberoast Request</button></div>}>
            <RecordTable rows={(adQuery.data ?? []).map((item) => [item.entity_type, item.name, item.domain, item.sid || "-"])} headers={["Type", "Name", "Domain", "SID"]} />
            <p className="empty-line">{adRelationshipsQuery.data?.length ?? 0} AD relationship records</p>
          </FeatureSection>
        ) : null}
        {tab === "poc" ? (
          <FeatureSection icon={<FlaskConical size={17} />} title={featureCopy.poc.title} description={featureCopy.poc.description} action={<ActionControls value={findingID} onChange={setFindingID} onRun={() => setPendingAction("poc")} label="Review PoC" disabled={!enabled || pocMutation.isPending} />}>
            <RecordTable rows={(pocQuery.data ?? []).map((item) => [item.poc_type, item.status, item.evidence, item.impact_narrative])} headers={["Type", "Status", "Evidence", "Impact"]} />
          </FeatureSection>
        ) : null}
        {tab === "callbacks" ? (
          <FeatureSection icon={<PlugZap size={17} />} title={featureCopy.callbacks.title} description={featureCopy.callbacks.description}>
            <RecordTable rows={callbackRows(callbacksQuery.data ?? [])} headers={["Provider", "Status", "URL", "Source", "Event"]} />
          </FeatureSection>
        ) : null}
        {tab === "burp" ? (
          <FeatureSection icon={<PlugZap size={17} />} title={featureCopy.burp.title} description={featureCopy.burp.description} action={<div className="action-row"><button className="secondary" onClick={() => burpStatusMutation.mutate()} disabled={!enabled || burpStatusMutation.isPending}>Status</button><button className="secondary" onClick={() => setPendingAction("burp_push")} disabled={!enabled || burpPushMutation.isPending}>Review Push Scope</button><button className="primary" onClick={() => setPendingAction("burp_pull")} disabled={!enabled || burpPullMutation.isPending}>Review Pull Issues</button></div>}>
            <RecordTable rows={[burpResultRow(burpStatusMutation.data, burpPushMutation.data?.message, burpPushMutation.data?.available, burpPullMutation.data?.length)]} headers={["Status", "Message"]} />
          </FeatureSection>
        ) : null}
        {tab === "evasion" ? (
          <FeatureSection icon={<ShieldAlert size={17} />} title={featureCopy.evasion.title} description={featureCopy.evasion.description}>
            <div className="filter-bar evasion-filter-bar">
              <label>Type
                <select value={blockTypeFilter} onChange={(event) => setBlockTypeFilter(event.target.value)}>
                  <option value="all">All</option>
                  <option value="waf">WAF block</option>
                  <option value="rate_limit">Rate limit</option>
                  <option value="http_error">HTTP error</option>
                </select>
              </label>
              <label>Time Range
                <select value={blockTimeRange} onChange={(event) => setBlockTimeRange(event.target.value)}>
                  <option value="all">All time</option>
                  <option value="24h">Last 24h</option>
                  <option value="7d">Last 7 days</option>
                </select>
              </label>
              <span>{filteredBlocks.length} visible events</span>
            </div>
            <RecordTable rows={filteredBlocks.map((item) => [blockEventType(item), item.tool_id || "-", item.status_code.toString(), item.signal, item.backoff_ms.toString()])} headers={["Type", "Tool", "Status", "Signal", "Backoff ms"]} />
          </FeatureSection>
        ) : null}
      </section>
    </section>
  );
}

export function powerState(power: Record<string, unknown> | undefined) {
  const activeValidation = Boolean((power?.active_validation as { enabled?: boolean } | undefined)?.enabled);
  const credentials = power?.credentials as { max_attempts_per_user?: number } | undefined;
  const callbacks = power?.callbacks as { provider?: string } | undefined;
  return {
    activeValidation,
    maxAttempts: credentials?.max_attempts_per_user ?? 3,
    callbackProvider: callbacks?.provider || "builtin",
  };
}

type ProviderStripStatus = {
  provider: string;
  state: "available" | "unconfigured" | "error";
  message: string;
};

type ActiveActionReview = {
  title: string;
  impact: string;
  rows: [string, string][];
};

function ProviderStatusStrip({ statuses }: { statuses: ProviderStripStatus[] }) {
  const icons = {
    available: <CheckCircle2 size={16} />,
    unconfigured: <CircleDashed size={16} />,
    error: <CircleAlert size={16} />,
  };
  return (
    <section className="provider-status-strip" aria-label="Provider status">
      <h2>Provider Status</h2>
      {statuses.map((item) => (
        <article className={item.state} key={item.provider}>
          {icons[item.state]}
          <div>
            <strong>{item.provider}</strong>
            <small>{item.state === "available" ? "available" : item.state}</small>
          </div>
          <span>{item.message}</span>
        </article>
      ))}
    </section>
  );
}

function OperationGroups({ activeTab, onSelect }: { activeTab: PowerTab; onSelect: (tab: PowerTab) => void }) {
  return (
    <section className="power-operation-groups" aria-label="Power feature groups">
      {operationGroups.map((group) => (
        <article key={group.title}>
          <h2>{group.title}</h2>
          <div>
            {group.tabs.map((item) => <button key={item} className={activeTab === item ? "primary" : "secondary"} onClick={() => onSelect(item)}>{featureCopy[item].label}</button>)}
          </div>
        </article>
      ))}
    </section>
  );
}

function ActiveActionReviewPanel({ review, onCancel, onConfirm }: { review: ActiveActionReview; onCancel: () => void; onConfirm: () => void }) {
  return (
    <section className="panel active-action-review" aria-label="Active action review">
      <div className="safety-heading">
        <h2><ShieldAlert size={18} />{review.title}</h2>
        <span className="status running">review required</span>
      </div>
      <dl>
        {review.rows.map(([label, value]) => (
          <span key={label}>
            <dt>{label}</dt>
            <dd>{value}</dd>
          </span>
        ))}
      </dl>
      <p>{review.impact}</p>
      <div className="action-row">
        <button className="secondary" onClick={onCancel}>Cancel</button>
        <button className="primary" onClick={onConfirm}>Confirm Reviewed Action</button>
      </div>
    </section>
  );
}

export function providerStatusStrip(statuses: ProviderStatus[]): ProviderStripStatus[] {
  return ["github", "shodan", "securitytrails"].map((provider) => {
    const latest = statuses.find((item) => item.provider.toLowerCase() === provider);
    if (!latest) {
      return { provider, state: "unconfigured", message: "No provider status recorded" };
    }
    if (latest.status === "ok" || latest.status === "configured") {
      return { provider, state: "available", message: latest.message || latest.module };
    }
    if (latest.status === "error") {
      return { provider, state: "error", message: latest.message || "Provider returned an error" };
    }
    return { provider, state: "unconfigured", message: latest.message || "Missing token or disabled provider" };
  });
}

export function activeActionReview(kind: ActiveActionKind | null, context: {
  findingID: string;
  credentialURL: string;
  credentialUser: string;
  credentialPass: string;
  providers: string;
  kerberoastSPN: string;
  powerConfig: ReturnType<typeof powerState>;
}): ActiveActionReview | null {
  if (!kind) {
    return null;
  }
  if (kind === "credential") {
    const active = Boolean(context.credentialURL.trim());
    return {
      title: "Credential Check Review",
      impact: active ? "Potential impact: this can submit login attempts to the target and may contribute to account lockout or alerting." : "Potential impact: correlate mode records candidate evidence only and does not attempt a login.",
      rows: [
        ["Target", active ? context.credentialURL : "No target URL; correlate stored evidence"],
        ["Scope", active ? "Scoped HTTP login check" : "Passive correlation"],
        ["Username", context.credentialUser || "-"],
        ["Password Display", credentialDisplaySecret(context.credentialPass)],
        ["Max Attempts", String(context.powerConfig.maxAttempts)],
      ],
    };
  }
  if (kind === "poc") {
    return {
      title: "PoC Evidence Review",
      impact: "Potential impact: active PoC validation can send a marker request and may create an outbound callback event for SSRF, XXE, or redirect evidence.",
      rows: [
        ["Finding", context.findingID || "First finding in session"],
        ["Active Validation", context.powerConfig.activeValidation ? "Enabled" : "Disabled server-side"],
        ["Callback Provider", context.powerConfig.callbackProvider],
        ["Scope", "Persisted finding URL is re-checked before the marker request"],
      ],
    };
  }
  if (kind === "payload_validation") {
    return {
      title: "Payload Validation Review",
      impact: "Potential impact: sends a safe marker validation request only when active validation is enabled.",
      rows: [
        ["Payload", "Selected payload row"],
        ["Active Validation", context.powerConfig.activeValidation ? "Enabled" : "Disabled server-side"],
        ["Scope", "Session scope and redirect boundaries apply"],
      ],
    };
  }
  if (kind === "osint") {
    return {
      title: "OSINT Provider Review",
      impact: "Potential impact: passive provider queries may consume API quota and disclose the searched domain to configured third-party providers.",
      rows: [
        ["Providers", context.providers || "Configured default providers"],
        ["Mode", "Passive collection"],
        ["Scope", "Discovered assets are recorded for operator review"],
      ],
    };
  }
  if (kind === "kerberoast") {
    return {
      title: "Kerberoast Request Review",
      impact: "Potential impact: records an operator-requested AD review artifact. Nyx does not crack hashes in this action.",
      rows: [
        ["SPN", context.kerberoastSPN || "Not specified"],
        ["Mode", "Record request only"],
        ["Scope", "Selected session AD evidence"],
      ],
    };
  }
  if (kind === "burp_push") {
    return {
      title: "Burp Scope Push Review",
      impact: "Potential impact: sends the selected session scope to configured Burp REST. Burp endpoints remain loopback or allowlist constrained.",
      rows: [
        ["Target", "Configured Burp REST endpoint"],
        ["Data", "Session target URLs only"],
        ["Scope", "Selected session"],
      ],
    };
  }
  return {
    title: "Burp Issue Pull Review",
    impact: "Potential impact: imports in-scope Burp issues into the selected session and may change triage evidence.",
    rows: [
      ["Target", "Configured Burp REST endpoint"],
      ["Data", "In-scope issue records"],
      ["Scope", "Out-of-scope issue hosts are skipped"],
    ],
  };
}

export function payloadRows(payloads: Payload[]) {
  return payloads.map((item) => [item.payload_type, item.payload, item.validated ? "validated" : "unvalidated", item.bypass_technique || "-", `${Math.round(item.confidence * 100)}%`, item.validated ? item.validated_response || "validated" : "validate"]);
}

export function credentialRows(credentials: CredentialFinding[]) {
  return credentials.map((item) => [item.credential_type, item.username, credentialDisplaySecret(item.password), credentialState(item), item.evidence]);
}

export function credentialDisplaySecret(value: string) {
  if (!value || value === "********" || value === "[REDACTED]") {
    return value ? "[REDACTED]" : "-";
  }
  if (value.length <= 4) {
    return "[REDACTED]";
  }
  return `[REDACTED] ending ${value.slice(-4)}`;
}

export function credentialState(item: CredentialFinding) {
  if (item.lockout_detected) {
    return "lockout detected";
  }
  return item.valid ? "valid" : "unconfirmed";
}

export function providerStatusRows(statuses: ProviderStatus[]) {
  return statuses.map((item) => [item.provider, item.module, item.status, item.message]);
}

export function callbackRows(callbacks: PowerCallback[]) {
  return callbacks.map((item) => [item.provider, item.received ? "received" : "pending", item.url, item.source_ip || "-", redactedCallbackEvent(item.raw_event ?? "") || "-"]);
}

export function redactedCallbackEvent(value: string) {
  const redacted = value
    .replace(/(authorization\s*:\s*bearer\s+)[^\s\r\n]+/gi, "$1[redacted]")
    .replace(/(cookie\s*:\s*)[^\r\n]+/gi, "$1[redacted]")
    .replace(/((?:api[_-]?key|token|secret|password)=)[^&\s]+/gi, "$1[redacted]");
  return redacted.length > 300 ? `${redacted.slice(0, 300)}\n...[truncated]` : redacted;
}

export function burpResultRow(status?: BurpStatusResponse, pushMessage = "", pushAvailable = false, importedCount = 0) {
  if (status) {
    return [status.available ? "available" : "unavailable", status.result.message];
  }
  if (pushMessage) {
    return [pushAvailable ? "available" : "unavailable", pushMessage];
  }
  return ["idle", `${importedCount} imported issues`];
}

export function powerFeatureLabel(tab: (typeof tabs)[number]) {
  return featureCopy[tab].label;
}

export function blockEventType(event: BlockEvent) {
  const signal = event.signal.toLowerCase();
  if (signal.includes("waf") || event.status_code === 403 || event.status_code === 406) {
    return "WAF block";
  }
  if (signal.includes("rate") || event.status_code === 429 || event.backoff_ms > 0) {
    return "Rate limit";
  }
  return "HTTP error";
}

export function filterBlockEvents(events: BlockEvent[], typeFilter: string, timeRange: string, now: Date) {
  const minimumTime = blockEventMinimumTime(timeRange, now);
  return events.filter((event) => {
    if (typeFilter !== "all" && blockEventType(event).toLowerCase().replace(/\s+/g, "_") !== typeFilter) {
      return false;
    }
    if (minimumTime && new Date(event.created_at).getTime() < minimumTime.getTime()) {
      return false;
    }
    return true;
  });
}

function blockEventMinimumTime(timeRange: string, now: Date) {
  if (timeRange === "24h") {
    return new Date(now.getTime() - 24 * 60 * 60 * 1000);
  }
  if (timeRange === "7d") {
    return new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
  }
  return null;
}

function FeatureSection({ icon, title, description, action, children }: { icon: React.ReactNode; title: string; description: string; action?: React.ReactNode; children: React.ReactNode }) {
  return (
    <div className="pipeline">
      <div className="action-panel">
        <div className="feature-heading">
          <h2>{icon}{title}</h2>
          <p>{description}</p>
        </div>
        {action}
      </div>
      {children}
    </div>
  );
}

function ActionControls({ value, onChange, onRun, label, disabled }: { value: string; onChange: (value: string) => void; onRun: () => void; label: string; disabled?: boolean }) {
  return (
    <div className="action-row">
      <input value={value} onChange={(event) => onChange(event.target.value)} placeholder="Finding ID (defaults to first)" />
      <button className="primary" onClick={onRun} disabled={disabled}>{label}</button>
    </div>
  );
}

function RecordTable({ headers, rows, actions }: { headers: string[]; rows: string[][]; actions?: (React.ReactNode | null)[] }) {
  return (
    <div className="table-wrap">
      <table>
        <thead><tr>{headers.map((header) => <th key={header}>{header}</th>)}</tr></thead>
        <tbody>
          {rows.map((row, index) => <tr key={index}>{row.map((cell, cellIndex) => <td key={cellIndex}>{actions?.[index] && cellIndex === row.length - 1 ? actions[index] : <code>{cell}</code>}</td>)}</tr>)}
        </tbody>
      </table>
      {rows.length === 0 ? <p className="empty-line">No records yet</p> : null}
    </div>
  );
}
