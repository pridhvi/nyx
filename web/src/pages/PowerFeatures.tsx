import { useState } from "react";
import type React from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { FlaskConical, KeyRound, Network, PlugZap, Radar, ShieldAlert, Sparkles } from "lucide-react";
import { effectiveConfig, generatePayloads, getBurpStatus, listADEntities, listADRelationships, listBlockEvents, listCredentials, listFindings, listOSINT, listPayloads, listPoCResults, listPowerCallbacks, listProviderStatuses, pullBurpIssues, pushBurpScope, runADKerberoast, runOSINT, runPoC, testCredentials, validatePayload, type BurpStatusResponse, type CredentialFinding, type Payload, type PowerCallback, type ProviderStatus } from "../api/client";
import { useSessionContext } from "../session";

const tabs = ["payloads", "credentials", "osint", "ad", "poc", "callbacks", "burp", "evasion"] as const;
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

  return (
    <section className="page power-page">
      <header className="page-header">
        <div>
          <h1>Power Features</h1>
          <p>Operator-triggered advanced modules. Active actions stay explicit and API-key protected.</p>
        </div>
      </header>
      {!selectedSessionID ? <section className="empty-state">Select a session to inspect power-feature records.</section> : null}
      <div className="target-strip">
        {tabs.map((item) => <button key={item} className={tab === item ? "primary" : "secondary"} onClick={() => setTab(item)}>{featureCopy[item].label}</button>)}
      </div>
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
      <section className="panel">
        {tab === "payloads" ? (
          <FeatureSection icon={<Sparkles size={17} />} title={featureCopy.payloads.title} description={featureCopy.payloads.description} action={<ActionControls value={findingID} onChange={setFindingID} onRun={() => generateMutation.mutate()} label="Generate" disabled={!enabled || generateMutation.isPending} />}>
            <RecordTable rows={payloadRows(payloadsQuery.data ?? [])} headers={["Type", "Payload", "State", "Bypass", "Confidence", "Action"]} actions={(payloadsQuery.data ?? []).map((item) => item.validated ? null : <button className="secondary" title={powerConfig.activeValidation ? "Validate this payload with a safe marker request" : "Enable power.active_validation.enabled before validation"} onClick={() => validateMutation.mutate(item.id)} disabled={validateMutation.isPending || !powerConfig.activeValidation}>Validate</button>)} />
          </FeatureSection>
        ) : null}
        {tab === "credentials" ? (
          <FeatureSection icon={<KeyRound size={17} />} title={featureCopy.credentials.title} description={featureCopy.credentials.description} action={<div className="action-row power-credential-controls"><input value={credentialURL} onChange={(event) => setCredentialURL(event.target.value)} placeholder="Login URL for confirmed checks" /><input value={credentialUser} onChange={(event) => setCredentialUser(event.target.value)} placeholder="Username" /><input value={credentialPass} onChange={(event) => setCredentialPass(event.target.value)} placeholder="Password" /><button className="primary" onClick={() => credMutation.mutate()} disabled={!enabled || credMutation.isPending}>Run</button></div>}>
            <RecordTable rows={credentialRows(credentialsQuery.data ?? [])} headers={["Type", "Username", "Password", "Status", "Evidence"]} />
          </FeatureSection>
        ) : null}
        {tab === "osint" ? (
          <FeatureSection icon={<Radar size={17} />} title={featureCopy.osint.title} description={featureCopy.osint.description} action={<div className="action-row"><input value={providers} onChange={(event) => setProviders(event.target.value)} placeholder="Providers" /><button className="primary" onClick={() => osintMutation.mutate()} disabled={!enabled || osintMutation.isPending}>Run Providers</button></div>}>
            <RecordTable rows={providerStatusRows(providersQuery.data ?? [])} headers={["Provider", "Module", "Status", "Message"]} />
            <RecordTable rows={(osintQuery.data ?? []).map((item) => [item.kind, item.value, item.source, `${Math.round(item.confidence * 100)}%`])} headers={["Kind", "Value", "Source", "Confidence"]} />
          </FeatureSection>
        ) : null}
        {tab === "ad" ? (
          <FeatureSection icon={<Network size={17} />} title={featureCopy.ad.title} description={featureCopy.ad.description} action={<div className="action-row"><input value={kerberoastSPN} onChange={(event) => setKerberoastSPN(event.target.value)} placeholder="Optional SPN to record" /><button className="primary" onClick={() => kerberoastMutation.mutate()} disabled={!enabled || kerberoastMutation.isPending}>Record Kerberoast Request</button></div>}>
            <RecordTable rows={(adQuery.data ?? []).map((item) => [item.entity_type, item.name, item.domain, item.sid || "-"])} headers={["Type", "Name", "Domain", "SID"]} />
            <p className="empty-line">{adRelationshipsQuery.data?.length ?? 0} AD relationship records</p>
          </FeatureSection>
        ) : null}
        {tab === "poc" ? (
          <FeatureSection icon={<FlaskConical size={17} />} title={featureCopy.poc.title} description={featureCopy.poc.description} action={<ActionControls value={findingID} onChange={setFindingID} onRun={() => pocMutation.mutate()} label="Record PoC" disabled={!enabled || pocMutation.isPending} />}>
            <RecordTable rows={(pocQuery.data ?? []).map((item) => [item.poc_type, item.status, item.evidence, item.impact_narrative])} headers={["Type", "Status", "Evidence", "Impact"]} />
          </FeatureSection>
        ) : null}
        {tab === "callbacks" ? (
          <FeatureSection icon={<PlugZap size={17} />} title={featureCopy.callbacks.title} description={featureCopy.callbacks.description}>
            <RecordTable rows={callbackRows(callbacksQuery.data ?? [])} headers={["Provider", "Status", "URL", "Source", "Event"]} />
          </FeatureSection>
        ) : null}
        {tab === "burp" ? (
          <FeatureSection icon={<PlugZap size={17} />} title={featureCopy.burp.title} description={featureCopy.burp.description} action={<div className="action-row"><button className="secondary" onClick={() => burpStatusMutation.mutate()} disabled={!enabled || burpStatusMutation.isPending}>Status</button><button className="secondary" onClick={() => burpPushMutation.mutate()} disabled={!enabled || burpPushMutation.isPending}>Push Scope</button><button className="primary" onClick={() => burpPullMutation.mutate()} disabled={!enabled || burpPullMutation.isPending}>Pull Issues</button></div>}>
            <RecordTable rows={[burpResultRow(burpStatusMutation.data, burpPushMutation.data?.message, burpPushMutation.data?.available, burpPullMutation.data?.length)]} headers={["Status", "Message"]} />
          </FeatureSection>
        ) : null}
        {tab === "evasion" ? (
          <FeatureSection icon={<ShieldAlert size={17} />} title={featureCopy.evasion.title} description={featureCopy.evasion.description}>
            <RecordTable rows={(blockQuery.data ?? []).map((item) => [item.tool_id || "-", item.status_code.toString(), item.signal, item.backoff_ms.toString()])} headers={["Tool", "Status", "Signal", "Backoff ms"]} />
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

export function payloadRows(payloads: Payload[]) {
  return payloads.map((item) => [item.payload_type, item.payload, item.validated ? "validated" : "unvalidated", item.bypass_technique || "-", `${Math.round(item.confidence * 100)}%`, item.validated ? item.validated_response || "validated" : "validate"]);
}

export function credentialRows(credentials: CredentialFinding[]) {
  return credentials.map((item) => [item.credential_type, item.username, item.password, credentialState(item), item.evidence]);
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
