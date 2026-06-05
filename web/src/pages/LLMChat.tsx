import { type Dispatch, type FormEvent, type SetStateAction, useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Bot, Check, ChevronDown, ChevronUp, Clipboard, FilePlus2, RotateCcw, Send, Sparkles, UserRound } from "lucide-react";
import { Link, useSearchParams } from "react-router-dom";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { llmAnalyse, llmChat, llmHistory, type LLMAnalysis, type LLMMessage } from "../api/client";
import { loadReportPins, pinTitle, removeReportPin, saveReportPins, upsertReportPin, type PinnedAnalystNote } from "../reportPins";
import { useSessionContext } from "../session";

type ChatMessage = LLMMessage & { analysisID: string; analysisCreatedAt: string; model: string };

const longMessageThreshold = 900;
const reasoningOnlyPlaceholder = "The model returned reasoning only and no final answer.";
const contextWindowEstimate = 32768;

export function LLMChat() {
  const queryClient = useQueryClient();
  const { selectedSessionID: selected, selected: selectedRecord } = useSessionContext();
  const [searchParams] = useSearchParams();
  const [message, setMessage] = useState("");
  const [expandedMessages, setExpandedMessages] = useState<Record<string, boolean>>({});
  const [expandedReasoning, setExpandedReasoning] = useState<Record<string, boolean>>({});
  const [expandedToolCalls, setExpandedToolCalls] = useState<Record<string, boolean>>({});
  const [copiedMessage, setCopiedMessage] = useState("");
  const [activeContextStart, setActiveContextStart] = useState("");
  const [showPriorHistory, setShowPriorHistory] = useState(false);
  const [pinnedNotes, setPinnedNotes] = useState<PinnedAnalystNote[]>([]);
  const historyQuery = useQuery({ queryKey: ["llm-history", selected], queryFn: () => llmHistory(selected), enabled: selected !== "" });
  const chatMutation = useMutation({
    mutationFn: (prompt: string) => llmChat(selected, prompt),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["llm-history", selected] }),
  });
  const analyseMutation = useMutation({
    mutationFn: () => llmAnalyse(selected),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["llm-history", selected] }),
  });

  useEffect(() => {
    if (!selected) {
      setActiveContextStart("");
      setPinnedNotes([]);
      return;
    }
    setActiveContextStart(window.localStorage.getItem(contextResetKey(selected)) ?? "");
    setPinnedNotes(loadReportPins(selected));
  }, [selected]);

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!message.trim() || !selected) {
      return;
    }
    chatMutation.mutate(message.trim());
    setMessage("");
  }

  function startNewAnalysis() {
    if (!selected) return;
    const startedAt = new Date().toISOString();
    window.localStorage.setItem(contextResetKey(selected), startedAt);
    setActiveContextStart(startedAt);
    setShowPriorHistory(false);
    setExpandedMessages({});
    setExpandedReasoning({});
    setExpandedToolCalls({});
    setMessage("");
  }

  function usePrompt(prompt: string) {
    setMessage(prompt);
  }

  async function copyMessage(id: string, content: string) {
    if (!content.trim() || !navigator.clipboard) {
      return;
    }
    await navigator.clipboard.writeText(content);
    setCopiedMessage(id);
    window.setTimeout(() => setCopiedMessage((current) => current === id ? "" : current), 1400);
  }

  function toggleReportPin(item: ChatMessage, messageID: string) {
    if (!selected || !item.content.trim()) return;
    const pinID = `${item.analysisID}:${messageID}`;
    const nextPins = pinnedNotes.some((note) => note.id === pinID)
      ? removeReportPin(pinnedNotes, pinID)
      : upsertReportPin(pinnedNotes, {
        id: pinID,
        session_id: selected,
        analysis_id: item.analysisID,
        message_id: messageID,
        title: pinTitle(item.content),
        content: item.content,
        created_at: new Date().toISOString(),
      });
    setPinnedNotes(nextPins);
    saveReportPins(selected, nextPins);
  }

  const analyses = historyQuery.data ?? [];
  const messages = chatMessages(analyses);
  const allVisibleMessages = visibleChatMessages(messages);
  const visibleMessages = allVisibleMessages.filter((item) => inActiveContext(item, activeContextStart));
  const priorMessageCount = allVisibleMessages.length - visibleMessages.length;
  const contextSummary = contextUsageSummary(analyses, activeContextStart);
  const prompts = suggestedPrompts({
    sessionStatus: selectedRecord?.session.status ?? "",
    currentFindingID: searchParams.get("finding_id") ?? "",
    activeMessages: visibleMessages.length,
    pinnedCount: pinnedNotes.length,
  });
  const analystThinking = chatMutation.isPending || analyseMutation.isPending;

  return (
    <section className="page">
      <header className="page-header">
        <div>
          <h1>Analyst</h1>
          <p>Session-bound analysis with persisted tool-call audit trails.</p>
        </div>
        <div className="action-row">
          <button className="secondary" type="button" onClick={startNewAnalysis} disabled={!selected}>
            <RotateCcw size={16} />New Analysis
          </button>
          <button className="primary" onClick={() => analyseMutation.mutate()} disabled={!selected || analyseMutation.isPending}>
            <Sparkles size={16} />Analyse
          </button>
        </div>
      </header>
      <div className="chat-panel">
        <div className="chat-layout">
          <div className="chat-main">
            <div className="message-list">
              {priorMessageCount > 0 ? (
                <div className="prior-history-strip">
                  <span>{priorMessageCount} prior messages kept in audit history</span>
                  <button className="secondary compact-button" type="button" onClick={() => setShowPriorHistory((current) => !current)}>
                    {showPriorHistory ? "Hide Prior" : "Show Prior"}
                  </button>
                </div>
              ) : null}
              {showPriorHistory ? (
                <div className="prior-history-group">
                  {allVisibleMessages.filter((item) => !inActiveContext(item, activeContextStart)).map((item, index) => (
                    <MessageArticle
                      copiedMessage={copiedMessage}
                      expandedMessages={expandedMessages}
                      expandedReasoning={expandedReasoning}
                      expandedToolCalls={expandedToolCalls}
                      item={item}
                      key={`prior-${item.analysisID}-${index}`}
                      messageID={`prior-${item.analysisID}-${index}`}
                      pinned={false}
                      selectedSessionID={selected}
                      setExpandedMessages={setExpandedMessages}
                      setExpandedReasoning={setExpandedReasoning}
                      setExpandedToolCalls={setExpandedToolCalls}
                      onCopy={copyMessage}
                      onToggleReportPin={undefined}
                    />
                  ))}
                </div>
              ) : null}
              {visibleMessages.map((item, index) => {
                const messageID = `${item.analysisID}-${index}`;
                const pinID = `${item.analysisID}:${messageID}`;
                return <MessageArticle
                  copiedMessage={copiedMessage}
                  expandedMessages={expandedMessages}
                  expandedReasoning={expandedReasoning}
                  expandedToolCalls={expandedToolCalls}
                  item={item}
                  key={messageID}
                  messageID={messageID}
                  pinned={pinnedNotes.some((note) => note.id === pinID)}
                  selectedSessionID={selected}
                  setExpandedMessages={setExpandedMessages}
                  setExpandedReasoning={setExpandedReasoning}
                  setExpandedToolCalls={setExpandedToolCalls}
                  onCopy={copyMessage}
                  onToggleReportPin={item.role === "assistant" ? toggleReportPin : undefined}
                />;
              })}
              {analystThinking ? (
                <article className="message assistant pending-message" aria-live="polite">
                  <div className="message-meta">
                    <strong className="message-header">Assistant</strong>
                  </div>
                  <ReasoningDisclosure active content="" expanded={false} onToggle={() => {}} />
                </article>
              ) : null}
              {visibleMessages.length === 0 && !analystThinking ? (
                <div className="empty-state-panel chat-empty-state">
                  <Bot size={22} />
                  <h2>{allVisibleMessages.length > 0 ? "Fresh Analysis Context" : "No Analyst History"}</h2>
                  <p>{allVisibleMessages.length > 0 ? "Prior messages remain in the audit trail. Send a prompt or run Analyse to populate this working context." : "Run Analyse after configuring an allowed local or OpenAI-compatible endpoint, or ask a scoped question about the selected session."}</p>
                  {allVisibleMessages.length > 0 ? null : <Link className="secondary link-button" to="/settings">Check LLM Configuration</Link>}
                </div>
              ) : null}
            </div>
            <form className="chat-input" onSubmit={submit}>
              <input value={message} onChange={(event) => setMessage(event.target.value)} placeholder="Ask about the selected session" />
              <button className="primary" type="submit" disabled={!selected || chatMutation.isPending}><Send size={16} />Send</button>
            </form>
          </div>
          <aside className="chat-side">
            <section>
              <h2>Suggested Prompts</h2>
              <div className="prompt-chip-row">
                {prompts.map((prompt) => (
                  <button className="prompt-chip" key={prompt.label} type="button" onClick={() => usePrompt(prompt.prompt)}>{prompt.label}</button>
                ))}
              </div>
            </section>
            <section>
              <h2>Context Summary</h2>
              <div className="context-meter" aria-label="Context summary">
                <div>
                  <strong>{contextSummary.percent}%</strong>
                  <span>Approx. usage</span>
                </div>
                <meter min={0} max={100} value={contextSummary.percent}>{contextSummary.percent}%</meter>
              </div>
              <div className="settings-grid compact-health">
                <dl><dt>Working Messages</dt><dd>{visibleMessages.length}</dd></dl>
                <dl><dt>Estimated Tokens</dt><dd>{contextSummary.tokens.toLocaleString()}</dd></dl>
                <dl><dt>Report Pins</dt><dd>{pinnedNotes.length}</dd></dl>
                <dl><dt>Reset</dt><dd>{activeContextStart ? "active" : "none"}</dd></dl>
              </div>
            </section>
            <section>
              <h2>Audit Trail</h2>
              <div className="settings-grid compact-health">
                <dl><dt>Analyses</dt><dd>{analyses.length}</dd></dl>
                <dl><dt>Messages</dt><dd>{visibleMessages.length}</dd></dl>
                <dl><dt>Tool Calls</dt><dd>{messages.filter((item) => item.tool_calls?.length).length}</dd></dl>
                <dl><dt>Model</dt><dd>{analyses[0]?.model_id ?? "not selected"}</dd></dl>
              </div>
            </section>
            {pinnedNotes.length > 0 ? (
              <section>
                <h2>Report Pins</h2>
                <div className="pinned-note-list">
                  {pinnedNotes.slice(-3).map((note) => <span className="pinned-note-pill" key={note.id}>{note.title}</span>)}
                </div>
                <Link className="secondary link-button" to={`/sessions/${selected}/report`}>Open Report Composer</Link>
              </section>
            ) : null}
            {chatMutation.error ? <p className="error-text">{chatMutation.error.message}</p> : null}
            {analyseMutation.error ? <p className="error-text">{analyseMutation.error.message}</p> : null}
          </aside>
        </div>
      </div>
    </section>
  );
}

function MessageArticle({
  copiedMessage,
  expandedMessages,
  expandedReasoning,
  expandedToolCalls,
  item,
  messageID,
  pinned,
  selectedSessionID,
  setExpandedMessages,
  setExpandedReasoning,
  setExpandedToolCalls,
  onCopy,
  onToggleReportPin,
}: {
  copiedMessage: string;
  expandedMessages: Record<string, boolean>;
  expandedReasoning: Record<string, boolean>;
  expandedToolCalls: Record<string, boolean>;
  item: ChatMessage;
  messageID: string;
  pinned: boolean;
  selectedSessionID: string;
  setExpandedMessages: Dispatch<SetStateAction<Record<string, boolean>>>;
  setExpandedReasoning: Dispatch<SetStateAction<Record<string, boolean>>>;
  setExpandedToolCalls: Dispatch<SetStateAction<Record<string, boolean>>>;
  onCopy: (id: string, content: string) => Promise<void>;
  onToggleReportPin?: (item: ChatMessage, messageID: string) => void;
}) {
  return (
    <article className={`message ${item.role}`}>
      <div className="message-meta">
        <span className="message-avatar" aria-hidden="true">{item.role === "assistant" ? <Bot size={15} /> : <UserRound size={15} />}</span>
        <strong className="message-header">{messageLabel(item.role)}</strong>
        {item.role === "assistant" && hasReasoningOutput(item) ? <span className="message-badge">Reasoning output</span> : null}
        {item.role === "assistant" && item.content.trim() && onToggleReportPin ? (
          <button className={`secondary compact-button message-pin ${pinned ? "active" : ""}`} type="button" onClick={() => onToggleReportPin(item, messageID)}>
            <FilePlus2 size={14} />{pinned ? "Pinned" : "Pin to Report"}
          </button>
        ) : null}
        {item.content.trim() ? (
          <button className="icon-button message-copy" type="button" onClick={() => void onCopy(messageID, item.content)} aria-label="Copy message">
            {copiedMessage === messageID ? <Check size={15} /> : <Clipboard size={15} />}
          </button>
        ) : null}
      </div>
      {item.content.trim() ? (
        <MessageContent
          content={item.content}
          expanded={expandedMessages[messageID] ?? false}
          reasoningContent={item.reasoning_content ?? ""}
          reasoningExpanded={expandedReasoning[messageID] ?? false}
          onReasoningToggle={() => setExpandedReasoning((current) => ({ ...current, [messageID]: !current[messageID] }))}
          onToggle={() => setExpandedMessages((current) => ({ ...current, [messageID]: !current[messageID] }))}
        />
      ) : null}
      {(item.tool_calls ?? []).map((call) => {
        const toolCallID = `${item.analysisID}-${call.name}-${call.id ?? ""}`;
        return (
          <ToolCallCard
            callID={toolCallID}
            expanded={expandedToolCalls[toolCallID] ?? false}
            key={`${call.name}-${call.id ?? ""}`}
            name={call.name}
            sessionID={selectedSessionID}
            text={call.error || call.result || call.arguments || ""}
            error={call.error ?? ""}
            onToggle={() => setExpandedToolCalls((current) => ({ ...current, [toolCallID]: !current[toolCallID] }))}
          />
        );
      })}
    </article>
  );
}

function MessageContent({
  content,
  expanded,
  reasoningContent,
  reasoningExpanded,
  onReasoningToggle,
  onToggle,
}: {
  content: string;
  expanded: boolean;
  reasoningContent: string;
  reasoningExpanded: boolean;
  onReasoningToggle: () => void;
  onToggle: () => void;
}) {
  const normalizedReasoning = reasoningContent.trim();
  if (normalizedReasoning) {
    const visibleContent = cleanFinalAnswerLabels(content);
    return (
      <>
        <ReasoningDisclosure content={normalizedReasoning} expanded={reasoningExpanded} onToggle={onReasoningToggle} />
        {visibleContent ? <StandardMessageContent content={visibleContent} expanded={expanded} onToggle={onToggle} /> : null}
      </>
    );
  }
  const reasoning = splitReasoningContent(content);
  if (reasoning) {
    return (
      <>
        <ReasoningDisclosure content={reasoning.reasoning} expanded={reasoningExpanded} onToggle={onReasoningToggle} />
        <StandardMessageContent content={reasoning.answer || reasoningOnlyPlaceholder} expanded={expanded} onToggle={onToggle} />
      </>
    );
  }
  return <StandardMessageContent content={content} expanded={expanded} onToggle={onToggle} />;
}

function StandardMessageContent({ content, expanded, onToggle }: { content: string; expanded: boolean; onToggle: () => void }) {
  const long = content.length > longMessageThreshold;
  const shown = long && !expanded ? content.slice(0, longMessageThreshold).trimEnd() + "..." : content;
  return (
    <>
      <div className={`message-content ${long && !expanded ? "collapsed" : ""}`}>{renderMarkdown(shown)}</div>
      {long ? (
        <button className="message-toggle" type="button" onClick={onToggle}>
          {expanded ? <ChevronUp size={15} /> : <ChevronDown size={15} />}
          {expanded ? "Collapse" : "Expand"}
        </button>
      ) : null}
    </>
  );
}

function ReasoningDisclosure({ active = false, content, expanded, onToggle }: { active?: boolean; content: string; expanded: boolean; onToggle: () => void }) {
  return (
    <div className={`reasoning-panel ${expanded ? "open" : ""} ${active ? "active" : ""}`}>
      <button className="reasoning-toggle" type="button" onClick={onToggle} disabled={active && !content}>
        <span className="thinking-label">Thinking{active ? <span className="thinking-dots" aria-hidden="true"><span>.</span><span>.</span><span>.</span></span> : null}</span>
        {expanded ? <ChevronUp size={15} /> : <ChevronDown size={15} />}
      </button>
      {expanded ? <div className="message-content reasoning-content">{renderMarkdown(content)}</div> : null}
    </div>
  );
}

function ToolCallCard({ callID, error, expanded, name, sessionID, text, onToggle }: { callID: string; error: string; expanded: boolean; name: string; sessionID: string; text: string; onToggle: () => void }) {
  const long = text.length > 520;
  const shown = long && !expanded ? text.slice(0, 520).trimEnd() + "..." : text;
  const summary = toolCallSummary(name, text, sessionID, error);
  return (
    <div className="tool-call-card">
      <div className="tool-call-header">
        <strong>{toolCallLabel(name)}</strong>
        <small>{name}</small>
        {long ? (
          <button className="message-toggle compact" type="button" onClick={onToggle} aria-controls={callID}>
            {expanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
            {expanded ? "Collapse" : "Expand"}
          </button>
        ) : null}
      </div>
      <p className="tool-call-caption">{summary}</p>
      <code id={callID}>{shown}</code>
    </div>
  );
}

export function chatMessages(analyses: LLMAnalysis[]): ChatMessage[] {
  return analyses.flatMap((analysis) => analysis.messages.map((item) => ({ ...item, analysisID: analysis.id, analysisCreatedAt: analysis.created_at, model: analysis.model_id })));
}

export function visibleChatMessages(messages: ChatMessage[]) {
  return messages.filter((item) => item.role !== "system" && !isInternalContextMessage(item.content) && (item.content.trim() || item.tool_calls?.length));
}

export function toolCallLabel(name: string) {
  const labels: Record<string, string> = {
    get_session_findings: "Analysis context: Findings",
    search_cves_for_technology: "Analysis context: CVEs",
    lookup_cve: "Analysis context: CVE detail",
    request_scan: "Analysis request: Follow-up scan",
    list_findings: "Analysis context: Findings",
    list_targets: "Analysis context: Targets",
    list_tool_runs: "Analysis context: Tool runs",
    list_vectors: "Analysis context: Attack paths",
    list_cves: "Analysis context: CVEs",
  };
  return labels[name] ?? name.replace(/_/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

export function toolCallSummary(name: string, text: string, sessionID: string, error = "") {
  if (error) return `Tool error for session ${shortID(sessionID)}.`;
  const parsed = parseJSON(text);
  const prefix = (verb: string, noun: string) => `${verb} ${noun} from session ${shortID(sessionID)}.`;
  if (name === "get_session_findings" || name === "list_findings") {
    return Array.isArray(parsed) ? prefix("Fetched", `${parsed.length} findings`) : prefix("Fetched", "findings");
  }
  if (name === "search_cves_for_technology" || name === "list_cves") {
    return Array.isArray(parsed) ? prefix("Fetched", `${parsed.length} CVE matches`) : prefix("Fetched", "CVE matches");
  }
  if (name === "lookup_cve") {
    const cveID = parsed && typeof parsed === "object" && "cve_id" in parsed ? String((parsed as { cve_id?: unknown }).cve_id ?? "CVE") : "CVE";
    return prefix("Fetched", `${cveID} details`);
  }
  if (name === "request_scan") {
    const target = parsed && typeof parsed === "object" && "target" in parsed ? String((parsed as { target?: unknown }).target ?? "target") : "target";
    const accepted = parsed && typeof parsed === "object" && "accepted" in parsed && Boolean((parsed as { accepted?: unknown }).accepted);
    return `${accepted ? "Recorded" : "Denied"} follow-up scan request for ${target}.`;
  }
  return prefix("Fetched", "analyst context");
}

export function contextUsageSummary(analyses: LLMAnalysis[], activeContextStart = "") {
  const activeAnalyses = activeContextStart
    ? analyses.filter((analysis) => Date.parse(analysis.created_at) >= Date.parse(activeContextStart))
    : analyses;
  const tokens = activeAnalyses.reduce((total, analysis) => total + Math.max(0, analysis.total_tokens || 0), 0);
  return {
    tokens,
    percent: Math.min(100, Math.round((tokens / contextWindowEstimate) * 100)),
  };
}

export function suggestedPrompts({ activeMessages, currentFindingID, pinnedCount, sessionStatus }: { activeMessages: number; currentFindingID: string; pinnedCount: number; sessionStatus: string }) {
  if (currentFindingID) {
    return [
      { label: "Finding brief", prompt: `Summarize finding ${currentFindingID}, its strongest evidence, and the safest remediation path.` },
      { label: "Evidence gaps", prompt: `What evidence is missing before I should mark finding ${currentFindingID} confirmed?` },
      { label: "Report wording", prompt: `Draft concise technical report language for finding ${currentFindingID} using only persisted evidence.` },
    ];
  }
  if (pinnedCount > 0) {
    return [
      { label: "Report synthesis", prompt: "Turn the pinned analyst notes into a concise executive summary candidate." },
      { label: "Remediation order", prompt: "Order the pinned risks by remediation priority and explain the dependency order." },
      { label: "Evidence check", prompt: "Which pinned conclusions need stronger stored evidence before report inclusion?" },
    ];
  }
  if (sessionStatus === "completed" && activeMessages === 0) {
    return [
      { label: "Post-scan brief", prompt: "Summarize the completed scan by confirmed risk, affected surface, and immediate remediation priority." },
      { label: "Evidence triage", prompt: "Which findings have the strongest evidence and easiest remediation path?" },
      { label: "Attack chains", prompt: "Map the likely attack chains from the selected session." },
    ];
  }
  if (activeMessages >= 4) {
    return [
      { label: "Refocus", prompt: "Restate the current analysis in five bullets using only the strongest persisted evidence." },
      { label: "Next decision", prompt: "What triage decision should I make next, and what evidence supports it?" },
      { label: "Safe checks", prompt: "Suggest safe follow-up checks that stay within the current scope." },
    ];
  }
  return [
    { label: "Risk summary", prompt: "Summarize the highest-confidence risks and why they matter." },
    { label: "Evidence triage", prompt: "Which findings have the strongest evidence and easiest remediation path?" },
    { label: "Follow-up checks", prompt: "Suggest safe follow-up checks that stay within the current scope." },
  ];
}

function contextResetKey(sessionID: string) {
  return `nyx:llm-context-start:${sessionID}`;
}

function inActiveContext(item: ChatMessage, activeContextStart: string) {
  return !activeContextStart || Date.parse(item.analysisCreatedAt) >= Date.parse(activeContextStart);
}

function parseJSON(value: string): unknown {
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

function shortID(value: string) {
  return value ? value.slice(0, 8) : "unknown";
}

export function splitReasoningContent(content: string) {
  const normalized = content.replace(/\r\n/g, "\n").trimStart();
  const thinkMatch = normalized.match(/^<think>\s*([\s\S]*?)\s*<\/think>\s*([\s\S]*)$/i);
  if (thinkMatch) {
    return { reasoning: thinkMatch[1].trim(), answer: thinkMatch[2].trim() };
  }
  const label = normalized.match(/^(thinking process|reasoning|thought process)\s*:\s*/i);
  if (!label) {
    return null;
  }
  const body = normalized.slice(label[0].length).trim();
  const finalMarker = body.match(/\n\s*(final answer|final output|answer|response|final)\s*:\s*/i);
  if (!finalMarker || finalMarker.index === undefined) {
    return { reasoning: body, answer: "" };
  }
  return {
    reasoning: body.slice(0, finalMarker.index).trim(),
    answer: body.slice(finalMarker.index + finalMarker[0].length).trim(),
  };
}

function cleanFinalAnswerLabels(content: string) {
  return content.replace(/\r\n/g, "\n").replace(/(^|\n)\s*(final answer|final output|answer|response|final)\s*:\s*/gi, "$1").trim();
}

function isInternalContextMessage(content: string) {
  return content.trimStart().startsWith("Session context JSON:");
}

function messageLabel(role: string) {
  switch (role) {
    case "assistant":
      return "Assistant";
    case "user":
      return "You";
    case "tool":
      return "Tool";
    default:
      return role;
  }
}

function renderMarkdown(content: string) {
  return <ReactMarkdown remarkPlugins={[remarkGfm]}>{content}</ReactMarkdown>;
}

function hasReasoningOutput(message: ChatMessage) {
  return Boolean(message.reasoning_content?.trim()) || isReasoningDerived(message.content);
}

function isReasoningDerived(content: string) {
  return splitReasoningContent(content) !== null;
}
