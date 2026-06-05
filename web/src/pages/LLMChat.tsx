import { type FormEvent, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Bot, Check, ChevronDown, ChevronUp, Clipboard, Send, Sparkles } from "lucide-react";
import { Link } from "react-router-dom";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { llmAnalyse, llmChat, llmHistory, type LLMAnalysis, type LLMMessage } from "../api/client";
import { useSessionContext } from "../session";

type ChatMessage = LLMMessage & { analysisID: string; model: string };

const longMessageThreshold = 900;
const reasoningOnlyPlaceholder = "The model returned reasoning only and no final answer.";

export function LLMChat() {
  const queryClient = useQueryClient();
  const { selectedSessionID: selected } = useSessionContext();
  const [message, setMessage] = useState("");
  const [expandedMessages, setExpandedMessages] = useState<Record<string, boolean>>({});
  const [expandedReasoning, setExpandedReasoning] = useState<Record<string, boolean>>({});
  const [expandedToolCalls, setExpandedToolCalls] = useState<Record<string, boolean>>({});
  const [copiedMessage, setCopiedMessage] = useState("");
  const historyQuery = useQuery({ queryKey: ["llm-history", selected], queryFn: () => llmHistory(selected), enabled: selected !== "" });
  const chatMutation = useMutation({
    mutationFn: (prompt: string) => llmChat(selected, prompt),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["llm-history", selected] }),
  });
  const analyseMutation = useMutation({
    mutationFn: () => llmAnalyse(selected),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["llm-history", selected] }),
  });

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!message.trim() || !selected) {
      return;
    }
    chatMutation.mutate(message.trim());
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

  const analyses = historyQuery.data ?? [];
  const messages = chatMessages(analyses);
  const visibleMessages = visibleChatMessages(messages);
  const analystThinking = chatMutation.isPending || analyseMutation.isPending;

  return (
    <section className="page">
      <header className="page-header">
        <div>
          <h1>Analyst</h1>
          <p>Session-bound analysis with persisted tool-call audit trails.</p>
        </div>
        <button className="primary" onClick={() => analyseMutation.mutate()} disabled={!selected || analyseMutation.isPending}>
          <Sparkles size={16} />Analyse
        </button>
      </header>
      <div className="chat-panel">
        <div className="chat-layout">
          <div className="chat-main">
            <div className="message-list">
              {visibleMessages.map((item, index) => {
                const messageID = `${item.analysisID}-${index}`;
                return (
                  <article key={messageID} className={`message ${item.role}`}>
                    <div className="message-meta">
                      <strong className="message-header">{messageLabel(item.role)}</strong>
                      {item.role === "assistant" && hasReasoningOutput(item) ? <span className="message-badge">Reasoning output</span> : null}
                      {item.content.trim() ? (
                        <button className="icon-button message-copy" type="button" onClick={() => void copyMessage(messageID, item.content)} aria-label="Copy message">
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
                    {(item.tool_calls ?? []).map((call) => (
                      <ToolCallCard
                        callID={`${item.analysisID}-${call.name}-${call.id ?? ""}`}
                        expanded={expandedToolCalls[`${item.analysisID}-${call.name}-${call.id ?? ""}`] ?? false}
                        key={`${call.name}-${call.id ?? ""}`}
                        name={call.name}
                        text={call.error || call.result || call.arguments || ""}
                        onToggle={() => setExpandedToolCalls((current) => ({ ...current, [`${item.analysisID}-${call.name}-${call.id ?? ""}`]: !current[`${item.analysisID}-${call.name}-${call.id ?? ""}`] }))}
                      />
                    ))}
                  </article>
                );
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
                  <h2>No Analyst History</h2>
                  <p>Run Analyse after configuring an allowed local or OpenAI-compatible endpoint, or ask a scoped question about the selected session.</p>
                  <Link className="secondary link-button" to="/settings">Check LLM Configuration</Link>
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
                <button className="prompt-chip" type="button" onClick={() => usePrompt("Summarize the highest-confidence risks and why they matter.")}>Risk summary</button>
                <button className="prompt-chip" type="button" onClick={() => usePrompt("Which findings have the strongest evidence and easiest remediation path?")}>Evidence triage</button>
                <button className="prompt-chip" type="button" onClick={() => usePrompt("Map the likely attack chains from the selected session.")}>Attack chains</button>
                <button className="prompt-chip" type="button" onClick={() => usePrompt("Suggest safe follow-up checks that stay within the current scope.")}>Follow-up checks</button>
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
            {chatMutation.error ? <p className="error-text">{chatMutation.error.message}</p> : null}
            {analyseMutation.error ? <p className="error-text">{analyseMutation.error.message}</p> : null}
          </aside>
        </div>
      </div>
    </section>
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

function ToolCallCard({ callID, expanded, name, text, onToggle }: { callID: string; expanded: boolean; name: string; text: string; onToggle: () => void }) {
  const long = text.length > 520;
  const shown = long && !expanded ? text.slice(0, 520).trimEnd() + "..." : text;
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
      <p className="tool-call-caption">Persisted context used by the analyst, not the final answer.</p>
      <code id={callID}>{shown}</code>
    </div>
  );
}

export function chatMessages(analyses: LLMAnalysis[]): ChatMessage[] {
  return analyses.flatMap((analysis) => analysis.messages.map((item) => ({ ...item, analysisID: analysis.id, model: analysis.model_id })));
}

export function visibleChatMessages(messages: ChatMessage[]) {
  return messages.filter((item) => item.role !== "system" && !isInternalContextMessage(item.content) && (item.content.trim() || item.tool_calls?.length));
}

export function toolCallLabel(name: string) {
  const labels: Record<string, string> = {
    list_findings: "Analysis context: Findings",
    list_targets: "Analysis context: Targets",
    list_tool_runs: "Analysis context: Tool runs",
    list_vectors: "Analysis context: Attack paths",
    list_cves: "Analysis context: CVEs",
  };
  return labels[name] ?? name.replace(/_/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
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
