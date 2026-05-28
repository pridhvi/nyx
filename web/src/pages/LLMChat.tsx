import { type FormEvent, type ReactNode, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Bot, Send, Sparkles } from "lucide-react";
import { llmAnalyse, llmChat, llmHistory } from "../api/client";
import { useSessionContext } from "../session";

export function LLMChat() {
  const queryClient = useQueryClient();
  const { selectedSessionID: selected } = useSessionContext();
  const [message, setMessage] = useState("");
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

  const analyses = historyQuery.data ?? [];
  const messages = analyses.flatMap((analysis) => analysis.messages.map((item) => ({ ...item, analysisID: analysis.id, model: analysis.model_id })));
  const visibleMessages = messages.filter((item) => item.role !== "system" && !isInternalContextMessage(item.content) && (item.content.trim() || item.tool_calls?.length));

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
              {visibleMessages.map((item, index) => (
                <article key={`${item.analysisID}-${index}`} className={`message ${item.role}`}>
                  <strong className="message-header">{messageLabel(item.role)}</strong>
                  {item.content.trim() ? <div className="message-content">{renderMarkdown(item.content)}</div> : null}
                  {(item.tool_calls ?? []).map((call) => (
                    <div className="tool-call-card" key={`${call.name}-${call.id ?? ""}`}>
                      <strong>{call.name}</strong>
                      <code>{call.error || call.result || call.arguments}</code>
                    </div>
                  ))}
                </article>
              ))}
              {visibleMessages.length === 0 ? <div className="empty-line"><Bot size={18} />No LLM history for the selected session.</div> : null}
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
  const lines = content.replace(/\r\n/g, "\n").split("\n");
  const blocks: ReactNode[] = [];
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (!line.trim()) {
      i++;
      continue;
    }
    const unordered = line.match(/^\s*[-*]\s+(.+)$/);
    const ordered = line.match(/^\s*\d+\.\s+(.+)$/);
    const heading = line.match(/^\s{0,3}#{1,3}\s+(.+)$/);
    if (heading) {
      blocks.push(<h3 key={i}>{renderInline(heading[1])}</h3>);
      i++;
      continue;
    }
    if (unordered || ordered) {
      const items: string[] = [];
      const orderedList = Boolean(ordered);
      while (i < lines.length) {
        const match = orderedList ? lines[i].match(/^\s*\d+\.\s+(.+)$/) : lines[i].match(/^\s*[-*]\s+(.+)$/);
        if (!match) {
          break;
        }
        items.push(match[1]);
        i++;
      }
      const children = items.map((item, itemIndex) => <li key={`${i}-${itemIndex}`}>{renderInline(item)}</li>);
      blocks.push(orderedList ? <ol key={i}>{children}</ol> : <ul key={i}>{children}</ul>);
      continue;
    }
    const paragraph = [line.trim()];
    i++;
    while (i < lines.length && lines[i].trim() && !/^\s*([-*]|\d+\.)\s+/.test(lines[i]) && !/^\s{0,3}#{1,3}\s+/.test(lines[i])) {
      paragraph.push(lines[i].trim());
      i++;
    }
    blocks.push(<p key={i}>{renderInline(paragraph.join(" "))}</p>);
  }
  return blocks;
}

function renderInline(text: string) {
  const nodes: ReactNode[] = [];
  const pattern = /(\*\*[^*]+\*\*|`[^`]+`)/g;
  let lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(text)) !== null) {
    if (match.index > lastIndex) {
      nodes.push(text.slice(lastIndex, match.index));
    }
    const token = match[0];
    if (token.startsWith("**")) {
      nodes.push(<strong key={nodes.length}>{token.slice(2, -2)}</strong>);
    } else {
      nodes.push(<code key={nodes.length}>{token.slice(1, -1)}</code>);
    }
    lastIndex = pattern.lastIndex;
  }
  if (lastIndex < text.length) {
    nodes.push(text.slice(lastIndex));
  }
  return nodes;
}
