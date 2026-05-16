import { type FormEvent, useState } from "react";
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
              {messages.filter((item) => item.role !== "system").map((item, index) => (
                <article key={`${item.analysisID}-${index}`} className={`message ${item.role}`}>
                  <strong>{item.role === "assistant" ? item.model : item.role}</strong>
                  <p>{item.content}</p>
                  {(item.tool_calls ?? []).map((call) => (
                    <div className="tool-call-card" key={`${call.name}-${call.id ?? ""}`}>
                      <strong>{call.name}</strong>
                      <code>{call.error || call.result || call.arguments}</code>
                    </div>
                  ))}
                </article>
              ))}
              {messages.length === 0 ? <div className="empty-line"><Bot size={18} />No LLM history for the selected session.</div> : null}
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
                <dl><dt>Messages</dt><dd>{messages.filter((item) => item.role !== "system").length}</dd></dl>
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
