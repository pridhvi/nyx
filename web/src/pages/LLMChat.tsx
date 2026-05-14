import { type FormEvent, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useParams } from "react-router-dom";
import { Bot, Send, Sparkles } from "lucide-react";
import { listSessions, llmAnalyse, llmChat, llmHistory } from "../api/client";

export function LLMChat() {
  const params = useParams();
  const queryClient = useQueryClient();
  const sessionsQuery = useQuery({ queryKey: ["sessions"], queryFn: listSessions });
  const selected = params.sessionID ?? sessionsQuery.data?.[0]?.session.id ?? "";
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

  const analyses = historyQuery.data ?? [];
  const messages = analyses.flatMap((analysis) => analysis.messages.map((item) => ({ ...item, analysisID: analysis.id, model: analysis.model_id })));

  return (
    <section className="page">
      <header className="page-header">
        <div>
          <h1>LLM Analyst</h1>
          <p>Session-bound analysis with persisted tool-call audit trails.</p>
        </div>
        <button className="primary" onClick={() => analyseMutation.mutate()} disabled={!selected || analyseMutation.isPending}>
          <Sparkles size={16} />Analyse
        </button>
      </header>
      <div className="chat-panel">
        <div className="message-list">
          {messages.filter((item) => item.role !== "system").map((item, index) => (
            <article key={`${item.analysisID}-${index}`} className={`message ${item.role}`}>
              <strong>{item.role === "assistant" ? item.model : item.role}</strong>
              <p>{item.content}</p>
              {(item.tool_calls ?? []).map((call) => (
                <code key={`${call.name}-${call.id ?? ""}`}>{call.name}: {call.error || call.result || call.arguments}</code>
              ))}
            </article>
          ))}
          {messages.length === 0 ? <div className="empty-line"><Bot size={18} />No LLM history for the selected session.</div> : null}
        </div>
        <form className="chat-input" onSubmit={submit}>
          <input value={message} onChange={(event) => setMessage(event.target.value)} placeholder="Ask about the selected session" />
          <button className="primary" type="submit" disabled={!selected || chatMutation.isPending}><Send size={16} />Send</button>
        </form>
        {chatMutation.error ? <p className="error-text">{chatMutation.error.message}</p> : null}
        {analyseMutation.error ? <p className="error-text">{analyseMutation.error.message}</p> : null}
      </div>
    </section>
  );
}
