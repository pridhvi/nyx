import { describe, expect, it } from "vitest";
import { chatMessages, contextUsageSummary, splitReasoningContent, suggestedPrompts, toolCallLabel, toolCallSummary, visibleChatMessages } from "./pages/LLMChat";
import type { LLMAnalysis } from "./api/client";

describe("LLM chat helpers", () => {
  it("hides internal session context and keeps visible user and assistant messages", () => {
    const analyses: LLMAnalysis[] = [{
      id: "analysis-1",
      session_id: "session-1",
      model_id: "local-model",
      prompt_summary: "summary",
      total_tokens: 10,
      created_at: "2026-06-05T12:00:00Z",
      messages: [
        { role: "system", content: "system prompt" },
        { role: "user", content: "Session context JSON:\n{\"internal\":true}" },
        { role: "user", content: "Summarize the session." },
        { role: "assistant", content: "**Risk:** missing headers" },
      ],
    }];

    const visible = visibleChatMessages(chatMessages(analyses));
    expect(visible.map((message) => message.content)).toEqual(["Summarize the session.", "**Risk:** missing headers"]);
    expect(visible[1].model).toBe("local-model");
  });

  it("splits reasoning-prefixed output from final assistant content", () => {
    expect(splitReasoningContent([
      "Thinking Process:",
      "Check the scan context.",
      "",
      "Final Answer:",
      "- **Risk:** confirmed SQL injection",
    ].join("\n"))).toEqual({
      reasoning: "Check the scan context.",
      answer: "- **Risk:** confirmed SQL injection",
    });
  });

  it("treats unmarked reasoning output as hidden reasoning without final text", () => {
    expect(splitReasoningContent("Reasoning:\nInspect findings first.")).toEqual({
      reasoning: "Inspect findings first.",
      answer: "",
    });
  });

  it("supports explicit think tags from local reasoning models", () => {
    expect(splitReasoningContent("<think>Inspect context.</think>\n- Final bullet")).toEqual({
      reasoning: "Inspect context.",
      answer: "- Final bullet",
    });
  });

  it("uses friendly labels for persisted analyst context calls", () => {
    expect(toolCallLabel("list_findings")).toBe("Analysis context: Findings");
    expect(toolCallLabel("get_session_findings")).toBe("Analysis context: Findings");
    expect(toolCallLabel("list_tool_runs")).toBe("Analysis context: Tool runs");
    expect(toolCallLabel("custom_context_probe")).toBe("Custom Context Probe");
  });

  it("summarizes tool-call payloads for operator trust", () => {
    expect(toolCallSummary("get_session_findings", JSON.stringify([{ id: "finding-1" }, { id: "finding-2" }]), "abcdef123456")).toBe("Fetched 2 findings from session abcdef12.");
    expect(toolCallSummary("lookup_cve", JSON.stringify({ cve_id: "CVE-2026-12345" }), "abcdef123456")).toBe("Fetched CVE-2026-12345 details from session abcdef12.");
    expect(toolCallSummary("request_scan", JSON.stringify({ accepted: false, target: "https://out.example" }), "abcdef123456")).toBe("Denied follow-up scan request for https://out.example.");
  });

  it("estimates active context usage after a reset point", () => {
    const analyses: LLMAnalysis[] = [
      { id: "old", session_id: "s", model_id: "m", prompt_summary: "old", messages: [], total_tokens: 1000, created_at: "2026-06-05T10:00:00Z" },
      { id: "new", session_id: "s", model_id: "m", prompt_summary: "new", messages: [], total_tokens: 16384, created_at: "2026-06-05T12:00:00Z" },
    ];
    expect(contextUsageSummary(analyses, "2026-06-05T11:00:00Z")).toEqual({ tokens: 16384, percent: 50 });
  });

  it("returns context-aware prompt sets", () => {
    expect(suggestedPrompts({ activeMessages: 0, currentFindingID: "finding-1", pinnedCount: 0, sessionStatus: "completed" })[0].label).toBe("Chain this finding");
    expect(suggestedPrompts({ activeMessages: 0, currentFindingID: "", pinnedCount: 2, sessionStatus: "completed" })[0].label).toBe("Chain synthesis");
    expect(suggestedPrompts({ activeMessages: 0, currentFindingID: "", pinnedCount: 0, sessionStatus: "completed" })[0].label).toBe("Attack path brief");
    expect(suggestedPrompts({ activeMessages: 4, currentFindingID: "", pinnedCount: 0, sessionStatus: "running" })[0].label).toBe("Refocus chain");
    expect(suggestedPrompts({ activeMessages: 0, currentFindingID: "", pinnedCount: 0, sessionStatus: "running" })[0].label).toBe("Attack path ideas");
  });
});
