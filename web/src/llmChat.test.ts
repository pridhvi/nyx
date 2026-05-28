import { describe, expect, it } from "vitest";
import { chatMessages, markdownBlocks, splitReasoningContent, visibleChatMessages } from "./pages/LLMChat";
import type { LLMAnalysis } from "./api/client";

describe("LLM chat helpers", () => {
  it("hides internal session context and keeps visible user and assistant messages", () => {
    const analyses: LLMAnalysis[] = [{
      id: "analysis-1",
      session_id: "session-1",
      model_id: "local-model",
      prompt_summary: "summary",
      total_tokens: 10,
      created_at: "",
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

  it("groups markdown-like assistant output into headings, bullets, numbering, and paragraphs", () => {
    expect(markdownBlocks([
      "### Summary",
      "",
      "- **Risk:** missing `CSP`",
      "- Add headers",
      "",
      "1. Confirm scope",
      "2. Re-test",
      "",
      "Final paragraph",
      "continues here.",
    ].join("\n"))).toEqual([
      { type: "heading", items: ["Summary"] },
      { type: "ul", items: ["**Risk:** missing `CSP`", "Add headers"] },
      { type: "ol", items: ["Confirm scope", "Re-test"] },
      { type: "paragraph", items: ["Final paragraph continues here."] },
    ]);
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
});
