import { describe, expect, it } from "vitest";
import { pinTitle, removeReportPin, upsertReportPin, type PinnedAnalystNote } from "./reportPins";

function pin(overrides: Partial<PinnedAnalystNote>): PinnedAnalystNote {
  return {
    id: "pin-1",
    session_id: "session-1",
    analysis_id: "analysis-1",
    message_id: "message-1",
    title: "Risk summary",
    content: "Risk summary",
    created_at: "2026-06-05T12:00:00Z",
    ...overrides,
  };
}

describe("report pins", () => {
  it("creates concise note titles from analyst responses", () => {
    expect(pinTitle("  Short risk summary.  ")).toBe("Short risk summary.");
    expect(pinTitle("A".repeat(90))).toHaveLength(72);
  });

  it("upserts and removes pins by id", () => {
    const notes = upsertReportPin([pin({ id: "pin-1", content: "old" })], pin({ id: "pin-1", content: "new" }));
    expect(notes).toHaveLength(1);
    expect(notes[0].content).toBe("new");
    expect(removeReportPin(notes, "pin-1")).toEqual([]);
  });
});
