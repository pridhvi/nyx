export type PinnedAnalystNote = {
  id: string;
  session_id: string;
  analysis_id: string;
  message_id: string;
  title: string;
  content: string;
  created_at: string;
};

export function reportPinsKey(sessionID: string) {
  return `nyx:report-pins:${sessionID}`;
}

export function loadReportPins(sessionID: string): PinnedAnalystNote[] {
  if (!sessionID || typeof window === "undefined") return [];
  try {
    const parsed = JSON.parse(window.localStorage.getItem(reportPinsKey(sessionID)) ?? "[]");
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(isPinnedAnalystNote);
  } catch {
    return [];
  }
}

export function saveReportPins(sessionID: string, notes: PinnedAnalystNote[]) {
  if (!sessionID || typeof window === "undefined") return;
  window.localStorage.setItem(reportPinsKey(sessionID), JSON.stringify(notes));
}

export function upsertReportPin(notes: PinnedAnalystNote[], note: PinnedAnalystNote) {
  const existing = notes.filter((item) => item.id !== note.id);
  return [...existing, note].sort((left, right) => left.created_at.localeCompare(right.created_at));
}

export function removeReportPin(notes: PinnedAnalystNote[], id: string) {
  return notes.filter((item) => item.id !== id);
}

export function pinTitle(content: string) {
  const compact = content.replace(/\s+/g, " ").trim();
  if (!compact) return "Analyst note";
  return compact.length > 72 ? compact.slice(0, 69).trimEnd() + "..." : compact;
}

function isPinnedAnalystNote(value: unknown): value is PinnedAnalystNote {
  if (!value || typeof value !== "object") return false;
  const note = value as Record<string, unknown>;
  return typeof note.id === "string"
    && typeof note.session_id === "string"
    && typeof note.analysis_id === "string"
    && typeof note.message_id === "string"
    && typeof note.title === "string"
    && typeof note.content === "string"
    && typeof note.created_at === "string";
}
