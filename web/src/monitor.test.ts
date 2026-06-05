import { describe, expect, it } from "vitest";
import type { MonitorConfig, MonitorRun, SurfaceChange } from "./api/client";
import { groupChangesByCategory, missedScheduledWindows, severityTrend, toggleValue } from "./pages/Monitor";

describe("monitor option helpers", () => {
  it("toggles checkbox options while preserving array payload shape", () => {
    expect(toggleValue(["recon"], "fingerprint")).toEqual(["recon", "fingerprint"]);
    expect(toggleValue(["recon", "fingerprint"], "recon")).toEqual(["fingerprint"]);
  });

  it("groups surface changes by operator triage category", () => {
    const groups = groupChangesByCategory([
      change({ id: "new", change_type: "new_finding", severity: "high" }),
      change({ id: "resolved", change_type: "resolved_finding", severity: "info" }),
      change({ id: "severity", change_type: "finding_severity_changed", severity: "critical" }),
      change({ id: "tech", change_type: "new_technology", severity: "low" }),
      change({ id: "gone", change_type: "resolved_service", severity: "info" }),
    ]);

    expect(groups.map((group) => group.title)).toEqual([
      "New Findings",
      "Resolved Findings",
      "Severity Changes",
      "New Technologies",
      "Disappeared Endpoints",
    ]);
  });

  it("estimates missed windows from overdue next_run_at for fixed schedules", () => {
    const config = {
      enabled: true,
      schedule: "@daily",
      next_run_at: "2026-06-04T12:00:00Z",
    } as MonitorConfig;

    expect(missedScheduledWindows(config, new Date("2026-06-05T13:00:00Z"))).toBe(2);
  });

  it("maps completed runs to max observed severity trend points", () => {
    const points = severityTrend([
      run({ id: "run-1", started_at: "2026-06-04T12:00:00Z", completed_at: "2026-06-04T12:10:00Z" }),
      run({ id: "run-2", started_at: "2026-06-05T12:00:00Z", completed_at: "2026-06-05T12:10:00Z" }),
    ], [
      [change({ severity: "low" })],
      [change({ severity: "medium" }), change({ severity: "critical" })],
    ]);

    expect(points.map((point) => point.rank)).toEqual([2, 5]);
  });
});

function run(overrides: Partial<MonitorRun>): MonitorRun {
  return {
    id: "run",
    config_id: "config",
    session_id: "session",
    status: "completed",
    changes_found: true,
    started_at: "2026-06-05T12:00:00Z",
    ...overrides,
  };
}

function change(overrides: Partial<SurfaceChange>): SurfaceChange {
  return {
    id: "change",
    monitor_run_id: "run",
    session_id: "session",
    change_type: "new_finding",
    severity: "medium",
    description: "Change",
    alerted: false,
    created_at: "2026-06-05T12:00:00Z",
    ...overrides,
  };
}
