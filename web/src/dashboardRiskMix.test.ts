import { describe, expect, it } from "vitest";
import { buildRiskMixData, buildRiskMixSegments, riskMixLabel, riskSegmentAtPoint, riskTooltipLabel } from "./pages/Dashboard";

describe("dashboard risk mix", () => {
  it("keeps only populated severities in display order", () => {
    expect(buildRiskMixData({ info: 2, critical: 0, high: 1, low: 3 })).toEqual([
      { severity: "high", value: 1 },
      { severity: "low", value: 3 },
      { severity: "info", value: 2 },
    ]);
  });

  it("builds labeled donut segments for populated severity counts", () => {
    const segments = buildRiskMixSegments(buildRiskMixData({ high: 1, medium: 3, low: 3, info: 2 }));

    expect(segments.map((segment) => segment.title)).toEqual([
      "high: 1 finding",
      "medium: 3 findings",
      "low: 3 findings",
      "info: 2 findings",
    ]);
    expect(segments[1].value).toBe(3);
    expect(riskTooltipLabel(segments[1])).toBe("medium: 3 findings");
    expect(Number(segments[0].length)).toBeCloseTo(37.7, 1);
    expect(Number(segments[segments.length - 1].offset)).toBeCloseTo(-263.89, 1);
  });

  it("maps hover points on the donut ring to severity segments", () => {
    const segments = buildRiskMixSegments(buildRiskMixData({ high: 1, medium: 3, low: 3, info: 2 }));

    expect(riskSegmentAtPoint(segments, 74, 20)?.severity).toBe("high");
    expect(riskSegmentAtPoint(segments, 128, 74)?.severity).toBe("medium");
    expect(riskSegmentAtPoint(segments, 74, 128)?.severity).toBe("low");
    expect(riskSegmentAtPoint(segments, 36, 36)?.severity).toBe("info");
    expect(riskSegmentAtPoint(segments, 74, 74)).toBeNull();
  });

  it("describes the risk mix for assistive technology", () => {
    expect(riskMixLabel(buildRiskMixData({ critical: 1, medium: 2 }))).toBe("Selected risk mix: 1 critical, 2 medium.");
    expect(riskMixLabel([])).toBe("No severity data yet.");
  });
});
