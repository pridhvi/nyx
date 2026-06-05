import { describe, expect, it } from "vitest";
import { contrastRatio, darkSurfaceColor, severityColorTokens } from "./theme";

describe("severity colors", () => {
  it("keep readable contrast on the dark operator surface", () => {
    for (const [severity, color] of Object.entries(severityColorTokens)) {
      expect(contrastRatio(color, darkSurfaceColor), severity).toBeGreaterThanOrEqual(4.5);
    }
  });
});
