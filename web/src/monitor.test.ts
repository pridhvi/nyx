import { describe, expect, it } from "vitest";
import { toggleValue } from "./pages/Monitor";

describe("monitor option helpers", () => {
  it("toggles checkbox options while preserving array payload shape", () => {
    expect(toggleValue(["recon"], "fingerprint")).toEqual(["recon", "fingerprint"]);
    expect(toggleValue(["recon", "fingerprint"], "recon")).toEqual(["fingerprint"]);
  });
});
