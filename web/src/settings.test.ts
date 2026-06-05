import { describe, expect, it } from "vitest";
import { sanitizedConfigForCopy } from "./pages/Settings";

describe("settings config copy helpers", () => {
  it("redacts secret-shaped config values before sharing", () => {
    const copied = JSON.parse(sanitizedConfigForCopy({
      server: {
        api_key: "secret-key",
        api_key_set: true,
      },
      llm: {
        token: "model-token",
        api_key_set: false,
      },
      nested: {
        cookie_header: "session=private",
        safe: "configured",
      },
    }));

    expect(copied.server.api_key).toBe("[REDACTED]");
    expect(copied.server.api_key_set).toBe(true);
    expect(copied.llm.token).toBe("[REDACTED]");
    expect(copied.llm.api_key_set).toBe(false);
    expect(copied.nested.cookie_header).toBe("[REDACTED]");
    expect(copied.nested.safe).toBe("configured");
  });
});
