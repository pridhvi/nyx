import { describe, expect, it } from "vitest";
import { activeActionReview, blockEventType, burpResultRow, callbackRows, credentialDisplaySecret, credentialRows, credentialState, filterBlockEvents, payloadRows, powerFeatureLabel, powerState, providerStatusRows, providerStatusStrip, redactedCallbackEvent } from "./pages/PowerFeatures";
import type { BlockEvent, BurpStatusResponse, CredentialFinding, Payload, PowerCallback, ProviderStatus } from "./api/client";

describe("power feature view helpers", () => {
  it("summarizes safety configuration with secure defaults", () => {
    expect(powerState(undefined)).toEqual({ activeValidation: false, maxAttempts: 3, callbackProvider: "builtin" });
    expect(powerState({ active_validation: { enabled: true }, credentials: { max_attempts_per_user: 2 }, callbacks: { provider: "interactsh" } })).toEqual({
      activeValidation: true,
      maxAttempts: 2,
      callbackProvider: "interactsh",
    });
  });

  it("formats payload validation state and confidence", () => {
    const payloads: Payload[] = [{
      id: "p1",
      finding_id: "f1",
      session_id: "s1",
      payload_type: "xss",
      payload: "<img>",
      context: "reflected marker",
      bypass_technique: "event",
      confidence: 0.62,
      validated: true,
      validated_response: "HTTP 200 reflected marker",
      rank: 1,
      created_at: "",
    }];
    expect(payloadRows(payloads)[0]).toEqual(["xss", "<img>", "validated", "event", "62%", "HTTP 200 reflected marker"]);
  });

  it("keeps credential passwords redacted and prioritizes lockout status", () => {
    const credential: CredentialFinding = {
      id: "c1",
      session_id: "s1",
      credential_type: "defaults",
      username: "admin",
      password: "********",
      service: "web",
      url: "http://127.0.0.1/login",
      valid: true,
      lockout_detected: true,
      evidence: "lockout indicator observed",
      created_at: "",
    };
    expect(credentialState(credential)).toBe("lockout detected");
    expect(credentialRows([credential])[0][2]).toBe("[REDACTED]");
    expect(credentialDisplaySecret("very-secret-value")).toBe("[REDACTED] ending alue");
  });

  it("formats provider, callback, and Burp state rows", () => {
    const statuses: ProviderStatus[] = [{ id: "ps1", session_id: "s1", provider: "github", module: "code_search", status: "skipped", message: "missing token", created_at: "" }];
    const callbacks: PowerCallback[] = [{ id: "cb1", session_id: "s1", provider: "builtin", token: "tok", url: "http://127.0.0.1/cb/tok", received: true, source_ip: "127.0.0.1", raw_event: "GET", created_at: "", updated_at: "" }];
    const burp: BurpStatusResponse = { configured: true, available: false, result: { available: false, action: "status", message: "Burp REST base URL is not configured" } };
    expect(providerStatusRows(statuses)[0]).toEqual(["github", "code_search", "skipped", "missing token"]);
    expect(callbackRows(callbacks)[0]).toEqual(["builtin", "received", "http://127.0.0.1/cb/tok", "127.0.0.1", "GET"]);
    expect(burpResultRow(burp)).toEqual(["unavailable", "Burp REST base URL is not configured"]);
  });

  it("summarizes provider strip states for configured, skipped, and errored providers", () => {
    const statuses: ProviderStatus[] = [
      { id: "ps1", session_id: "s1", provider: "github", module: "code_search", status: "ok", message: "token works", created_at: "" },
      { id: "ps2", session_id: "s1", provider: "shodan", module: "host_lookup", status: "skipped", message: "missing token", created_at: "" },
      { id: "ps3", session_id: "s1", provider: "securitytrails", module: "dns", status: "error", message: "quota exhausted", created_at: "" },
    ];
    expect(providerStatusStrip(statuses).map((item) => [item.provider, item.state])).toEqual([
      ["github", "available"],
      ["shodan", "unconfigured"],
      ["securitytrails", "error"],
    ]);
  });

  it("builds explicit active action review details", () => {
    const review = activeActionReview("credential", {
      findingID: "finding-1",
      credentialURL: "https://example.test/login",
      credentialUser: "admin",
      credentialPass: "super-secret",
      providers: "github",
      kerberoastSPN: "",
      powerConfig: powerState({ active_validation: { enabled: true }, credentials: { max_attempts_per_user: 2 }, callbacks: { provider: "builtin" } }),
    });
    expect(review?.title).toBe("Credential Check Review");
    expect(review?.impact).toContain("account lockout");
    expect(review?.rows).toContainEqual(["Target", "https://example.test/login"]);
    expect(review?.rows).toContainEqual(["Max Attempts", "2"]);
  });

  it("filters block events by type and time range", () => {
    const events: BlockEvent[] = [
      blockEvent({ id: "waf", status_code: 403, signal: "waf rule", created_at: "2026-06-05T12:00:00Z" }),
      blockEvent({ id: "rate", status_code: 429, signal: "rate limit", backoff_ms: 5000, created_at: "2026-06-05T12:00:00Z" }),
      blockEvent({ id: "old", status_code: 500, signal: "server error", created_at: "2026-05-30T12:00:00Z" }),
    ];
    expect(blockEventType(events[0])).toBe("WAF block");
    expect(filterBlockEvents(events, "rate_limit", "24h", new Date("2026-06-05T13:00:00Z")).map((item) => item.id)).toEqual(["rate"]);
    expect(filterBlockEvents(events, "all", "24h", new Date("2026-06-05T13:00:00Z")).map((item) => item.id)).toEqual(["waf", "rate"]);
  });

  it("redacts callback event secrets before rendering rows", () => {
    const event = "GET /cb?token=secret HTTP/1.1\r\nAuthorization: Bearer test\r\nCookie: session=private\r\n\r\n";
    const redacted = redactedCallbackEvent(event);
    expect(redacted).toContain("token=[redacted]");
    expect(redacted).toContain("Authorization: Bearer [redacted]");
    expect(redacted).toContain("Cookie: [redacted]");
    expect(redacted).not.toContain("secret");
    expect(redacted).not.toContain("session=private");
  });

  it("uses human-readable power feature labels", () => {
    expect(powerFeatureLabel("ad")).toBe("Active Directory");
    expect(powerFeatureLabel("poc")).toBe("PoC Evidence");
    expect(powerFeatureLabel("burp")).toBe("Burp Sync");
  });
});

function blockEvent(overrides: Partial<BlockEvent>): BlockEvent {
  return {
    id: "block",
    session_id: "s1",
    tool_id: "test",
    url: "https://example.test",
    status_code: 403,
    signal: "waf",
    response_snippet: "",
    backoff_ms: 0,
    created_at: "2026-06-05T12:00:00Z",
    ...overrides,
  };
}
