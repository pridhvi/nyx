import { describe, expect, it } from "vitest";
import { burpResultRow, callbackRows, credentialRows, credentialState, payloadRows, powerFeatureLabel, powerState, providerStatusRows, redactedCallbackEvent } from "./pages/PowerFeatures";
import type { BurpStatusResponse, CredentialFinding, Payload, PowerCallback, ProviderStatus } from "./api/client";

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
    expect(credentialRows([credential])[0][2]).toBe("********");
  });

  it("formats provider, callback, and Burp state rows", () => {
    const statuses: ProviderStatus[] = [{ id: "ps1", session_id: "s1", provider: "github", module: "code_search", status: "skipped", message: "missing token", created_at: "" }];
    const callbacks: PowerCallback[] = [{ id: "cb1", session_id: "s1", provider: "builtin", token: "tok", url: "http://127.0.0.1/cb/tok", received: true, source_ip: "127.0.0.1", raw_event: "GET", created_at: "", updated_at: "" }];
    const burp: BurpStatusResponse = { configured: true, available: false, result: { available: false, action: "status", message: "Burp REST base URL is not configured" } };
    expect(providerStatusRows(statuses)[0]).toEqual(["github", "code_search", "skipped", "missing token"]);
    expect(callbackRows(callbacks)[0]).toEqual(["builtin", "received", "http://127.0.0.1/cb/tok", "127.0.0.1", "GET"]);
    expect(burpResultRow(burp)).toEqual(["unavailable", "Burp REST base URL is not configured"]);
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
