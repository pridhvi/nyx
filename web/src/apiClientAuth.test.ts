import { afterEach, describe, expect, it, vi } from "vitest";
import { authExpiredEvent, listSessions } from "./api/client";

const originalFetch = globalThis.fetch;
const originalWindow = globalThis.window;
const originalCustomEvent = globalThis.CustomEvent;

afterEach(() => {
  globalThis.fetch = originalFetch;
  vi.stubGlobal("window", originalWindow);
  vi.stubGlobal("CustomEvent", originalCustomEvent);
  vi.restoreAllMocks();
});

describe("API auth expiry notification", () => {
  it("dispatches an auth-expired event for API 401 responses", async () => {
    const dispatchEvent = vi.fn();
    vi.stubGlobal("window", { dispatchEvent });
    vi.stubGlobal("CustomEvent", class {
      type: string;

      constructor(type: string) {
        this.type = type;
      }
    });
    globalThis.fetch = vi.fn(async () => new Response(JSON.stringify({ error: "unauthorized" }), { status: 401 })) as typeof fetch;

    await expect(listSessions()).rejects.toThrow("unauthorized");
    expect(dispatchEvent).toHaveBeenCalledTimes(1);
    expect(dispatchEvent.mock.calls[0][0]).toMatchObject({ type: authExpiredEvent });
  });

  it("does not dispatch an auth-expired event for other API failures", async () => {
    const dispatchEvent = vi.fn();
    vi.stubGlobal("window", { dispatchEvent });
    vi.stubGlobal("CustomEvent", class {
      type: string;

      constructor(type: string) {
        this.type = type;
      }
    });
    globalThis.fetch = vi.fn(async () => new Response(JSON.stringify({ error: "server failed" }), { status: 500 })) as typeof fetch;

    await expect(listSessions()).rejects.toThrow("server failed");
    expect(dispatchEvent).not.toHaveBeenCalled();
  });
});
