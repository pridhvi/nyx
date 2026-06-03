import { afterEach, describe, expect, it, vi } from "vitest";
import { listSourceDirectories, listSourceRoots } from "./api/client";

const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
  vi.restoreAllMocks();
});

describe("source browser client", () => {
  it("loads source roots", async () => {
    globalThis.fetch = vi.fn(async () => new Response(JSON.stringify({ roots: [{ label: "Workspace", path: "/repo" }] }), { status: 200 })) as typeof fetch;

    await expect(listSourceRoots()).resolves.toEqual({ roots: [{ label: "Workspace", path: "/repo" }] });
    expect(globalThis.fetch).toHaveBeenCalledWith("/api/source-roots", expect.objectContaining({ credentials: "same-origin" }));
  });

  it("encodes directory paths", async () => {
    globalThis.fetch = vi.fn(async () => new Response(JSON.stringify({ path: "/repo one", directories: [] }), { status: 200 })) as typeof fetch;

    await expect(listSourceDirectories("/repo one")).resolves.toEqual({ path: "/repo one", directories: [] });
    expect(globalThis.fetch).toHaveBeenCalledWith("/api/source-dirs?path=%2Frepo%20one", expect.any(Object));
  });
});
