import { afterEach, describe, expect, it, vi } from "vitest";

import { ApiError, apiGet, buildUrl } from "./client";

describe("buildUrl", () => {
  it("joins base and path with exactly one slash", () => {
    expect(buildUrl("/health", "http://api.test/")).toBe("http://api.test/health");
    expect(buildUrl("health", "http://api.test")).toBe("http://api.test/health");
  });
});

describe("apiGet", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("returns parsed JSON on success", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response(JSON.stringify({ status: "ok" }), { status: 200 })),
    );

    await expect(apiGet<{ status: string }>("/health")).resolves.toEqual({ status: "ok" });
  });

  it("throws ApiError with the status code on failure", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("", { status: 503 })));

    await expect(apiGet("/health")).rejects.toMatchObject({ name: "ApiError", status: 503 });
    await expect(apiGet("/health")).rejects.toBeInstanceOf(ApiError);
  });
});
