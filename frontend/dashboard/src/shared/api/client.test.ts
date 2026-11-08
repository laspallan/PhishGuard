import { afterEach, describe, expect, it, vi } from "vitest";

import { ApiError, apiGet, apiPost, buildUrl, explainRefusal } from "./client";

describe("apiPost", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("sends JSON with the key and keeps the API's reason for a refusal", async () => {
    sessionStorage.setItem("phishguard.apiKey", "k");
    const fetchMock = vi
      .fn()
      .mockResolvedValue(new Response(JSON.stringify({ detail: "no ethics approval reference" }), { status: 403 }));
    vi.stubGlobal("fetch", fetchMock);

    const error = await apiPost("/admin/simulation/campaigns/x/launch", { a: 1 }).catch((e: unknown) => e);
    sessionStorage.clear();

    const [, init] = fetchMock.mock.calls[0];
    expect(init.method).toBe("POST");
    expect(init.body).toBe('{"a":1}');
    expect(init.headers["X-API-Key"]).toBe("k");
    expect(explainRefusal(error)).toBe("no ethics approval reference");
  });

  it("does not show raw validation errors", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response(JSON.stringify({ detail: [{ loc: ["body", "email"] }] }), { status: 422 })),
    );
    const error = await apiPost("/x", {}).catch((e: unknown) => e);
    expect(explainRefusal(error)).toBe("Some fields are missing or not valid.");
  });
});

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

  it("sends the saved API key", async () => {
    sessionStorage.setItem("phishguard.apiKey", "k");
    const fetchMock = vi.fn().mockResolvedValue(new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);

    await apiGet("/admin/status");
    sessionStorage.clear();

    expect(fetchMock.mock.calls[0][1].headers["X-API-Key"]).toBe("k");
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
