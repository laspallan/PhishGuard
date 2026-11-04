import { describe, expect, it } from "vitest";

import { DEFAULT_SETTINGS, blockedPagePath, scanRequest, shouldScan, verdictFrom } from "./api";

describe("shouldScan", () => {
  it("scans web pages only, not the API itself", () => {
    expect(shouldScan("https://shop-test.com/login", DEFAULT_SETTINGS)).toBe(true);
    expect(shouldScan("http://127.0.0.1:8000/docs", DEFAULT_SETTINGS)).toBe(false);
    expect(shouldScan("chrome://settings", DEFAULT_SETTINGS)).toBe(false);
    expect(shouldScan("not a url", DEFAULT_SETTINGS)).toBe(false);
    expect(shouldScan(undefined, DEFAULT_SETTINGS)).toBe(false);
  });
});

describe("scanRequest", () => {
  it("posts the URL and sends the API key when set", () => {
    const { endpoint, init } = scanRequest("https://a-test.com/", {
      apiBaseUrl: "http://127.0.0.1:8000/",
      apiKey: "k",
    });
    expect(endpoint).toBe("http://127.0.0.1:8000/scan/url");
    expect(init.method).toBe("POST");
    expect((init.headers as Record<string, string>)["X-API-Key"]).toBe("k");
    expect(JSON.parse(init.body as string)).toEqual({ url: "https://a-test.com/" });
  });

  it("sends no key header when none is configured", () => {
    const { init } = scanRequest("https://a-test.com/", DEFAULT_SETTINGS);
    expect(init.headers as Record<string, string>).not.toHaveProperty("X-API-Key");
  });
});

describe("verdictFrom", () => {
  it("acts only on HTTP 200 with a known verdict", () => {
    expect(verdictFrom(200, { verdict: "block" })).toBe("block");
    expect(verdictFrom(200, { verdict: "warn" })).toBe("warn");
    expect(verdictFrom(503, { detail: "no trained model is registered yet" })).toBeNull();
    expect(verdictFrom(401, { verdict: "block" })).toBeNull();
    expect(verdictFrom(200, { verdict: "maybe" })).toBeNull();
    expect(verdictFrom(200, null)).toBeNull();
  });
});

describe("blockedPagePath", () => {
  it("encodes the blocked URL", () => {
    expect(blockedPagePath("https://x-test.com/a?b=1&c=2")).toBe(
      "blocked.html?url=https%3A%2F%2Fx-test.com%2Fa%3Fb%3D1%26c%3D2",
    );
  });
});
