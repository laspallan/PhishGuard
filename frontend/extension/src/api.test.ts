import { describe, expect, it } from "vitest";

import {
  DEFAULT_SETTINGS,
  VERDICT_CACHE_MS,
  blockRule,
  blockedPagePath,
  freshVerdict,
  scanRequest,
  shouldScan,
  verdictFrom,
} from "./api";

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

describe("freshVerdict", () => {
  const cache = { "https://a-test.com/": { verdict: "block" as const, at: 1000 } };

  it("remembers a verdict for an hour, then asks again", () => {
    expect(freshVerdict(cache, "https://a-test.com/", 1000 + VERDICT_CACHE_MS - 1)).toBe("block");
    expect(freshVerdict(cache, "https://a-test.com/", 1000 + VERDICT_CACHE_MS)).toBeNull();
    expect(freshVerdict(cache, "https://other-test.com/", 1000)).toBeNull();
  });
});

describe("blockRule", () => {
  it("redirects exactly this page, before it loads, to the warning page", () => {
    const rule = blockRule(7, "https://a-test.com/login?x=1");
    expect(rule?.id).toBe(7);
    expect(rule?.condition.urlFilter).toBe("|https://a-test.com/login?x=1|");
    expect(rule?.condition.resourceTypes).toEqual(["main_frame"]);
    expect(rule?.action.redirect?.extensionPath).toBe(
      "/blocked.html?url=https%3A%2F%2Fa-test.com%2Flogin%3Fx%3D1",
    );
  });

  it("makes no rule when the URL would act as a wider pattern", () => {
    expect(blockRule(1, "https://a-test.com/*")).toBeNull();
    expect(blockRule(1, "https://a-test.com/a|b")).toBeNull();
    expect(blockRule(1, "https://a-test.com/a^b")).toBeNull();
  });
});
