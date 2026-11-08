import { describe, expect, it } from "vitest";

import { blockRule } from "./api";
import {
  MAX_VISITED,
  PRIORITY,
  allowHostsRule,
  allowOnceRule,
  blocklistRule,
  gateOutcome,
  gateRule,
  hostOf,
  hostsFrom,
  remember,
  urlFromHash,
  withTimeout,
} from "./precheck";

const BASE = "chrome-extension://abc/";

describe("gate (D)", () => {
  it("sends GET page loads to the checking page with the URL after #, never the API itself", () => {
    const rule = gateRule(BASE, "127.0.0.1");
    expect(rule.action.redirect?.regexSubstitution).toBe(`${BASE}checking.html#\\1`);
    expect(rule.condition.requestMethods).toEqual(["get"]); // form posts are never redirected
    expect(rule.condition.resourceTypes).toEqual(["main_frame"]);
    expect(rule.condition.excludedRequestDomains).toEqual(["127.0.0.1"]);
    expect(new RegExp(rule.condition.regexFilter!).test("https://a-test.com/x?y=1")).toBe(true);
    expect(new RegExp(rule.condition.regexFilter!).test("file:///c:/x")).toBe(false);
  });

  it("opens the page whatever the API says, except block; no answer means unchecked", () => {
    expect(gateOutcome("block")).toBe("block");
    expect(gateOutcome("warn")).toBe("open");
    expect(gateOutcome("allow")).toBe("open");
    expect(gateOutcome(null)).toBe("open-unchecked");
  });

  it("gives up waiting after the time limit", async () => {
    const slow = new Promise<string>((resolve) => setTimeout(() => resolve("late"), 200));
    expect(await withTimeout(slow, 10)).toBeNull();
    expect(await withTimeout(Promise.resolve("fast"), 100)).toBe("fast");
  });
});

describe("rule priorities", () => {
  it("open once > block > visited > gate", () => {
    const once = allowOnceRule(1000, "https://a-test.com/")!;
    const blocklist = blocklistRule(["a-test.com"], BASE)!;
    const blockedHere = blockRule(1001, "https://a-test.com/")!;
    const visited = allowHostsRule(2, ["a-test.com"])!;
    const gate = gateRule(BASE, null);
    expect(once.priority).toBeGreaterThan(blocklist.priority!);
    expect(blocklist.priority).toBe(PRIORITY.block);
    expect(blockedHere.priority).toBe(PRIORITY.block); // a visited host's blocked URL still stops
    expect(visited.priority).toBeGreaterThan(gate.priority!);
  });

  it("makes no rule from an empty list or a URL with filter characters", () => {
    expect(allowHostsRule(2, [])).toBeNull();
    expect(blocklistRule([], BASE)).toBeNull();
    expect(allowOnceRule(1000, "https://a-test.com/*")).toBeNull();
  });

  it("sends blocked hosts to the warning page with the URL after #", () => {
    const rule = blocklistRule(["evil.test"], BASE)!;
    expect(rule.condition.requestDomains).toEqual(["evil.test"]);
    expect(rule.action.redirect?.regexSubstitution).toBe(`${BASE}blocked.html#\\1`);
  });
});

describe("helpers", () => {
  it("reads hosts", () => {
    expect(hostOf("https://Login.Example.test./a")).toBe("login.example.test");
    expect(hostOf("chrome://settings")).toBeNull();
    expect(hostOf("not a url")).toBeNull();
  });

  it("keeps the most recent visited hosts only", () => {
    const full = Object.fromEntries(Array.from({ length: MAX_VISITED }, (_, i) => [`h${i}.test`, i]));
    const visited = remember(full, "new.test", MAX_VISITED);
    expect(Object.keys(visited)).toHaveLength(MAX_VISITED);
    expect(visited["h0.test"]).toBeUndefined(); // the oldest visit goes
    expect(visited["new.test"]).toBe(MAX_VISITED);
    expect(remember({ "a.test": 1 }, "a.test", 9)).toEqual({ "a.test": 9 });
  });

  it("takes only clean host names from the API, and nothing from a bad answer", () => {
    expect(hostsFrom(200, { hosts: ["a.test", "192.0.2.7", "bad host", 5, "x/y"] })).toEqual([
      "a.test",
      "192.0.2.7",
    ]);
    expect(hostsFrom(404, { hosts: ["a.test"] })).toBeNull();
    expect(hostsFrom(200, { nothing: true })).toBeNull();
  });

  it("reads the URL after #, including a # inside it", () => {
    expect(urlFromHash("#https://a-test.com/p?q=1#frag")).toBe("https://a-test.com/p?q=1#frag");
    expect(urlFromHash("")).toBe("");
  });
});
