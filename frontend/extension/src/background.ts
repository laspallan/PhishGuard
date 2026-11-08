/// <reference types="chrome" />
// Checks each page the user opens with the PhishGuard API.
// Before a page loads: hosts PhishGuard blocked recently are stopped, and a first visit to a host
// this browser has not visited waits on the checking page for at most GATE_TIMEOUT_MS (precheck.ts).
// After it starts loading: block -> the warning page, and a rule that stops repeat visits;
// warn -> "!" badge on the tab; errors -> nothing (fail-open, Docs/decisions.md).
import { blockRule, blockedPagePath, freshVerdict, scanRequest, shouldScan, verdictFrom } from "./api";
import type { CachedVerdict, Verdict } from "./api";
import brandHashes from "./brandHashes.json";
import {
  BLOCKLIST_REFRESH_MINUTES,
  BLOCKLIST_RULE_ID,
  FIRST_SESSION_RULE_ID,
  GATE_RULE_ID,
  GATE_TIMEOUT_MS,
  UNCHECKED_RULE_ID,
  VISITED_RULE_ID,
  allowHostsRule,
  allowOnceRule,
  blocklistRule,
  gateOutcome,
  gateRule,
  hostOf,
  hostsFrom,
  remember,
  withTimeout,
} from "./precheck";
import { loadSettings } from "./settings";
import { ICON_SIZE, dhash, faviconSource, matchBrand } from "./visual";

const CACHE_KEY = "verdicts";
const ALLOWED_KEY = "allowOnce";
const LOOKALIKE_KEY = "lookalike"; // tab id -> URL whose favicon looked like a brand's
const VISITED_KEY = "visitedHosts"; // local only: host -> last visit; never sent anywhere
const UNCHECKED_KEY = "uncheckedHosts"; // this browser session: hosts the API could not check
const ALARM = "blocklist";

// --- Checking before the page is shown (options C + D, src/precheck.ts) ---

chrome.runtime.onInstalled.addListener(() => void start());
chrome.runtime.onStartup.addListener(() => void start());
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === ALARM) void syncRules();
});
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && ("apiBaseUrl" in changes || "apiKey" in changes)) void syncRules();
});

async function start(): Promise<void> {
  await chrome.alarms.create(ALARM, { periodInMinutes: BLOCKLIST_REFRESH_MINUTES });
  await syncRules();
}

async function visitedHosts(): Promise<Record<string, number>> {
  return (await chrome.storage.local.get(VISITED_KEY))[VISITED_KEY] ?? {};
}

/** Hosts PhishGuard blocked recently, or null if the API gave no usable answer. */
async function fetchBlockedHosts(): Promise<string[] | null> {
  const settings = await loadSettings();
  if (!settings.apiKey) return null;
  try {
    const response = await fetch(`${settings.apiBaseUrl.replace(/\/+$/, "")}/extension/blocked-hosts`, {
      headers: { "X-API-Key": settings.apiKey },
    });
    return hostsFrom(response.status, await response.json().catch(() => null));
  } catch {
    return null;
  }
}

/** Installs the gate, the visited-hosts rule and the blocklist. Without an API key: no gate. */
async function syncRules(): Promise<void> {
  const settings = await loadSettings();
  const base = chrome.runtime.getURL("/");
  const blocked = await fetchBlockedHosts();
  const rules = [
    settings.apiKey ? gateRule(base, hostOf(settings.apiBaseUrl)) : null,
    allowHostsRule(VISITED_RULE_ID, Object.keys(await visitedHosts())),
    blocked === null ? null : blocklistRule(blocked, base),
  ].filter((rule): rule is chrome.declarativeNetRequest.Rule => rule !== null);
  // An unusable answer keeps the last blocklist rather than dropping it.
  const removeRuleIds = [GATE_RULE_ID, VISITED_RULE_ID, ...(blocked === null ? [] : [BLOCKLIST_RULE_ID])];
  await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds, addRules: rules });
}

async function rememberHost(url: string): Promise<void> {
  const host = hostOf(url);
  if (!host) return;
  const visited = await visitedHosts();
  const isNew = !(host in visited);
  const updated = remember(visited, host, Date.now());
  await chrome.storage.local.set({ [VISITED_KEY]: updated });
  if (!isNew) return;
  const rule = allowHostsRule(VISITED_RULE_ID, Object.keys(updated));
  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: [VISITED_RULE_ID],
    addRules: rule ? [rule] : [],
  });
}

/** No answer in time: let the host through for this browser session (fail-open, as before). */
async function allowUnchecked(url: string): Promise<void> {
  const host = hostOf(url);
  if (!host) return;
  const stored: string[] = (await chrome.storage.session.get(UNCHECKED_KEY))[UNCHECKED_KEY] ?? [];
  const hosts = stored.includes(host) ? stored : [...stored, host];
  await chrome.storage.session.set({ [UNCHECKED_KEY]: hosts });
  const rule = allowHostsRule(UNCHECKED_RULE_ID, hosts);
  await chrome.declarativeNetRequest.updateSessionRules({
    removeRuleIds: [UNCHECKED_RULE_ID],
    addRules: rule ? [rule] : [],
  });
}

/** A first visit waits on the checking page for at most GATE_TIMEOUT_MS. */
async function gate(tabId: number, url: string): Promise<void> {
  const outcome = gateOutcome(await withTimeout(verdictFor(url), GATE_TIMEOUT_MS));
  if (outcome === "block") {
    await addRule(url);
    await chrome.tabs.update(tabId, { url: chrome.runtime.getURL(blockedPagePath(url)) });
    return;
  }
  if (outcome === "open") await rememberHost(url);
  else await allowUnchecked(url);
  await chrome.tabs.update(tabId, { url });
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "loading") void check(tabId, tab.url);
  if (changeInfo.status === "complete") void visualCheck(tabId, tab.url, tab.favIconUrl);
});

/** D6: warn (never block) when the page's favicon looks like a brand's on someone else's site. */
async function visualCheck(tabId: number, url: string | undefined, favIconUrl?: string) {
  if (!shouldScan(url, await loadSettings())) return;
  // Chrome and Edge have a favicon cache for extensions; Firefox gives a data: URL or nothing.
  const cache = navigator.userAgent.includes("Firefox") ? null : chrome.runtime.getURL("/");
  const source = faviconSource(favIconUrl, url, cache);
  if (!source) return;
  let pixels: Uint8ClampedArray;
  try {
    const bitmap = await createImageBitmap(await (await fetch(source)).blob());
    const canvas = new OffscreenCanvas(ICON_SIZE, ICON_SIZE);
    const context = canvas.getContext("2d");
    if (!context) return;
    context.drawImage(bitmap, 0, 0, ICON_SIZE, ICON_SIZE);
    pixels = context.getImageData(0, 0, ICON_SIZE, ICON_SIZE).data;
  } catch {
    return; // no icon or not readable: no signal, never a guess
  }
  const brand = matchBrand(dhash(pixels), new URL(url).hostname, brandHashes.brands);
  if (!brand) return;
  const stored = await chrome.storage.session.get(LOOKALIKE_KEY);
  await chrome.storage.session.set({ [LOOKALIKE_KEY]: { ...stored[LOOKALIKE_KEY], [tabId]: url } });
  await chrome.action.setBadgeText({ tabId, text: "!" });
  await chrome.action.setBadgeBackgroundColor({ tabId, color: "#b45309" });
  await chrome.action.setTitle({ tabId, title: `PhishGuard: this site uses an icon like ${brand}'s` });
}

async function isLookalike(tabId: number, url: string): Promise<boolean> {
  const stored = await chrome.storage.session.get(LOOKALIKE_KEY);
  return stored[LOOKALIKE_KEY]?.[tabId] === url;
}

// "Open once" on the warning page, and the checking page's request.
chrome.runtime.onMessage.addListener((message: { type?: string; url?: string }, sender) => {
  const tabId = sender.tab?.id;
  if (!message.url || tabId === undefined) return;
  if (message.type === "allow-once") void allowOnce(tabId, message.url);
  if (message.type === "gate") void gate(tabId, message.url);
});

/** The user's choice beats every block (also a host on the blocklist) for this one visit. */
async function allowOnce(tabId: number, url: string): Promise<void> {
  await removeRule(url, "redirect");
  const rule = allowOnceRule(await nextSessionRuleId(), url);
  if (rule) await chrome.declarativeNetRequest.updateSessionRules({ addRules: [rule] });
  const stored = await chrome.storage.session.get(ALLOWED_KEY);
  await chrome.storage.session.set({ [ALLOWED_KEY]: [...(stored[ALLOWED_KEY] ?? []), url] });
  await chrome.tabs.update(tabId, { url });
}

/** True once for a URL the user chose to open. It is used up by this visit. */
async function takeAllowOnce(url: string): Promise<boolean> {
  const stored = await chrome.storage.session.get(ALLOWED_KEY);
  const allowed: string[] = stored[ALLOWED_KEY] ?? [];
  if (!allowed.includes(url)) return false;
  await chrome.storage.session.set({ [ALLOWED_KEY]: allowed.filter((item) => item !== url) });
  await removeRule(url, "allow");
  return true;
}

/** Removes this browser's per-URL rules of one kind ("redirect" = block, "allow" = open once). */
async function removeRule(url: string, type: "redirect" | "allow"): Promise<void> {
  const rules = await chrome.declarativeNetRequest.getSessionRules();
  const removeRuleIds = rules
    .filter((r) => r.condition.urlFilter === `|${url}|` && r.action.type === type)
    .map((r) => r.id);
  await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds });
}

async function nextSessionRuleId(): Promise<number> {
  const rules = await chrome.declarativeNetRequest.getSessionRules();
  return rules.reduce((highest, rule) => Math.max(highest, rule.id), FIRST_SESSION_RULE_ID - 1) + 1;
}

async function addRule(url: string): Promise<void> {
  const rule = blockRule(await nextSessionRuleId(), url);
  if (rule) await chrome.declarativeNetRequest.updateSessionRules({ addRules: [rule] });
}

async function verdictFor(url: string): Promise<Verdict | null> {
  const settings = await loadSettings();
  if (!shouldScan(url, settings)) return null;
  const stored = await chrome.storage.session.get(CACHE_KEY);
  const cache: Record<string, CachedVerdict> = stored[CACHE_KEY] ?? {};
  const known = freshVerdict(cache, url, Date.now());
  if (known) return known;
  const { endpoint, init } = scanRequest(url, settings);
  let verdict: Verdict | null;
  try {
    const response = await fetch(endpoint, init);
    verdict = verdictFrom(response.status, await response.json().catch(() => null));
  } catch {
    return null; // API not reachable: never guess
  }
  if (verdict) {
    await chrome.storage.session.set({
      [CACHE_KEY]: { ...cache, [url]: { verdict, at: Date.now() } },
    });
  }
  return verdict;
}

async function check(tabId: number, url: string | undefined): Promise<void> {
  if (!url) return;
  if (await takeAllowOnce(url)) {
    await chrome.action.setBadgeText({ tabId, text: "!" });
    return;
  }
  const verdict = await verdictFor(url);
  if (verdict === "block") {
    await addRule(url);
    await chrome.tabs.update(tabId, { url: chrome.runtime.getURL(blockedPagePath(url)) });
  } else if (verdict === "warn") {
    await rememberHost(url);
    await chrome.action.setBadgeText({ tabId, text: "!" });
    await chrome.action.setBadgeBackgroundColor({ tabId, color: "#b45309" });
  } else if (verdict === "allow") {
    await rememberHost(url);
    // an "allow" from the API does not clear a lookalike warning for the same page
    if (!(await isLookalike(tabId, url))) await chrome.action.setBadgeText({ tabId, text: "" });
  }
}
