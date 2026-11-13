// Checking a page before it is shown (Phase 7, options C + D in Docs/extension_precheck_proposal.md).
// Pure logic, no chrome.* calls, so it can be unit-tested. Rules, highest priority first:
//   4  allow once: the user chose "Open once anyway" for this exact URL
//   3  block: hosts PhishGuard blocked recently (C), and URLs blocked in this browser
//   2  allow: hosts this browser has visited before, or could not check this session
//   1  gate: any other page load (GET, top frame) goes to the checking page first (D)
import type { Verdict } from "./api";

type Rule = chrome.declarativeNetRequest.Rule;

export const GATE_RULE_ID = 1;
export const VISITED_RULE_ID = 2;
export const BLOCKLIST_RULE_ID = 3;
export const UNCHECKED_RULE_ID = 900; // session rule: hosts that could not be checked
export const FIRST_SESSION_RULE_ID = 1000; // per-URL session rules start here

export const PRIORITY = { gate: 1, allow: 2, block: 3, allowOnce: 4 } as const;
/** How long a first visit waits. Set 2026-11-11 from measured live latency
 *  (live-latency --n 200: all-answered p95 3.7 s; suggested_gate_timeout_ms 3800). */
export const GATE_TIMEOUT_MS = 3800;
export const MAX_VISITED = 5000;
export const BLOCKLIST_REFRESH_MINUTES = 5;

const MAIN_FRAME = ["main_frame" as chrome.declarativeNetRequest.ResourceType];
const ANY_WEB_PAGE = "^(https?://.*)$";

/** Lower-case host of an http(s) URL, or null. */
export function hostOf(url: string): string | null {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return null;
    return parsed.hostname.toLowerCase().replace(/\.$/, "") || null;
  } catch {
    return null;
  }
}

/** Sends a page load to `page` with the original URL after "#" (read back by that page). */
function redirectTo(page: string): chrome.declarativeNetRequest.RuleAction {
  return {
    type: "redirect" as chrome.declarativeNetRequest.RuleActionType,
    redirect: { regexSubstitution: `${page}#\\1` },
  };
}

/** D: every GET page load not allowed by a higher rule goes to the checking page first. */
export function gateRule(extensionBase: string, apiHost: string | null): Rule {
  return {
    id: GATE_RULE_ID,
    priority: PRIORITY.gate,
    action: redirectTo(`${extensionBase}checking.html`),
    condition: {
      regexFilter: ANY_WEB_PAGE,
      resourceTypes: MAIN_FRAME,
      requestMethods: ["get" as chrome.declarativeNetRequest.RequestMethod],
      ...(apiHost ? { excludedRequestDomains: [apiHost] } : {}),
    },
  };
}

/** Hosts that skip the gate. A rule for a host also covers its subdomains. Null if none. */
export function allowHostsRule(id: number, hosts: string[]): Rule | null {
  if (hosts.length === 0) return null;
  return {
    id,
    priority: PRIORITY.allow,
    action: { type: "allow" as chrome.declarativeNetRequest.RuleActionType },
    condition: { requestDomains: hosts, resourceTypes: MAIN_FRAME },
  };
}

/** C: hosts PhishGuard blocked recently, stopped before they load. Null if none. */
export function blocklistRule(hosts: string[], extensionBase: string): Rule | null {
  if (hosts.length === 0) return null;
  return {
    id: BLOCKLIST_RULE_ID,
    priority: PRIORITY.block,
    action: redirectTo(`${extensionBase}blocked.html`),
    condition: { regexFilter: ANY_WEB_PAGE, requestDomains: hosts, resourceTypes: MAIN_FRAME },
  };
}

/** "Open once anyway" for one exact URL, above every block. Null if the URL can't be a filter. */
export function allowOnceRule(id: number, url: string): Rule | null {
  if (/[*^|]/.test(url)) return null;
  return {
    id,
    priority: PRIORITY.allowOnce,
    action: { type: "allow" as chrome.declarativeNetRequest.RuleActionType },
    condition: { urlFilter: `|${url}|`, resourceTypes: MAIN_FRAME },
  };
}

/** Remembers a visited host (time of the last visit), keeping the MAX_VISITED most recent. */
export function remember(
  visited: Record<string, number>,
  host: string,
  now: number,
): Record<string, number> {
  const updated = { ...visited, [host]: now };
  const hosts = Object.keys(updated);
  if (hosts.length <= MAX_VISITED) return updated;
  hosts.sort((a, b) => updated[b] - updated[a]);
  return Object.fromEntries(hosts.slice(0, MAX_VISITED).map((h) => [h, updated[h]]));
}

/** What the checking page does with the API's answer (null = no answer in time, or an error). */
export function gateOutcome(verdict: Verdict | null): "block" | "open" | "open-unchecked" {
  if (verdict === "block") return "block";
  return verdict === null ? "open-unchecked" : "open";
}

/** A promise's value, or null if it takes longer than `ms` (the promise itself keeps running). */
export function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T | null> {
  return Promise.race([promise, new Promise<null>((resolve) => setTimeout(() => resolve(null), ms))]);
}

/** The blocked hosts from the API's answer, or null if the answer is not usable. */
export function hostsFrom(status: number, body: unknown): string[] | null {
  if (status !== 200 || typeof body !== "object" || body === null) return null;
  const hosts = (body as { hosts?: unknown }).hosts;
  if (!Array.isArray(hosts)) return null;
  return hosts.filter((h): h is string => typeof h === "string" && /^[a-z0-9.:\-[\]]+$/.test(h));
}

/** The URL a redirect put after "#" on the checking or warning page. */
export function urlFromHash(hash: string): string {
  return hash.startsWith("#") ? hash.slice(1) : hash;
}
