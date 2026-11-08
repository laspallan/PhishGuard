// Pure logic of the extension (no chrome.* calls), so it can be unit-tested.

export type Verdict = "block" | "warn" | "allow";

export interface Settings {
  apiBaseUrl: string;
  apiKey: string;
}

export const DEFAULT_SETTINGS: Settings = { apiBaseUrl: "http://127.0.0.1:8000", apiKey: "" };

/** Only web pages are scanned, and never the PhishGuard API itself. */
export function shouldScan(url: string | undefined, settings: Settings): url is string {
  if (!url) return false;
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return false;
  try {
    return parsed.origin !== new URL(settings.apiBaseUrl).origin;
  } catch {
    return true;
  }
}

export function scanRequest(url: string, settings: Settings): { endpoint: string; init: RequestInit } {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (settings.apiKey) headers["X-API-Key"] = settings.apiKey;
  return {
    endpoint: `${settings.apiBaseUrl.replace(/\/+$/, "")}/scan/url`,
    init: { method: "POST", headers, body: JSON.stringify({ url }) },
  };
}

/**
 * The verdict to act on, or null. Anything but HTTP 200 with a known verdict (API down,
 * wrong key, 503 "no trained model yet") means: do nothing, never guess.
 */
export function verdictFrom(status: number, body: unknown): Verdict | null {
  if (status !== 200 || typeof body !== "object" || body === null) return null;
  const verdict = (body as { verdict?: unknown }).verdict;
  return verdict === "block" || verdict === "warn" || verdict === "allow" ? verdict : null;
}

/** Address of the extension's own warning page for a blocked URL. */
export function blockedPagePath(url: string): string {
  return `blocked.html?url=${encodeURIComponent(url)}`;
}

export const VERDICT_CACHE_MS = 60 * 60 * 1000; // same hour as the API's verdict cache

export interface CachedVerdict {
  verdict: Verdict;
  at: number;
}

/** A remembered verdict that is still fresh. A repeat visit then needs no API call. */
export function freshVerdict(
  cache: Record<string, CachedVerdict>,
  url: string,
  now: number,
): Verdict | null {
  const entry = cache[url];
  return entry && now - entry.at < VERDICT_CACHE_MS ? entry.verdict : null;
}

/**
 * Session rule that stops a known-blocked URL before it loads. A rule cannot wait for the API, so
 * the first visit starts loading and is then replaced; only repeat visits are stopped in advance.
 * Null if the URL holds a character with a special meaning in rule filters.
 */
export function blockRule(
  id: number,
  url: string,
): chrome.declarativeNetRequest.Rule | null {
  if (/[*^|]/.test(url)) return null;
  return {
    id,
    priority: 3, // above the visited-hosts allow rule (precheck.ts, PRIORITY.block)
    action: {
      type: "redirect" as chrome.declarativeNetRequest.RuleActionType,
      redirect: { extensionPath: `/${blockedPagePath(url)}` },
    },
    condition: {
      urlFilter: `|${url}|`,
      resourceTypes: ["main_frame" as chrome.declarativeNetRequest.ResourceType],
    },
  };
}
