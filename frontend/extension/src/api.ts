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
