/// <reference types="chrome" />
// Checks each page the user opens with the PhishGuard API.
// block -> the extension's warning page; warn -> "!" badge on the tab; errors -> nothing.
import { blockedPagePath, scanRequest, shouldScan, verdictFrom } from "./api";
import { loadSettings } from "./settings";

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status !== "loading") return;
  void check(tabId, tab.url);
});

async function check(tabId: number, url: string | undefined): Promise<void> {
  const settings = await loadSettings();
  if (!shouldScan(url, settings)) return;
  const { endpoint, init } = scanRequest(url, settings);
  let verdict = null;
  try {
    const response = await fetch(endpoint, init);
    verdict = verdictFrom(response.status, await response.json().catch(() => null));
  } catch {
    return; // API not reachable: never guess
  }
  if (verdict === "block") {
    await chrome.tabs.update(tabId, { url: chrome.runtime.getURL(blockedPagePath(url)) });
  } else if (verdict === "warn") {
    await chrome.action.setBadgeText({ tabId, text: "!" });
    await chrome.action.setBadgeBackgroundColor({ tabId, color: "#b45309" });
  } else {
    await chrome.action.setBadgeText({ tabId, text: "" });
  }
}
