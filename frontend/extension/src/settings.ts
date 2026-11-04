/// <reference types="chrome" />
import { DEFAULT_SETTINGS, type Settings } from "./api";

export async function loadSettings(): Promise<Settings> {
  const stored = await chrome.storage.local.get(["apiBaseUrl", "apiKey"]);
  return {
    apiBaseUrl: typeof stored.apiBaseUrl === "string" && stored.apiBaseUrl ? stored.apiBaseUrl : DEFAULT_SETTINGS.apiBaseUrl,
    apiKey: typeof stored.apiKey === "string" ? stored.apiKey : DEFAULT_SETTINGS.apiKey,
  };
}

export async function saveSettings(settings: Settings): Promise<void> {
  await chrome.storage.local.set(settings);
}
