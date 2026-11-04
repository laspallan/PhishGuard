/// <reference types="chrome" />
// Settings form: where the PhishGuard API runs and the API key it expects.
import { loadSettings, saveSettings } from "./settings";

const form = document.querySelector<HTMLFormElement>("#settings");
const baseInput = document.querySelector<HTMLInputElement>("#apiBaseUrl");
const keyInput = document.querySelector<HTMLInputElement>("#apiKey");
const status = document.querySelector<HTMLParagraphElement>("#status");

void loadSettings().then((settings) => {
  if (baseInput) baseInput.value = settings.apiBaseUrl;
  if (keyInput) keyInput.value = settings.apiKey;
});

form?.addEventListener("submit", (event) => {
  event.preventDefault();
  void saveSettings({ apiBaseUrl: baseInput?.value.trim() ?? "", apiKey: keyInput?.value ?? "" }).then(() => {
    if (status) status.textContent = "Saved.";
  });
});
