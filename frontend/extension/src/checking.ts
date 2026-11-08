// The checking page (D): a first visit to a host waits here while the background asks the API.
import { hostOf, urlFromHash } from "./precheck";

const url = urlFromHash(location.hash);
const host = document.querySelector<HTMLElement>("#host");
if (host) host.textContent = hostOf(url) ?? url; // shown as text, never as a link
void chrome.runtime.sendMessage({ type: "gate", url });
