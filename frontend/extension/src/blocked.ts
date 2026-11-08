// Warning page shown instead of a page PhishGuard blocked. The URL comes as ?url=... (blocked in this
// browser) or after "#" (a host PhishGuard blocked recently, redirected by a rule).
import { urlFromHash } from "./precheck";

const blocked = new URLSearchParams(location.search).get("url") ?? urlFromHash(location.hash);
const target = document.querySelector<HTMLElement>("#blocked-url");
if (target) target.textContent = blocked; // shown as text, never as a link
document.querySelector<HTMLButtonElement>("#back")?.addEventListener("click", () => history.go(-2));
document.querySelector<HTMLButtonElement>("#once")?.addEventListener("click", () => {
  void chrome.runtime.sendMessage({ type: "allow-once", url: blocked });
});
