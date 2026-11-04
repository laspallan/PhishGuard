// Warning page shown instead of a page PhishGuard blocked.
const blocked = new URLSearchParams(location.search).get("url") ?? "";
const target = document.querySelector<HTMLElement>("#blocked-url");
if (target) target.textContent = blocked; // shown as text, never as a link
document.querySelector<HTMLButtonElement>("#back")?.addEventListener("click", () => history.go(-2));
