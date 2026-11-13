# PhishGuard browser extension

WebExtension Manifest V3 (Chrome / Edge), Phase 7.

```
public/manifest.json   copied into dist/ by the build
public/popup.html      settings: API address and API key (stored in chrome.storage.local)
public/blocked.html    warning page shown instead of a blocked page
public/checking.html   the page a first visit to a new host waits on
src/api.ts             pure logic, unit-tested (src/api.test.ts)
src/precheck.ts        rules for checking before a page loads, unit-tested (src/precheck.test.ts)
src/visual.ts          D6 favicon look-alike check, unit-tested (src/visual.test.ts)
src/brandHashes.json   brand favicon hashes, made by `python -m phishguard_ml brand-icons`
src/background.ts      service worker: checks each page with POST /scan/url
src/settings.ts        reads / saves the settings
```

Visual-similarity check (D6): when a page has loaded, its favicon is hashed (64-bit difference
hash) and compared with the brands' own favicons. Within 8 bits of a brand, on a site that is not
one of that brand's domains, the tab gets the "!" badge and a title naming the brand. It never
blocks. The favicon is read from a data: URL or the browser's favicon cache (Chrome and Edge,
`favicon` permission); a favicon address on the web is never fetched.

Behaviour: `block` → the extension's warning page; `warn` → a "!" badge on the tab;
`allow` → nothing. If the API is unreachable, the key is wrong, or the API has no trained
model yet (HTTP 503), the extension does **nothing** — it never guesses.

Privacy: every visited http(s) URL (with its query string) is sent to the configured API.
Point it only at your own PhishGuard API; the API never submits URLs to VirusTotal.

```powershell
npm install
npm test            # unit tests
npm run build       # type-check + build -> dist/
```

Load it: `chrome://extensions` → Developer mode → **Load unpacked** → choose `dist/`. Then
open the toolbar popup and enter the API address (default `http://127.0.0.1:8000`) and the
`PHISHGUARD_API_KEY` from `.env`.

Checking before the page is shown (`src/precheck.ts`, decisions.md 2026-11-09):
- hosts PhishGuard blocked recently (`GET /extension/blocked-hosts`, refreshed every 5 minutes) go to
  the warning page before they load;
- a first visit to a host this browser has not visited waits on `checking.html` for at most 3.8 s
  (`GATE_TIMEOUT_MS`, set 2026-11-11 from measured live latency, p95 3.7 s); any answer but block
  opens it, and no answer opens it unchecked for this session;
- visited hosts are kept in `chrome.storage.local` only, never sent anywhere; form posts are never
  redirected.

Loaded and tried in headless Edge on 2026-11-09 (blocklist, first and second visit). Rebuilt
2026-11-12 (picks up `GATE_TIMEOUT_MS=3800`); 28 unit tests pass. The "allow" path with trained URL
models was confirmed 2026-11-12 at the API boundary the service worker calls: `POST /scan/url` for
`http://example.com/` returned a real verdict (`url-live-lightgbm`, two-stage cascade, SHAP
explanations), and `GET /extension/blocked-hosts` answers 401 without the key and 200 with it. Still
open (need a person at a browser): a Firefox run and the D6 favicon check in a real browser.
