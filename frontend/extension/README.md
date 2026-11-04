# PhishGuard browser extension

WebExtension Manifest V3 (Chrome / Edge), Phase 7.

```
public/manifest.json   copied into dist/ by the build
public/popup.html      settings: API address and API key (stored in chrome.storage.local)
public/blocked.html    warning page shown instead of a blocked page
src/api.ts             pure logic, unit-tested (src/api.test.ts)
src/background.ts      service worker: checks each page with POST /scan/url
src/settings.ts        reads / saves the settings
```

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

Still open for Phase 7: the visual-similarity check (decision D6), and checking before the
page is shown (declarativeNetRequest); today the check starts when the tab begins loading.
