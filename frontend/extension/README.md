# PhishGuard browser extension

WebExtension Manifest V3 for Chrome, Edge and Firefox. Built in Phase 7.

Planned layout (the standard MV3 parts, not feature folders; the extension is small):

```
manifest.json
background/   service worker: checks navigations against the API, caches verdicts
content/      content script: shows the warning banner when needed
popup/        toolbar popup: verdict for the current page
options/      settings page
pages/        block and warning pages
```

Open design choice for Phase 7: the visual-similarity check (decision D6 in
`Docs/IMPLEMENTATION_PLAN.md`).
