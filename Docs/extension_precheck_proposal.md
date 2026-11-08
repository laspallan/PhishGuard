# Proposal: stopping a blocked page before it is shown (Phase 7)

Status: **C + D chosen and built (2026-11-09).** What was built, and where it differs from this
proposal (hosts instead of domains, visited hosts in plain text, GET only), is in
`Docs/decisions.md`, "Extension: checking before the page is shown".

## The problem today

`background.ts` starts the API check on `tabs.onUpdated` (the tab has begun loading). A page rated
**block** is then replaced by the warning page, and a session `declarativeNetRequest` rule stops
later visits to the same URL before they load. So on a **first visit** the phishing page can be on
screen for as long as the API takes to answer, and the user could type into it during that time
(decisions.md, "Extension: first visit and API downtime"). In MV3, Chrome gives extensions no way to
hold a request while asking a server (blocking `webRequest` is reserved for enterprise-installed
extensions); rules must exist before the request.

## Options

| | What it does | First visit protected? | Cost to every page | Work |
|---|---|---|---|---|
| A | Keep today's design | No | None | None |
| B | Send every navigation to an extension "checking" page that asks the API, then continues | Yes | The full API wait on every page; breaks form posts and back/forward | Medium |
| C | Download a list of domains PhishGuard has recently blocked, and install them as dynamic rules | Only for domains already seen by PhishGuard | None | Small |
| D | Hold only the **first visit to a domain this browser has not visited before**, on the checking page, with a short time limit | Yes, for new domains | Only on first visits to new domains | Medium |
| E | Run a URL-only model inside the extension and hold only suspicious URLs | Yes, if the local model flags it | A few ms | Large: a second feature extractor in TypeScript, against the rule of one extractor |

Notes:
- **B** puts the API on the path of every page. Stage 1 alone took 2.7 s in the one real check so far
  (live_url_scanning.md), which would make browsing unusable.
- **C** helps users of one PhishGuard (all users of the same API): once anyone's scan blocks a domain,
  every extension blocks it before it loads. Dynamic rules have a count limit in Chrome (check the
  current number in Chrome's `declarativeNetRequest` documentation before building); a list of recent
  blocks is far below it.
- **D** relies on the fact that most browsing returns to sites already visited. A first visit to a new
  domain waits on the checking page for stage 1 only, up to a limit (for example 2 s; to be set from
  measured stage-1 latency). On a timeout or API error the page opens, as today (fail-open stays).
  The extension would keep a list of visited registrable domains, hashed, in local storage, which
  never leaves the browser.
- **E** is the only option with no waiting, but it needs F1–F45 reimplemented in TypeScript and kept
  identical to the Python extractor, and the model exported to the browser. That breaks the project's
  rule that training and live use one extractor, and needs its own equivalence tests.

## Recommendation

**C and D together**, keeping A's behaviour for everything else.
- C removes the delay for known phishing domains at no cost.
- D closes the first-visit gap for unknown domains, which is where phishing usually is (new
  domains), and costs nothing on sites the user already visits.
- Both keep one feature extractor and the existing fail-open choice.

What it would take: an API endpoint listing recently blocked registrable domains (behind the key);
the extension refreshing it every few minutes into dynamic rules; a checking page with a timer; the
visited-domain list; tests for each; a real-browser test (still open for the extension anyway). Rough
size: two to three working days, plus measuring stage-1 latency first, since D's time limit depends on
it.

## For the thesis

Whatever is chosen, report the first-visit window as measured (time from navigation to warning page),
not as designed, and keep the limitation in Chapter 8 if A stays.
