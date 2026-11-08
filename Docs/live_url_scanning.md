# Phase 5 design proposal: live URL scanning

**Status:** agreed 2026-11-05 — D11a–D11f accepted as recommended (section 8). Build order in section 9.

## 1. The problem

The URL models are trained on F1–F95. Only F1–F45 come from the URL string. The rest come
from evidence the **snapshot container** collected when each URL was captured:

| Features | Evidence | Contacts |
|---|---|---|
| F1–F45 URL lexical | the URL string | nobody |
| F46–F52 registration | RDAP (`data/rdap/`) | the TLD registry |
| F53–F56 DNS | `dns.json` (resolver queries) | DNS resolvers / the domain's name servers |
| F57–F58 Tranco | the downloaded Tranco list | nobody |
| F59–F64 TLS | `tls.json` (handshake on port 443) | **the target host** |
| F65 ASN | (always missing, decided) | — |
| F66–F95 page | `page.html` (plain GET) | **the target host** |

For a live scan the same evidence is needed, but the safety rule says: *phishing pages are
fetched only by the snapshot collector, inside its container, with plain HTTP GET: no
JavaScript, no form submission, no binary downloads.* So the API itself must never contact
the target.

## 2. Proposed architecture

```
extension / gateway ──X-API-Key──▶ API (backend/)            no outbound requests to targets
                                     │  F1–F45, Tranco, scoring, verdict
                                     │  enqueue "collect evidence for URL", wait ≤ deadline
                                     ▼
                                   Redis (compose network only, never published)
                                     ▼
                              evidence collector (container)   same image and limits as `snapshot`
                                     │  reuses ml/phishguard_ml/data/snapshot.py functions:
                                     │  check_safe_target, fetch_page, dns_info, tls_info;
                                     │  rdap.fetch (single try, short timeout)
                                     ▼
                                   the internet
```

- **API**: computes F1–F45 and the Tranco features locally, asks the collector for evidence
  through a Redis-backed Celery queue (`evidence`), builds `UrlEvidence`, calls the same
  `extractor.url_features`, scores, answers. It has no code path that opens a connection to a
  scanned URL. A test enforces this (section 7).
- **Evidence collector**: a Celery worker in a container built from `ml/Dockerfile` (it
  already holds the snapshot code and sets `PHISHGUARD_IN_SNAPSHOT_CONTAINER=1`), with the
  `snapshot` service's isolation: `cap_drop: [ALL]`, `no-new-privileges`, non-root, no
  database or encryption secrets, only the Redis URL. It returns the same structures the
  snapshot collector writes (`meta`, page bytes, `dns`, `tls`, `rdap`), so training and live
  evidence have one format.
- **Why not reuse the `snapshot` service as it is:** it is a batch job over the dataset
  (writes folders, no queue, 10 s timeouts per hop). Live scans need a request/response path
  with a hard deadline; the functions are reused, the batch loop is not.

## 3. Two evidence stages (fewer contacts with the target)

Fetching every page a user opens would (a) contact phishing hosts for every scan, (b) repeat
GET requests that can have side effects (one-time login links, unsubscribe and
password-reset confirmations), and (c) be slow. Proposed:

| Stage | Features | Contacts | When |
|---|---|---|---|
| 1 | F1–F45, F53–F56 (DNS); no RDAP, see D11c | resolvers — **not** the target host | every scan |
| 2 | + F59–F64 (TLS), F66–F95 (page) | the target host, via the collector | only if stage 1 is uncertain **and** the URL is safe to fetch |

- Two models per deployment: **M1** trained on the stage-1 feature set, **M2** on the full live
  set (section 4). Both are trained on the development split like every other model, so no new
  data is needed (the dataset already has all evidence).
- The "uncertain" band for M1 (e.g. 0.15–0.85) is chosen on development OOF predictions for a
  target share of fetched URLs; never on the locked test set.
- **Safe to fetch** = no query parameter that looks like a secret (names such as `token`,
  `code`, `key`, `session`, `sid`, `auth`, `sig`, `otp`, `reset`, `ticket`, or a long random
  value). Such URLs are decided by stage 1 alone and can be at most **warn**, never silently
  allowed or blocked on page evidence that was not collected.

## 4. Which features the live model uses (training/serving skew)

- **RDAP (F46–F52):** in training, RDAP was fetched slowly with retries; missingness differs
  by class (decision 2026-11-02). Live, registries rate-limit, so a 2–3 s single try will often
  fail and the features would be missing for reasons the model never saw. Proposal: the
  deployed models do **not** use F46–F52 (the `no_rdap` result already exists for RQ1).
  RDAP stays in the thesis evaluation.
- **Tranco (F57–F58):** they separate the training classes by construction (every legitimate
  URL came from Tranco). Live, a legitimate site outside the Tranco top list would look
  suspicious. Proposal: the deployed models also leave out F57–F58.
- **F55 `num_name_servers` (found while building the sets, 2026-11-06):** it falls back to the RDAP
  name servers when DNS gives none, so without RDAP the same URL could get another value live
  than in training. It follows D11c and stays out of both deployed models too.
- So: **M2 = F1–F95 without F46–F52, F55, F57–F58 and F65** (84 features; F65 is always missing);
  **M1 = F1–F45 + F53, F54, F56** (48 features). Two feature sets in `training/devdata.py`
  (`live`, `live_stage1`), reported next to the RQ1 results.

## 5. Safety changes needed before live use

1. **DNS rebinding (must fix).** `check_safe_target` resolves and checks the host, but httpx
   resolves it **again** when it connects; a hostile name server can answer a public address
   first and an internal one second. For user-submitted URLs this is server-side request
   forgery. Fix: connect to the address that was checked (pin the resolved IP for the request,
   keep the host name for TLS SNI and the Host header), for every redirect hop and for the TLS
   handshake. The batch collector benefits too; stored data does not change.
2. **Abuse as a request proxy:** per-API-key rate limit on scans and a per-URL evidence cache
   (Redis, e.g. 1 h), so PhishGuard cannot be used to hammer a site.
3. **Collector egress only:** the collector has no inbound ports; Redis is not published to
   the host network.
4. Unchanged rules: plain GET, no JavaScript, no forms, HTML only, 2 MB cap, no cookies,
   one hop at a time with the safety check on each hop.

## 6. Deadlines and degraded answers

- Batch timeouts allow ~60 s per page (6 hops × 10 s). Live: **one deadline for all evidence,
  e.g. 6 s** (collector side), page and TLS in parallel with DNS.
- If evidence is late or fails, the API answers with what it has, using M1, and marks the
  result `evidence: "partial"`. Proposed policy: a partial answer can be **block** (if M1 alone
  is confident) or **warn**, but an uncertain partial answer becomes **warn**, not allow.
- Cache as built (2026-11-06): verdict per URL in Redis, 1 h, or 5 min for a partial answer. It
  replaces the per-URL evidence cache: a repeated scan does not contact the target at all. There
  is no per-host DNS cache, because the stage 1 lookup goes to a resolver, not to the target. RDAP
  is not used (D11c). Keys are hashes of the URL, so Redis holds no URLs.
- Latency is measured per stage and reported (Phase 5 acceptance check).

## 7. Tests (acceptance checks for this part)

- **No target contact from the API:** a test fails if any module under
  `phishguard/services/` other than `intel/` imports `httpx`, `socket`, `ssl`, `dns` or
  `urllib.request`.
- **Parity:** one stored snapshot folder → the collector result format → the API's
  `UrlEvidence` gives exactly the same 140 values as `ml/.../features/matrix.url_evidence` (one
  shared builder function in the backend, used by both).
- **SSRF:** private, loopback and link-local targets refused; a resolver that answers public
  then private (rebinding) is refused; redirects to private addresses are refused.
- **Secrets in URLs:** token-like URLs are never sent to stage 2.
- **Deadline:** a collector that does not answer in time gives a stage-1 answer marked
  partial, never an error to the extension.
- All offline (mocked network, fake collector), like every other test.

## 8. Decisions needed

| ID | Question | Recommendation |
|---|---|---|
| D11a | Evidence collector as its own Celery worker container (same isolation as `snapshot`), reached through Redis? | Yes |
| D11b | Two stages (no target contact first; fetch only when uncertain and safe), or always fetch? | Two stages |
| D11c | Deployed URL models without RDAP (F46–F52) and Tranco (F57–F58)? | Yes; RDAP and Tranco stay in the RQ1 evaluation |
| D11d | URLs with secret-looking query parameters never fetched, verdict at most warn? | Yes |
| D11e | Partial evidence: uncertain → warn (never silent allow)? | Yes |
| D11f | Fix DNS rebinding by connecting to the checked IP, in the batch collector too? | Yes, before any live use |

## 9. Order of work once agreed

1. Pinned-IP fetching (D11f) + SSRF tests — in the shared snapshot code.
2. Shared evidence builder (backend) used by `matrix.url_evidence` and the API + parity test.
3. Collector worker (Celery task, compose service, isolation) + deadline handling.
4. Feature sets `live`, `live_stage1`; train M1 / M2 with the Phase 3 pipeline (after the split).
5. API wiring: stage 1, stage 2, caches, partial answers, persistence to `scans`, latency
   measurement.
6. End-to-end test with the extension and the gateway.
