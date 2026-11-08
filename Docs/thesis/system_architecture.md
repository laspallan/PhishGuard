# System architecture (draft)

**DRAFT for the thesis.** Facts come from `Docs/live_url_scanning.md`, `Docs/database.md`,
`Docs/decisions.md`, `PROGRESS.md` and the code docstrings, as of 2026-11-09. Items in [brackets]
still need a figure or a check. Section numbers are placeholders.

## 5.1 Overview

PhishGuard checks URLs (through a browser extension) and emails (through an IMAP gateway) in real
time. Both clients send items to one backend API, which extracts the features, runs the trained
models and answers block, warn or allow. A simulation module runs phishing simulations for consenting
participants, and a dashboard shows totals. Every part runs as a Docker Compose service.

```
browser extension ─┐                         ┌─ PostgreSQL (scans, models, simulations)
                   ├─ X-API-Key ─▶  API  ────┼─ Redis ─▶ evidence collector (container) ─▶ internet
IMAP gateway ──────┘                         ├─ model registry and files (data/models/)
dashboard ── read-only admin API ────────────┘
GoPhish (simulations, local only)
```

## 5.2 Backend API

The API is built with FastAPI and Pydantic v2 [cite] and follows a model-view-controller structure.
Views only handle HTTP and call controllers; controllers hold the logic and use services and database
models; "models" means database tables only, and machine-learning code lives in services.

**Table 5.1: Endpoints**

| Endpoint | Purpose |
|---|---|
| `GET /health` | health check (public) |
| `POST /scan/url`, `POST /scan/email` | scan one item, answer a verdict |
| `GET /models` | the registered models |
| `GET /admin/status`, `/admin/overview`, `/admin/scans`, `/admin/campaigns`, `/admin/results`, `/admin/experiments` | read-only data for the dashboard |
| `GET`/`POST /admin/simulation/...` | templates, participants and withdrawal, campaigns, launch, fetching events, completing (Section 5.9) |
| `GET /extension/blocked-hosts` | hosts the extension stops before they load (Section 5.7) |

Every endpoint except `/health` needs the `X-API-Key` header, compared in constant time. Browsers may
read the answers only from the dashboard's own origins (CORS, an exact list, no credentials); CORS
does not protect the API, the key does, but it stops a script on any other site from reading the
local API's answers through the user's browser. Outside
development, the API fails closed: without a configured key, protected endpoints answer 503. Scans
also answer 503 until a trained model is available. The API never returns a placeholder verdict, so
the clients never act on a guess. Scans are rate-limited per API client (60 a minute by default).

## 5.3 Database

PostgreSQL 16 stores operational data only. The research dataset stays in files. Schema changes go
only through Alembic migrations. The main principles are:

- every primary key is a UUID;
- email addresses (participants, administrators) are encrypted with Fernet, and a separate HMAC-SHA256
  "blind index" allows look-ups without decrypting;
- an email scan stores only a hash of the email, the sender domain and the verdict, never the body or
  subject;
- a URL that may carry a secret is stored without its query;
- API keys are stored only as hashes;
- simulation events have no column for submitted form data;
- deleting a participant also deletes their events and samples.

[Table of the 13 tables, from `Docs/database.md`, as an appendix.]

## 5.4 One feature extractor, and the model registry

Training and live scans call the same extractor in the backend package, which produces the 140
features in a fixed order. Stored or collected evidence becomes extractor input only through one
function, shared by both. Recomputing 3,000 real records through the live path gave no differences. A
hash of the extractor code (`feature_code_hash`) is stored with the feature table and with every
model.

The training pipeline writes a **model registry**: a list of registered model versions with their
files and hashes. The API's model loader serves a model only if it was built by the current feature
code and its file still has the recorded hash, because model files run code when loaded. It refuses
paths outside the models folder. Of the usable models, it picks the one with the lowest OOF log loss.
XGBoost and LightGBM answers include SHAP explanations of the top features; a random forest gives none.

## 5.5 Live URL scanning in two stages (decision D11)

Most URL features need evidence about the site: DNS, its TLS certificate and its page. By the safety
rule, only the collector container may fetch a phishing page, so the API itself never contacts the
target. A test fails if any backend service other than threat intelligence can open a network
connection.

**Two stages** reduce contact with the target:

| Stage | Model | Inputs | Contacts | When |
|---|---|---|---|---|
| 1 | M1 (`live_stage1`, 48 features) | URL lexical features and DNS | DNS resolvers, not the target | every scan |
| 2 | M2 (`live`, 84 features) | adds the page and the TLS certificate | the target, through the collector | only when M1 is unsure and the URL is safe to fetch |

Fetching only when needed contacts fewer phishing hosts, is faster, and avoids repeating requests that
can have side effects, such as one-time login links. The band of M1 scores counted as "unsure" is
provisional (0.15–0.85) and will be chosen on development predictions (Chapter 4).

**Deployed features (D11c).** The deployed models leave out the registration features (F46–F52) and
F55, because live registry look-ups are often rate-limited and would be missing for reasons never seen
in training. They also leave out the Tranco features (F57–F58), which separate the training classes by
construction. All of these stay in the RQ1 evaluation.

**The evidence collector (D11a)** is a Celery worker in its own container, reached through a Redis
queue. It reuses the snapshot collector's functions, so live and training evidence share one format.
It has the snapshot container's isolation:

- only its own network, shared with Redis and the API;
- no volume, a read-only file system and no secrets;
- all Linux capabilities dropped, running as a non-root user;
- no inbound ports; it only takes jobs from Redis.

It has one 6-second deadline for all evidence, and lists any parts that arrived late. Like the snapshot
collector, it uses plain GET requests only, refuses private, loopback and link-local addresses, checks
each redirect, and connects only to the address it has just checked, which closes the DNS-rebinding
gap (D11f).

**Rules for what is unknown:**

- **D11d:** a URL with a query parameter that looks like a secret (names such as `token`, `session`,
  `reset`, or a long random value) is never fetched, and its verdict is at most warn;
- **D11e:** if evidence is late or fails, the answer is marked partial. It is block only if M1 alone
  is sure; otherwise it is warn, never allow.

**Caching.** Verdicts are cached in Redis for 1 hour, or 5 minutes for a partial answer, so a repeated
scan does not contact the target again. Cache keys are hashes, so Redis holds no URLs. A Redis failure
does not stop scans.

**Status.** Steps 1–5 of the design are built and tested offline. M1 and M2 are still training, so URL
scans currently answer 503. The end-to-end test with the extension and gateway is still open. Redis is
still published on the PC's loopback address for development tools; the design says it should not be
published. [Update when closed.] As a smoke check, 201 development emails went through the email scan
path with a median latency of 569 ms (p95 995 ms) while training used the CPU [replace with the
measured live latency].

## 5.6 Threat-intelligence service

The service looks up a URL at VirusTotal (API v3) and AlienVault OTX, and combines the answers into
`ti_score` (Chapter 4):

- the VirusTotal client is read-only and never submits a URL, because a submitted URL becomes visible
  to other VirusTotal users and URLs can contain private tokens;
- rate limits follow VirusTotal's public limits (4 a minute, 500 a day); OTX documents no limit, so a
  limit of 30 a minute is applied;
- answers are cached (Redis, or a bounded in-memory cache); failed or incomplete look-ups are not
  cached, so a refused request is never remembered as "clean";
- without keys, or in offline mode, `ti_score` is unknown (None), never 0;
- every raw answer can be recorded with a timestamp, for RQ2.

Live scans do not use `ti_score` yet: whether it should be used is what RQ2 tests, so it is added only
if RQ2 shows it helps [update after RQ2]. While the RQ2 lookups are being recorded, the API makes no
threat-intelligence lookups at all, because each process counts the free VirusTotal limits on its
own and the two together could exceed them.

## 5.7 Browser extension

A WebExtension (Manifest V3) for Chrome, Edge and Firefox checks each page the user opens. Chrome
gives extensions no way to hold a page while asking a server, so checks that must happen **before**
a page loads are prepared in advance as browser rules (`declarativeNetRequest`), in this order:

1. **open once:** the exact URL the user chose to open from the warning page;
2. **block:** hosts the API rated block in the last 7 days (fetched every 5 minutes; host names only,
   since a URL can carry the victim's address, and leaving out any domain with a page rated allow in
   the last 30 days, so one phishing page on shared hosting does not block the whole host), and URLs
   blocked earlier in this browser;
3. **allow:** hosts this browser has visited before (kept only in the browser), or could not check
   during this session;
4. **check:** any other page load (GET, top frame) goes first to the extension's checking page, which
   waits at most 2 s for the API [replace with the limit set from measured stage-1 latency].

After a page starts loading, its verdict acts as before:

- **block:** the page is replaced by the warning page, and a rule stops repeat visits;
- **warn:** a "!" badge on the tab;
- verdicts are cached for an hour, and the API address and key are set in a settings popup;
- if the API is down or has no model, the extension does nothing (**fail-open**), so it never blocks
  browsing on a guess. A first visit whose check gets no answer in time opens unchecked.

Form submissions are never redirected, and sites already visited are never delayed. The logic is
unit-tested, and the built extension was loaded in headless Edge on 2026-11-09: a host on the
blocklist was stopped before loading, a first visit went through the checking page, and a second
visit went straight through. [Add the Firefox run, and the test with trained URL models.]

## 5.8 IMAP email gateway

The gateway scans new email in a mailbox through the API. It is used only with mailboxes the
researcher controls or whose owners consented.

- Messages are fetched with `BODY.PEEK[]`, so the user's mail is never marked as read.
- The last scanned UID (per UIDVALIDITY) is kept in a state file, so each email is scanned once, also
  across restarts.
- Block moves the email to a quarantine folder, warn flags it, and allow leaves it alone.
- If the API is down, answers an error, or has no model yet, the gateway stops the round and retries
  the same email later without acting (**fail-safe**: nothing is lost).

It runs as a non-root container with pinned dependencies, and is tested offline with a fake IMAP
server.

## 5.9 Simulation module

Phishing simulations run through GoPhish 0.12.1, reached only through its documented API. Its ports are
bound to the local machine only. PhishGuard's GoPhish client uses only endpoints checked against the
documentation and the source code: templates, landing pages, groups, sending profiles, campaigns and
results. The safety rules are built into the code and tested:

- no campaign launches unless the university's ethics approval reference is configured;
- every target must have recorded, unwithdrawn consent;
- every template must name a fictional organisation, and a name on the list of real brands is refused;
- landing pages are always created with credential capture off. The landing page is an explanation
  page with no form, which says at once that the email was a simulation;
- the `details` field of GoPhish events, which can hold submitted values, is never read;
- events of people who withdrew are dropped;
- a failed simulation (a click) becomes a training sample made of the template's own text, never
  anything about the participant;
- samples from holdout templates go only to the simulation-holdout set;
- no sample can be marked for the locked test set.

Capture was verified on real GoPhish in a local container with no outgoing email: a password submitted
through a test form did not reach GoPhish, and only the fact of the submission was recorded. The
whole campaign flow (launch, the explanation page, fetching events, completing) was also run through
the real API code against real GoPhish, with a closed SMTP port and a `.test` address so no email
could leave; the explanation page had no form and no outside resources, and no answer named the
participant.

The API talks to GoPhish over TLS with the certificate always checked. GoPhish's own certificate
names no host, so it cannot be checked; PhishGuard therefore gives GoPhish its own certificate (for
`gophish`, `localhost` and `127.0.0.1`) and trusts exactly that file. The API container receives the
certificate but not its private key.

## 5.10 Dashboard

A React dashboard (Vite, Tailwind, Recharts) has pages for an overview, detections, campaigns,
simulation management, experiments, models, threat intelligence and settings. Campaign results are
shown as totals, never individuals, and participants appear by code only: no API answer contains a
participant's address. On the simulation page, launching stays disabled while no ethics approval
reference is set, and withdrawing, launching and completing each ask first. The API key is kept in
session storage. Every page was opened in headless Edge against the running API on 2026-11-08: all
loaded real answers, with no script errors and no sideways scrolling.

## 5.11 Deployment

**Table 5.2: Docker Compose services**

| Service | Profile | Role | Isolation |
|---|---|---|---|
| `postgres` | default | database | port bound to 127.0.0.1 |
| `redis` | default | cache, evidence queue | not published; reached only on the compose networks |
| `api` | default | backend API | port bound to 127.0.0.1 |
| `snapshot` | `collect` | batch evidence for the dataset | no capabilities, non-root, no secrets |
| `collector` | `collect` | daily fresh data for RQ3 | no capabilities, non-root |
| `evidence-collector` | `live` | live scan evidence | own network, read-only, no volume, no secrets, no ports |
| `gophish` | `simulate` | simulations | ports bound to 127.0.0.1 |
| `spamassassin` | `baseline` | signature baseline | no network at all |

Profiles keep the research and simulation services off unless they are started explicitly. A
step-by-step deployment guide (`Docs/deployment.md`) covers every service, and `make results`
recomputes every reported table from the saved files without opening the locked test set.
