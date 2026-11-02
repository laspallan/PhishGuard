# Design decisions

Each entry: the decision, why, the main alternative and why it was not chosen.

## 2026-11-01 — D0: Repository layout

**Decision:** top-level folders `backend/` (API), `ml/` (offline training and evaluation),
`gateway/` (IMAP gateway), `frontend/` (`dashboard/`, `extension/`) and `Docs/`, with
`docker-compose.yml`, `Makefile` and `.env.example` at the repo root.

**Why:** each top-level folder is one deployable or runnable part of the system, so the
research pipeline (`ml/`) is kept apart from the live service while still sharing code with
it. Compose sits at the root because it starts services from several folders.

**Alternative:** putting `ml/` and `gateway/` inside `backend/`. Not chosen because training
code and its heavy dependencies would then be part of the API package and image.

## 2026-11-01 — MVC structure for the backend

**Decision:** `backend/phishguard/` uses models (SQLAlchemy tables), views (FastAPI routers)
and controllers (logic per resource), plus `schemas/` (Pydantic) and `services/` (feature
extractor, ML, threat intelligence, simulation).

**Why:** views only translate HTTP to function calls, so every controller can be unit-tested
without starting a web server, and the detection logic does not depend on FastAPI.

**Alternative:** putting logic directly in the route functions (the common FastAPI style).
Not chosen because it mixes HTTP handling with detection logic and makes the logic harder to
test and to reuse from `ml/` and `gateway/`.

## 2026-11-01 — `models/` means database tables only

**Decision:** ML models live in `phishguard/services/ml/`; trained model files live under
`data/` (gitignored); `phishguard/models/` holds only database tables.

**Why:** in MVC "model" is the data layer; using the same folder for ML models would give one
word two meanings in the code and in the thesis.

**Alternative:** a single `models/` folder for both. Not chosen because of that ambiguity.

## 2026-11-01 — Feature-based dashboard structure

**Decision:** `frontend/dashboard/src/features/` has one folder per menu item (overview,
detections, campaigns, models, experiments, threat-intel, settings, plus auth), and one
`shared/` folder for anything used by more than one feature. A feature may import only from
`shared/`; `shared/` never imports a feature. A test enforces this. TypeScript is used.

**Why:** each menu item can be built, changed or removed on its own, and the import rule
stops hidden dependencies between pages. TypeScript lets the API response types be checked
against the backend schemas at compile time.

**Alternative:** grouping by file type (`components/`, `pages/`, `hooks/` at the top).
Not chosen because the code for one screen would be spread over many folders.

## 2026-11-01 — Backend is an installable package named `phishguard`

**Decision:** `backend/` is installed with `pip install -e backend[dev]`; `ml/` and `gateway/`
import from `phishguard` (e.g. the feature extractor).

**Why:** CLAUDE.md requires one feature extractor shared by training and the live API;
importing one package guarantees both use the same code.

**Alternative:** copying the extractor into `ml/`. Not chosen because the two copies could
drift apart, which would silently make training features differ from live features.

## 2026-11-02 — LF line endings (`.gitattributes`)

**Decision:** `* text=auto eol=lf` for all text files.

**Why:** scripts and Makefiles run inside Linux containers, where Windows CRLF line endings
break them.

**Alternative:** git's Windows default (`core.autocrlf=true`). Not chosen because files
would differ between Windows checkouts and the containers.

## 2026-11-02 — Research dataset stays in files, not in the database

**Decision:** the 175,000 samples, snapshots, splits and feature matrices live under `/data/`
as hashed files. The database holds only what the running system produces (scans, model
versions, simulations, experiment results).

**Why:** a frozen, hashed split file makes it provable that the locked test set never
changes, and the database stays small.

**Alternative:** a `samples` table. Not chosen because it makes accidental queries on the
locked test set easy and would store large raw HTML in PostgreSQL.

## 2026-11-02 — UUID primary keys for every table

**Decision:** every `id` is a random UUID (version 4), generated in Python.

**Why:** ids can be created before the row is saved (useful for the gateway and Celery
tasks), and they cannot be guessed or counted from the outside, unlike 1, 2, 3...

**Alternative:** auto-increment integers. Not chosen because they leak volumes (e.g. how
many scans exist) and allow guessing other records' ids in API URLs.

## 2026-11-02 — Email addresses encrypted, with a blind index

**Decision:** admin and participant email addresses are encrypted with Fernet (from the
`cryptography` library) using `PHISHGUARD_ENCRYPTION_KEY`. Each also gets an HMAC-SHA256
"blind index" (`email_hash`) under a separate key, used for lookups and uniqueness.

**Why:** the proposal promises that personal data is encrypted. Fernet encryption is
randomised, so an encrypted column cannot be searched; the blind index makes login and
duplicate checks possible without decrypting every row.

**Alternative:** PostgreSQL `pgcrypto`. Not chosen because the key would be sent to the
database in every query and appear in its logs; encrypting in the application keeps the key
out of the database entirely.

## 2026-11-02 — Scans store a hash, not email content; verdict is part of the scan

**Decision:** for email scans only `input_hash`, `sender_domain` and the verdict are kept,
never the body or subject. Score, decision and explanation are columns of `scans`.

**Why:** emails are personal data even in a test mailbox, and the hash is enough to match a
scan to its message. Each scan has exactly one verdict, so a separate table adds only joins.

**Alternative:** storing full messages for later retraining. Not chosen for privacy; the
research dataset comes from the public corpora instead.

## 2026-11-02 — Enums stored as VARCHAR + CHECK constraint

**Decision:** enum columns use SQLAlchemy `Enum(native_enum=False, create_constraint=True)`.

**Why:** adding a new allowed value is a simple constraint change in a migration, and the
same schema works on SQLite for fast unit tests.

**Alternative:** native PostgreSQL `ENUM` types. Not chosen because changing them needs
special migration steps and they do not exist in SQLite.

## 2026-11-02 — D1: Attack categories come from ordered rules

**Decision:** each phishing sample gets the first category whose rule matches:
1. `malware`: the URL path ends in a risky file extension (e.g. .exe, .scr, .zip, .js, .iso),
   or the URL is listed by URLhaus.
2. `brand_impersonation`: a known brand appears in the URL, page title or email text, but the
   registered domain is not that brand's.
3. `credential_harvest`: the page has a password field or a login form, or the email asks the
   reader to sign in or verify an account.
4. `spear`: the email addresses the recipient or their organisation by name.
5. `unknown`: none of the above.
Legitimate samples have no attack category. The exact word lists and the counts per rule are
recorded in `Docs/data_card.md`.

**Why:** none of the sources label attack categories, so a transparent, repeatable rule set is
the only option that can be rebuilt from the scripts and checked by an examiner.

**Alternative:** hand-labelling. Not chosen for 87,500 phishing samples (too slow, hard to
reproduce); a small hand-checked sample is used instead to report how often the rules agree
with a human.

## 2026-11-02 — D3: URL/email mix is fixed after counting the cleaned sources

**Decision:** all sources are downloaded and cleaned first. The URL/email split of the
175,000 samples is then chosen from the real counts (a URL-heavy split is expected because the
Nazario corpus is small), with each modality kept 50% phishing / 50% legitimate.

**Why:** fixing the mix before counting could require more phishing emails than exist, which
would force duplicates or oversampling.

**Alternative:** an even 87,500/87,500 split. Not chosen because it probably needs more
phishing emails than the Nazario corpus contains. URLs and emails are reported separately, so
an uneven mix does not hide weak email results.

## 2026-11-02 — D4: Grouping key for the split

**Decision:** URLs are grouped by registered domain (eTLD+1, using the Public Suffix List);
emails are grouped by sender address, and Enron emails by mailbox owner. Groups never cross
the locked-test / development boundary or the CV folds.

**Why:** grouping keeps near-duplicates (same phishing domain, same sender) on one side of the
split, so the test set measures generalisation rather than memorisation.

**Alternative:** grouping emails by sender domain. Not chosen because every Enron email shares
`enron.com`, which would put the whole Enron corpus on one side of the split.

## 2026-11-02 — Dataset records: Parquet, UUID v5 sample ids

**Decision:** every source is converted to one `SampleRecord` schema and stored as Parquet.
`sample_id` is a UUID version 5 derived from the sample type and the content hash.

**Why:** Parquet keeps column types (dates, timestamps, nulls) and handles large email bodies
safely. A content-derived UUID means identical content gets the same id across sources and
across rebuilds, so de-duplication and the frozen split stay reproducible, while keeping the
"all ids are UUIDs" rule.

**Alternative:** CSV with random UUIDs. Not chosen: CSV loses types and breaks on commas and
newlines inside emails, and random ids would change every time the dataset is rebuilt.

## 2026-11-02 — `ml/` is its own package, `phishguard_ml`

**Decision:** `ml/` is an installable package that uses the local `phishguard` package but
does not declare it as a pip dependency.

**Why:** heavy data and ML libraries stay out of the API's Docker image. Declaring
`phishguard` as a dependency would make pip look for it on PyPI, where an unrelated package
with that name could be installed (a supply-chain risk).

**Alternative:** putting the pipeline inside the backend package. Not chosen for the image
size reason above (see D0).

## 2026-11-02 — Phase 1 data choices (made while building; open to change)

**Tranco: top 100,000 domains, as `https://<domain>/`.** These are sites people actually visit;
the long tail of the top 1M contains many parked or infrastructure-only domains (e.g. a top-5
domain in our check, `ezviz7.com`, does not even resolve). The limit is a setting
(`build --tranco-limit`), recorded in build_report.json.

**Enron: received mail only, deterministic 10% sample, grouped by mailbox owner.** Folders whose
name contains `sent`, `all_documents` or `discussion_threads` are skipped: sent mail is written
by the owner (phishing is received mail) and the other two are copies of other folders. A
message is kept if the SHA-256 of its path falls in the lowest 10%, so the sample is identical
on every rebuild without needing a random seed. Setting: `build --enron-fraction`.

**SpamAssassin: only the three 2003-02-28 ham archives.** The 2002-10-10 archives are earlier
copies of the same messages and the spam archives are spam, not phishing. Note: the messages in
these archives are dated 2002 (the proposal says 2002–2005).

**Snapshot safety beyond CLAUDE.md.** Each redirect hop is checked separately; hosts resolving to
private, loopback, link-local or reserved addresses are never contacted (stops a phishing URL
from reaching the home network or the cloud metadata address); bodies that are not HTML are
never read; pages are capped at 2 MB; no cookies are kept. Snapshot code refuses to run unless
`PHISHGUARD_IN_SNAPSHOT_CONTAINER=1`, which only `ml/Dockerfile` sets. The container gets no
database or encryption secrets, drops all Linux capabilities and runs as a non-root user.

**Malformed emails never stop the pipeline.** Python's email parser raises on some real headers
(e.g. `To: unlisted-recipients:; (no To-header on input)` in Nazario); all header reads go
through `clean.header()`, which returns "" instead.

## 2026-11-02 — D9 finding: PhishTank dates

PhishTank's file lists only phishes still online, but their `submission_time` spans 2011–2026:
2021: 156, 2022: 915, 2023: 6,724, 2024: 16,169, 2025: 7,657, 2026: 19,618 (data card). So the
proposal's "2021–2026" is true by submission date, though 2021–2022 are thin. Decision D9 stays
open for you; this finding supports option (a).

## 2026-11-02 — D10 (OPEN): legitimate URLs are home pages only

Tranco gives domains, so every legitimate URL is `https://<domain>/`, while phishing URLs have
paths, queries and subdomains. A model could reach high accuracy from URL length alone, which
would inflate RQ1. Options: (a) during snapshotting, also take a few same-site links from each
Tranco home page as extra legitimate URLs (deeper pages of real sites); (b) keep home pages and
report it as a limitation; (c) report URL results with and without the lexical path features.
Recommendation: (a), plus (c) as a robustness check. Needs your decision before the split.

## 2026-11-02 — Decided by you: D3 size, D9, D10, snapshot go-ahead ("accept recommendations")

**D3 — dataset size.** The split uses the **largest balanced set available when it is made**,
each modality 50% phishing / 50% legitimate: every phishing email that survives cleaning
(about 9,400, matched by as many legitimate emails once Enron is in) and up to all phishing URLs
(about 51,600 matched by as many legitimate URLs). Expected total ≈ 120,000, below the
proposal's 175,000; the shortfall and its reason (the public phishing-email corpus is small) are
reported in the thesis. The split is made only after Enron, the snapshots and the D10 links are
done, so it is made once with complete data.
*Viva:* "I kept the 50/50 balance and the stratification, and used every usable sample rather
than duplicating phishing emails to reach 175,000; oversampling would have put copies of the same
email on both sides of the split."

**D9 — option (a).** The sources stay as fixed. The thesis describes the phishing URLs as
"PhishTank's verified online list downloaded on 2026-11-02 (submission dates 2021–2026) plus
OpenPhish, then collected daily". No archived dataset is added.

**D10 — options (a) and (c).** (a) While snapshotting, each Tranco home page contributes one
same-site deeper page (chosen deterministically from its links) as an extra legitimate URL, so
legitimate URLs also have paths. (c) In Phase 3, URL results are also reported without the
URL-path features, as a robustness check.

**Snapshots of the real URLs: approved.** Run in the snapshot container, phishing URLs first
(they go offline fastest), then the legitimate ones. A run can be stopped and restarted: URLs that
already have a snapshot folder are not fetched again.

## 2026-11-02 — RDAP collected separately, directly from the registries

**Decision:** registration data is no longer part of the page snapshot. A separate step
(`python -m phishguard_ml rdap`) queries each registered domain once, directly at its registry's
RDAP server from IANA's bootstrap file (RFC 9224), one request at a time per registry with a 0.5 s
pause, retrying HTTP 429/5xx with increasing waits. Results: `data/rdap/<domain>.json`.

**Why:** in the first real run, rdap.org answered most requests with HTTP 429 (too many
requests), and doing RDAP inside the snapshot slowed page capture to ~60 URLs a minute. Pages go
offline within hours; registration records do not, so they can be fetched more slowly. Going to
each registry spreads the load instead of sending everything through one redirector.

**Alternative:** keep using rdap.org with a global rate limit. Not chosen: one shared limit for
~100,000 domains would take days, and rdap.org is a volunteer service.

Note: the first 801 snapshot folders contain an old `rdap.json` (mostly HTTP 429); it is ignored —
feature extraction reads `data/rdap/`.

## 2026-11-02 — Missing registration data is reported, not worked around

First RDAP run: 5,144 answers, 23,907 with no RDAP data (23,806 because IANA's bootstrap file
lists no RDAP server for the TLD: mostly .ru, .de, .jp, .io, .cn, .it, .co, .edu), 948 refused
with HTTP 403 (mostly .xyz, .sbs, .lat, .cyou, .cfd — TLDs common in phishing), 32 rate-limited
(retried on the next run).

**Decision:** registries that refuse requests are respected: no disguised clients or other ways
around the refusal. Missing registration data stays missing, with the reason stored. In Phase 2,
the RDAP features (F46–F52) use the fixed missing value; the data card reports how often they
are missing **per class**; and RQ1 is also reported without F46–F52, so a model cannot score
well just because missingness differs between phishing and legitimate domains.

## 2026-11-02 — Snapshot scope: all phishing URLs, top 30,000 Tranco sites (+ one page each)

At ~220 URLs per minute, snapshotting all 100,000 Tranco home pages plus their links would take
~16 hours, and the D10 link pages would only start after every home page. About 52,000
legitimate URLs are needed to balance the phishing URLs, so the run is: (1) every phishing URL,
(2) the top 30,000 Tranco home pages with one same-site page each (up to 60,000 legitimate URLs).
More can be added later with `snapshot --only legitimate --limit N` (resumable).

## 2026-11-02 — Finding: most live phishing pages show no credential form without JavaScript

After snapshots, `label` gives URL categories: unknown 46,731, credential_harvest 2,965,
brand_impersonation 1,878, malware 18 (of 51,592 phishing URLs). Of the 46,731 unknown, 23,708
answered HTTP 2xx with HTML; the rest were offline (4xx 15,473, network error 6,263, 5xx 118)
or not HTML (1,157). In the 23,708 live unknown pages (rough text checks, overlapping): only
3% contain `<form`, 9% `<input`; 49% redirect by meta refresh or JavaScript, 40% are mostly
`<script>`, 29% are under 2 KB, and 58% contain takedown / parking / bot-check words
(suspended, not found, captcha, "just a moment", …).

**Meaning:** the labeller is not missing forms; the forms are not in the HTML that may be
fetched (no JavaScript, by the safety rule), or the page was already taken down. "unknown" is
the honest label, and it stays.

**Consequences, to decide later (not changed now):**
- Per-category URL results will be based on ~4,900 labelled URLs; email categories are fine.
- Many phishing snapshots are takedown or bot-check pages. Page-content features (Phase 2) on
  those pages describe the takedown, not the attack; Phase 3 should also report URL results
  without page-content features, and per snapshot status (live / offline).
- Option for D1: use PhishTank's own `target` field to mark brand impersonation (source
  metadata, not our guess). Not done without your decision.

## 2026-11-02 — Snapshot metadata is written atomically

One phishing snapshot had an empty `meta.json` (a run was stopped while writing it). Because
the file existed, resume treated it as complete, so it was never fetched again. Now
`meta.json` is written to a temporary file and renamed, and an unreadable `meta.json` counts as
not done. The one affected URL was re-fetched (HTTP 200).
