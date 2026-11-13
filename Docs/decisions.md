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

## 2026-11-02 — D1 extended: PhishTank's `target` field also marks brand impersonation (you decided)

**Decision:** a phishing URL is `brand_impersonation` if our brand rule matches **or** PhishTank's
`target` column names a brand (anything except "Other"). Malware still comes first. The field is
read from the raw PhishTank files at labelling time (`parse.phishtank_targets`), so the record
format does not change. HTML escapes in the file are decoded (`AT&amp;T` -> `AT&T`).

**Why:** the page-based rules can label only ~4,900 URLs (see the finding above), and the
`target` field is PhishTank's own verified annotation, not a guess of ours. In the file of
2026-11-02, 5,138 of 51,463 rows name one of 93 brands (Allegro 1,899, IRS 790, Amazon 394, …);
46,325 say "Other".

**Limits (for the thesis):** only PhishTank URLs can get it (OpenPhish has no such field), and
the brands are skewed toward Allegro. The data card reports categories as they come out.

**Viva:** "Why trust PhishTank's target?" — It is the source's own annotation, taken from the same
file as the phishing label we already use, not a rule of ours. **Not yet verified:** how
PhishTank assigns `target` (submitter or verifier); check PhishTank's FAQ / developer pages
before the viva and note the answer here.

## 2026-11-02 — D2, D5, D7 decided; Phase 2 conventions (you accepted the recommendations)

- **D2 (signature baseline):** URLs: lookup in blocklist snapshots taken before the sample's
  collection date; emails: SpamAssassin rule score with Bayes off.
- **D5:** separate URL and email models, the same six model types for each.
- **D7:** `ti_score` only for a stratified subset that fits the free API limits (limits checked
  in each provider's docs before coding); RQ2 on that subset; circularity discussed.
- **DistilBERT training:** on Google Colab (rented GPU) — this PC has no NVIDIA GPU. The
  notebook/script must read only the development split; the locked test set stays local.
- **P2-a missing value = NaN.** One fixed missing value for "not applicable" and "could not be
  measured". Viva: XGBoost and LightGBM learn a direction for NaN, so missingness is used
  without inventing a number; a sentinel like −1 collides with real values (F133 ranges −1..1).
- **P2-b modality:** URL records get F1–F95 (F96–F140 = NaN); emails get F96–F140
  (F1–F95 = NaN). Pages linked from emails are never fetched (safety rule).
- **P2-c Tranco leakage:** every legitimate URL comes from Tranco, so F57/F58 separate the
  classes by construction. They stay (the list is fixed), and RQ1 is also reported without
  F57/F58.
- **P2-d lists** (suspicious TLDs, shorteners, ASNs, mailers) come from dated external
  sources, never from our own data (that would leak the test set); each source is recorded.
- **P2-e:** F46–F52 read the stored RDAP files; F96–F101 read only `Authentication-Results`
  headers (no live DNS; old DKIM keys no longer exist). F55 may use RDAP name servers when the
  host-level DNS query has no NS answer.
- **P2-f:** `pyspellchecker` (F129) and `vaderSentiment` (F133) after checking version and
  licence; Flesch reading ease (F130) computed with the published formula.

## 2026-11-02 — Lists for F26 and F27 (sources checked)

- **F26 suspicious_tld:** the 20 TLDs with the highest Phishing Domain Score in Table 2 of
  Interisle Consulting Group, "Phishing Activity in TLDs, May 2025 – April 2026"
  (https://www.cybercrimeinfocenter.org/phishing-activity-in-tlds-may-april-2026, read
  2026-11-02; checked against the page text): xin, win, icu, garden, cfd, pro, help, mom, rest,
  mobi, qpon, live, ink, best, lat, cyou, top, wang, life, homes. The page is "All Rights
  Reserved"; only the TLD names (facts) are used, with citation.
  **Viva:** "Why the score table, not the count table?" — the count table ranks com and net
  first only because they are huge; the score (phishing domains per 10,000 registered) measures
  how *often* a TLD is abused, which is what F26 says. **Threat to validity:** the report's
  period (May 2025 – Apr 2026) overlaps our collection period; the list is still external (not
  derived from our split), but a TLD heavily used in our phishing feeds will also rank there.
- **F27 is_shortened:** PeterDaveHello/url-shorteners, file `list` at commit
  `c0993928ba85b252a89640774e58467249d0ab74` (2026-09-06), 1,454 domains, CC BY-SA 4.0. Stored
  unchanged in `backend/phishguard/services/features/data/url_shorteners.txt` (keeps its
  licence; source, hash and licence in `data/README.md`). Matched on host or registered domain.
- Spamhaus's TLD statistics page (spamhaus.org/statistics/tlds/) now returns 404, so it could
  not be used.

## 2026-11-02 — Finding: URLhaus terms forbid AI training without consent (affects D2, Phase 4)

abuse.ch terms of use (https://abuse.ch/terms-of-use/, effective 4 Nov 2025, s.7.3): "Data or
Confidential Information may not be used by users to customise, train, or otherwise improve any
artificial intelligence model or product … without Spamhaus' express prior written consent."
The URLhaus API and downloads also now need a free Auth-Key (https://auth.abuse.ch/).

**Status:** URLhaus data is not used anywhere yet (the `urlhaus` input of `label` is empty).
**Open for you:** either ask Spamhaus/abuse.ch for written consent, or use URLhaus only where no
model learns from it (e.g. the D2 lookup baseline) and leave it out of `ti_score` and the
malware labelling rule. Recorded so it is decided before Phase 3 (D2) and Phase 4.

## 2026-11-02 — URLhaus only in the blocklist baseline; F65 left out (you decided)

- **URLhaus** is used only for the D2 signature baseline (a lookup; no model learns from it).
  It is removed from the malware labelling rule (it was never filled in) and is not part of
  `ti_score` (Phase 4: VirusTotal + AlienVault OTX only). Reason: abuse.ch terms s.7.3 forbid
  AI training without Spamhaus' written consent. **Viva:** the baseline only compares a URL to
  a list, so it does not "train or improve" a model; the ML models never see URLhaus data.
- **F65 suspicious_asn** is kept in the vector (the 140-feature list is fixed) but is always
  MISSING (NaN): no IP-to-ASN data is collected. A constant column carries no information, so
  the models ignore it; the thesis states F65 as not implemented, with the reason (needs an
  extra IP-to-network dataset and an abuse-ASN list).

## 2026-11-02 — F46–F65: measured at capture time; RDAP changes after capture are not used

RDAP was queried hours or days after each page was captured. A phishing domain that was taken
down in between shows a fresh "last changed" date, which would tell the model the label.
**Decision:** all ages (domain, certificate) are measured at the capture time stored in the
snapshot; F51 is MISSING when "last changed" is after the capture. Thin registries (.com,
Verisign) hold no registrant, so F50/F52 are MISSING there, not 0. Exact rules are in the
`domain_ssl.py` docstring. **Viva:** a feature must be computable at the moment of detection;
anything recorded later can only be used if it could not have been affected by the label.

## 2026-11-02 — Email features: header features from the raw email, text features from the normalised one

The plan says the time-clue normaliser runs "before feature extraction", but it replaces the
X-Mailer and Date values, so F109/F110 could never be measured and "results without the
age-sensitive features" would compare nothing. **Decision:** F96–F115 are computed from the raw
email; F116–F140 and the text models use the normalised email; evaluation drops
`email_headers.AGE_SENSITIVE` (F96–F101, F109, F110) for the age-gap result. F109 uses the three
X-Mailer "known spam mailers" rules of Apache SpamAssassin 4.0.2 (`20_ratware.cf`, Apache 2.0);
no published list names phishing kits, so F109 is almost always 0.

## 2026-11-02 — Finding: Enron headers identify the corpus, not the class (decision needed before Phase 3)

Header presence in the real data: Received 100% Nazario / 97% SpamAssassin / **0% Enron**;
Return-Path 100% / 100% / **0%**; X-Mailer 44% / 38% / **0%**; Authentication-Results
22% / 0% / 0%. The Enron release removed delivery headers, and its Message-IDs end in
`@thyme`, so F103/F106/F107/F108 separate Enron from the rest by corpus format. Enron is 82% of
the legitimate emails (18,808 of 22,916), so an email model with header features would learn
"no Received headers = legitimate". Options (to decide before Phase 3):
(a) headline email results without header features F96–F115; header features evaluated only on
SpamAssassin vs Nazario; (b) also report per legitimate source; (c) drop Enron from
header-feature models. Recommendation: (a) + (b).

## 2026-11-02 — F116–F140 text features: libraries and hand-written word lists

- `pyspellchecker` 0.9.1 (MIT, PyPI `license_expression`) for F129 and `vaderSentiment` 3.3.2
  (MIT) for F133; both work offline (VADER imports only the standard library). F130 Flesch
  reading ease is computed with the published formula and a vowel-group syllable count.
- The urgency / threat / reward / financial / greeting / call-to-action lists and the F138
  weights are **our own**, written by hand before any model was trained and never tuned on the
  data (no published list exists). **Viva:** "Aren't hand-made lists biased?" — they are
  fixed, short, and published in `lexicons.py`; because they were never adjusted to the data,
  they cannot leak the test set, and their effect is measured like any other feature (SHAP).
- Run on all 32,345 real emails (normalised view): no crashes, ~10 ms per email.

## 2026-11-03 — Accepted: Defender exclusion, Enron headers, Phase 3 design, Phase 4 scope

- **Defender:** option 1 — you add a Windows Security exclusion for `D:\PhishGuard\data` only
  (needs administrator rights; your action). Reason: stored phishing pages are research data,
  read as text and never opened in a browser; without the exclusion Defender blocks the most
  typical phishing pages and biases the dataset. Restore the one quarantined page from
  Protection history. To be stated in the thesis ethics / threats-to-validity section.
- **Enron headers (a)+(b):** headline email results are reported **without** header features
  F96–F115; header features are evaluated on SpamAssassin vs Nazario only; results are also
  reported per legitimate source.
- **Phase 3:** Optuna tuning on the 5-fold CV score (single level, not nested; the small
  optimism is stated, the locked test set gives the unbiased estimate in Phase 8);
  calibration and stacking cross-fitted on out-of-fold predictions; xgboost, lightgbm, optuna,
  shap, torch (CPU) after version/licence checks; DistilBERT on Colab with the development
  split only; a guard so no training code can load the locked test set.
- **Phase 4:** URLs only. Subset size and the ti_score formula (fixed formula vs raw inputs)
  are settled at the start of Phase 4 (no recommendation was given yet).

## 2026-11-03 — Phase 3 step 1: development loader, feature sets, tabular models

- Libraries (newest supporting Python 3.11 here, checked on PyPI 2026-11-03): xgboost 3.2.0
  (Apache-2.0), lightgbm 4.7.0 (MIT), optuna 5.0.0 (MIT), shap 0.51.0 (MIT). Installed as the
  `train` extra of `ml/`, so the snapshot/collector container stays small. Checked on the
  installed versions: all three tree models accept NaN; `TPESampler(seed=...)` exists.
- **Tuning objective = OOF log loss.** It scores the probabilities (needed for calibration,
  ensembles and the 0.60 / 0.90 thresholds) without choosing a threshold first. Alternative:
  F1 at 0.5 — not chosen, it ignores how confident the model is.
- **url/no_path (D10c)** removes every F1–F45 feature that reads the path, query or fragment,
  including whole-URL counts such as F1 url_length (they grow with the path); it keeps the 15
  host-only features. A narrower set (path-only features) would still let URL length tell
  home pages from deep links.
- Guard: `devdata.load_development` is the only training/evaluation code that opens the split
  and keeps development rows only; a test scans the package for any other access. A feature
  matrix built by other feature code is refused (`feature_code_hash`).

## 2026-11-03 — Phase 3 steps 2–3: metrics, calibration, ensembles, cascade logic

- **Confidence intervals by group bootstrap** (resample whole registered domains / senders,
  D4). Viva: samples of one group are correlated; resampling single samples would give
  intervals that are too narrow.
- **McNemar:** exact two-sided binomial test on the discordant pairs (scipy `binomtest`).
- **Calibration:** isotonic, cross-fitted by fold (a sample is never calibrated with its own
  label; a test flips one fold's labels and checks that fold's output does not change).
- **Stacker** on the raw OOF probabilities (log-odds), cross-fitted. Calibrated inputs would
  leak: the other folds' calibrators were fitted with this fold's labels.
- **Cascade:** inside [0.30, 0.80] (inclusive) the text model's probability replaces the
  tabular one. **Thresholds** stay 0.60 / 0.90; `threshold_for_fpr` exists if you later want a
  threshold chosen for a target false-positive rate on development OOF data.

## 2026-11-03 — D2 signature baseline built (emails: SpamAssassin; URLs: RQ3 only)

- **Emails:** Debian 13's `spamassassin` package (SpamAssassin 4.0.1, Apache-2.0, the rules it
  ships; `sa-update` never run, so the rule set is fixed) in our own container
  (`ml/spamassassin/Dockerfile`, compose profile `baseline`, `network_mode: none`, non-root).
  Options checked in the container: `--mbox -L -t`, `--cf='use_bayes 0'`,
  `--cf='bayes_auto_learn 0'`, `--cf='report_safe 0'`; detected = score ≥ required (5.0).
  Raw emails are scored. Smoke test on 300 real emails: Nazario 82/100 flagged, SpamAssassin
  ham 3/100, Enron 0/100; ~0.08 s per email.
- `report_safe 0` was needed: by default SpamAssassin wraps spam in a new report message, which
  hid our ID header for exactly the flagged emails (found in the smoke test; the importer
  refuses any run where an exported email has no result).
- **Threat to validity:** the SpamAssassin public ham corpus is likely to have been used when
  SpamAssassin's rule scores were tuned, so the baseline FPR on that source may be optimistic;
  per-source FPR is reported.
- **URLs (decided 2026-11-03):** no RQ1 URL baseline — every phishing URL came from the
  blocklists on its collection day, so a lookup would find all of them by construction. The
  lookup baseline is used in the RQ3 rounds (lists from earlier days vs URLs first seen later).

## 2026-11-04 — Review fixes to the Phase 3–7 scaffolding (commit bf4574d)

Found in review and fixed (tests added, all offline):
- **API startup:** the backend imported `phishguard_ml`, which the API image does not contain;
  the data folder now comes from settings (`PHISHGUARD_DATA_DIR`, same variable as ml/).
- **Registry:** `registry.json` is a list; the loader called `.get()` on it (crash after the
  first trained model).
- **Auth:** `require_api_key` existed but no route used it. Now on `/scan`, `/models`,
  `/admin`; fails closed outside development (503 without a configured key); constant-time
  comparison; `/health` stays public.
- **No placeholder verdicts:** scans answered "allow" from a fixed heuristic. They now answer
  503 until a trained model is wired in (Phase 5), so the gateway / extension never act on it.
- **VirusTotal is read-only:** the client submitted unknown URLs for scanning, which makes them
  visible to other VirusTotal users (visited URLs can hold reset tokens). **Viva:** a detector
  must not leak the URLs it is asked about to a third party.
- **Rate limits:** async (the old limiter blocked the event loop with time.sleep) and the
  documented VirusTotal public limits (4/min, 500/day; it was 15/min, no daily cap).
- **Cache:** failed / incomplete lookups are not cached (a 429 was remembered as "clean" for
  an hour); Redis is used when configured; the in-memory fallback is bounded. No keys or
  offline mode give ti_score = None ("unknown"), not 0.
- **Tests** no longer call real APIs or leak environment variables.
- **ml stubs** that returned invented 0.0 results (RQ2, RQ3) now raise NotImplementedError;
  `Cascade` uses the tested `ensembles.cascade` rule.
- `.env.example`: the PhishTank variables (still used by the collector) are back;
  `PHISHGUARD_API_KEY` and `PHISHGUARD_DATA_DIR` added.

**Still open (your decision):** the `ti_score` formula in `services/intel/scoring.py` (weights
10/3/4, caps 60/40; OTX `pulse_info` is not in the OTX docs) — to be settled at the start of
Phase 4; duplicated simulation code (`gophish.py` / `gophish_client.py`, `TemplateType` /
`SimulationEvent` next to `models.enums`), the unused `inference/persist.py` stub, and the two
`RQ3Harness` classes — kept untouched until you decide.

## 2026-11-04 — Duplicate and placeholder files removed (you decided)

Removed because they duplicated existing definitions or held no logic (only invented or
"queued" results): GoPhish client stubs (two copies), `TemplateType` / `SimulationEvent`
(duplicates of `models.enums.TemplateSplit` / `EventType`), `inference/persist.py`,
`workers/tasks.py`, two `RQ3Harness` copies, `RQ2Experiment`, `DistilBERTTrainer`, and the
extension content script that only logged to the console (it also ran on every page). The real
work is planned in Phases 3 (DistilBERT), 4 (RQ2), 5 (persisting scans, Celery tasks) and
6 (simulation, RQ3).

## 2026-11-05 — D11: live URL scanning (you agreed, all as recommended)

Design in `Docs/live_url_scanning.md`. D11a evidence collector as its own isolated Celery worker
container reached through Redis; D11b two stages (no target contact first, page and TLS only when
uncertain and safe to fetch); D11c deployed URL models without RDAP (F46–F52) and Tranco
(F57–F58), both kept in the RQ1 evaluation; D11d URLs with secret-looking query parameters are
never fetched, verdict at most warn; D11e an uncertain partial answer becomes warn; D11f connect
to the checked IP (DNS-rebinding fix), in the batch collector too, before any live use.

**Viva explanation:** the safety rule allows only the collector container to fetch phishing pages,
so the API asks the collector instead of fetching. Training/serving skew decides the deployed
features: live RDAP fails often under registry rate limits (missing for reasons unseen in
training) and Tranco membership separates the classes by construction. Fetching only when needed
cuts contacts with phishing hosts and avoids repeating GETs that can have side effects (one-time
links). Checking an address and then letting the HTTP library resolve again leaves a
server-side request forgery gap (DNS rebinding); pinning the checked IP closes it.

## 2026-11-05 — Split redone: URL groups by site owner, not platform (you agreed)

**What happened.** The first real split (seed 42, sizes per D3) met the group and duplicate
checks but not stratification: legitimate URLs 2.7% test, phishing URLs 26% (credential_harvest
41.6%). Cause: URLs were grouped by registered domain, and 58.9% of phishing URLs sat on 15
shared platforms (google.com 5,636; qrco.de 4,591; q-r.to 3,512; ead.me 3,293; web.app 1,932;
...). A whole platform became one "attacker" group, and three of them fell into the test set.
Nothing was trained or evaluated on that split; it is kept in `data/splits_rejected_2026-11-05/`.

**Decided (applied to phishing URLs only; legitimate URLs keep their Tranco site's group,
shared with its D10a link page):**
1. Hosting platforms in the Public Suffix List's private section: the group is the customer
   site (`evil.web.app`, not `web.app`).
2. On a popular site (the owner is in the Tranco list: google.com, bit.ly, qrco.de, ...) the
   attacker owns only the link: one group per link; but a link whose snapshot redirected to a
   non-popular site is grouped with that landing site.
3. URLs and emails are split separately (separate models, D5).
4. Only URL records with a snapshot are sampled (54,100 of 117,586 legitimate URLs have one; all
   phishing URLs do).

**Result** (`data/splits/`, created 2026-11-05 04:54 UTC): 122,042 samples (103,184 URLs +
18,858 emails), locked test 18,271 (URL 15.0%, email 14.8%; every category 14.2–15.3%, URL
malware 16.7% of 18), 5 dev folds of 20,754–20,755, no group in two parts, no duplicate content.

**Viva explanation.** Group splitting exists so near-copies from one attacker cannot be in both
training and test. On shared platforms the platform is not the attacker, so domain grouping
was both wrong (it merged unrelated attackers) and harmful (it made the test set 90% phishing).
The PSL private section is the standard list of such platforms; Tranco membership marks
domains no attacker owns; following redirects keeps links to the same phishing site together.
URLs without a snapshot would have no page / DNS / TLS evidence only on the legitimate side,
so "missing evidence" would leak the label. Redoing a split before any model has seen it is
not test-set tuning: only class and category shares were inspected, never model results.

## 2026-11-06 — D11c applied: F55 also leaves the deployed URL models

Building the `live` and `live_stage1` feature sets showed that F55 `num_name_servers` uses the RDAP
name servers when DNS has no NS answer (common for subdomains). Live scans have no RDAP (D11c), so
F55 is left out of both sets; it stays in the RQ1 evaluation. M2 `live` has 84 features, M1
`live_stage1` has 48. The feature itself is unchanged, so `feature_code_hash` and the models
already trained stay valid.

**Measured on 3,000 random development URLs:** removing RDAP changes F55 for 51.0% of phishing URLs
(765 of 1,499) and 13.5% of legitimate URLs (203 of 1,501). Outside F46–F52, F55 is the only
feature that changes. F55 therefore also carried RDAP information into `url/no_rdap`, so that set
now drops F46–F52 and F55 (you decided; the run had not started). M1 and M2 train after the
current queue (you decided).

**Viva explanation:** a deployed model must get inputs computed the same way as in training. Tests
check this by behaviour: changing RDAP or Tranco changes no `live` input, and removing the page and
TLS changes no `live_stage1` input.

## 2026-11-06 — Text models: inputs and training (you accepted the recommendations)

**Decision:** LSTM and CNN read URL characters (up to 200) or email words (first 400, vocabulary
30,000 from the training folds only). URLs are run twice: full URL and scheme plus host only.
Email text is the subject and body after the time-clue normaliser, with no other headers. Same
5 folds as the tabular models. Early stopping on a group-aware 10% of the training rows. 10 Optuna
trials on fold 0. DistilBERT on Colab with fixed settings (2e-5, at most 3 epochs), no tuning.

**Why:** the host-only run shows how much of the URL score only reflects that legitimate Tranco
URLs are mostly home pages (D10c). Tuning on one fold keeps CPU time practical.

**Alternative not chosen:** 50 trials over 5 folds as for the tabular models: far too slow on a CPU.

**Viva explanation:** the text models get less tuning than the tabular models. This is a limitation
of the comparison and must be stated with the results.

## 2026-11-06 — Dataset names hidden from the email text models (recommendation, please review)

**Finding:** on development emails, `enron` is in 37.5% of legitimate and 0% of phishing, `jose`
19.5% of phishing and 0.6% of legitimate, `monkey` 16.4% and 0.1% (jose@monkey.org owns the Nazario
corpus). The `<YEAR>` placeholder was in 56% and 18%.

**Decision:** `services/text_input.py` replaces enron, ect, hou, jose and monkey with `<ORG>` and
removes years, before any text model was trained. Training and live scans use the same function.

**Threat that remains:** the style of forwarded mail also differs by corpus (`subject` 33% and 4%,
`cc` 20% and 1%, `pm` 24% and 1%), and topics such as `energy` (13% and 0%) identify Enron. These
were left in: removing ordinary words would make the text unrealistic. Report the FPR per
legitimate source and on the recent own-mailbox emails, which share none of this.

**Viva explanation:** a high score could mean the model recognises the source, not phishing. The
word list comes from development rows only, so the locked test set played no part in choosing it.

## 2026-11-06 — Simulations: safety built into the code (Phase 6, recommendation, please review)

**Decision:** landing pages are always created with capture off; `details` of GoPhish events is
never read; a campaign cannot launch without `PHISHGUARD_ETHICS_APPROVAL_REF`, active consent for
every target, and a fictional organisation; events of people who withdrew are dropped. Samples are
the template's own content, never anything about a participant. The dashboard shows totals only.

**Verified on real GoPhish 0.12.1 (2026-11-06, local container, closed SMTP port, no email could
leave):** GoPhish removed the `name` of every input, a submitted form did not reach GoPhish, and
"Submitted Data" was still recorded.

**Note for the ethics form:** GoPhish itself stores each participant's IP address and browser with
each event, in its own database. PhishGuard does not copy them.

**Viva explanation:** "never store credential values" is met at three points: the browser has
nothing to send, GoPhish has nothing to store, and PhishGuard never reads that field.

## 2026-11-07 — Simulations: the explanation appears on click, with no form (you decided)

**Decision:** the landing page is `services/simulation/debrief.py`: it explains the simulation as soon
as the link is opened, and has no form. So real campaigns will record clicks but no submissions, and
any submission rate on the dashboard stays 0. RQ3 is not affected: a click alone is already a failed
event. Since 2026-11-08 `campaigns.launch` creates this page itself for every campaign, from the
template's fictional organisation and `PHISHGUARD_SIMULATION_CONTACT_EMAIL`, so no other page can be
used; it refuses without a contact address.

**Viva explanation:** I gave up measuring how many people would type a password in order to reduce
harm: nobody is led to a form, and they learn straight away that it was a simulation.

## 2026-11-07 — Simulation data retention (you decided; the committee has not answered)

**Decision:** the ethics request proposes keeping study data with no planned deletion date, except when
a participant withdraws, and asks the committee whether this is allowed. The committee's answer replaces
this decision. Some participants may be my own students or staff, and the request says so.

## 2026-11-08 — RQ2: ti_score formula, D7 subset and experiment (you agreed; built)

Built 2026-11-08: `services/intel/scoring.py` (formula), `ml/phishguard_ml/training/rq2.py` with the
`ti-record` and `rq2` commands; tests offline (`test_intel.py`, `test_rq2.py`). Not run yet: it needs
the API keys, and the experiment needs the `url/live` models. Checked 2026-11-08 on the VirusTotal docs: the public API allows "500
requests per day and a rate of 4 requests per minute", "must not be used in commercial products or
services", and multiple accounts to get around the limits are not allowed
(docs.virustotal.com/reference/public-vs-premium-api). The URL object has `last_analysis_stats`
(harmless, malicious, suspicious, timeout, undetected) and `last_analysis_results`, one entry per engine
with `category` (harmless, undetected, suspicious, malicious), `engine_name`, `method`, `result`
(docs.virustotal.com/docs/url-object). **Not verified:** the VirusTotal terms of service and the OTX
terms could not be read automatically, so whether either restricts using results as model input is
unknown (URLhaus does restrict it). OTX `pulse_info.count` is used by third-party integrations but is not
in official docs we could read; check it on one real response.

**1. Subset (D7).**
- Phishing: fresh URLs from the collector's batch of today or yesterday, so each is looked up within
  about a day of collection (D7: at collection time only). They are outside the frozen split. The
  median hours from collection to lookup is reported.
- Legitimate: development legitimate URLs in a fixed random order (a hash of the sample id), never the
  locked test set, never more each day than phishing URLs. A legitimate site's reputation changes
  slowly, so the later lookup date matters less.
- Size: 250 phishing + 250 legitimate a day (VirusTotal's 500 a day; about 2 h at 4 a minute) for 8
  days, so 2,000 + 2,000. The same URLs go to OTX.

**2. `ti_score` formula, fixed before any response is seen.**
- `vt = 100 × min(1, (malicious + 0.5 × suspicious) / 5)`, counted from `last_analysis_results` with
  feed engines removed (any engine named PhishTank or OpenPhish, if present: check on one real
  response, since those feeds are where the phishing URLs came from).
- `otx = 100 × min(1, pulse_count / 5)`.
- `ti_score = max(vt, otx)`. "Not found" by a provider counts as 0 for that provider; an error leaves
  that provider out; if both are left out, `ti_score` is missing (NaN, as for any feature).

Why: `max` because either source alone is evidence, and an average would halve the score whenever one
provider has not seen a new URL yet. Five engines or pulses for a full score is a round number, not
tuned. Tree models are unaffected by any monotonic rescaling of one input, so the exact scale matters
much less than the combination. The current `scoring.py` weights (10/3/4, caps 60/40) were never agreed
and would be replaced.

Alternative not chosen: giving the models the raw counts as separate inputs. CLAUDE.md fixes
`ti_score` as one 0–100 input. The raw counts are kept in the recordings, so this could be a
sensitivity check.

**3. Experiment.** On the subset only: the three tabular models and the soft vote on the `live` feature
set (the deployed URL inputs: no RDAP, no Tranco), with and without `ti_score`. Both use the same rows,
the same 5 group folds (D4 groups) and the hyper-parameters already tuned for `url/live`, so the only
difference is `ti_score`. Report FPR at 0.5 and at the warn and block thresholds, F1, group-bootstrap
95% CIs and McNemar. Also report `ti_score` alone as a rule, and how many phishing URLs VirusTotal had
already flagged on the day.

**4. Circularity (threat to validity).** The phishing URLs come from PhishTank and OpenPhish, which
also feed threat-intelligence services. Mitigations: feed engines removed from the VirusTotal count;
same-day lookups; the "flagged on the day" share and the `ti_score`-alone row are reported, so a reader
can see how much the score only repeats the source list.

**Viva explanation:** RQ2 asks what live threat intelligence does to false positives, so the comparison
holds everything else fixed: same rows, folds and hyper-parameters. Looking up phishing URLs on the day
they appear mimics deployment, where a new URL is checked once, before most services know it.

## 2026-11-08 — D6: visual similarity by favicon perceptual hash (you chose the perceptual hash)

**Decision:** the extension compares a 64-bit difference hash (dHash, 9 x 8 cells of the 32 x 32
icon) of the page's favicon with the favicons of the 35 brands in `lexicons.BRAND_DOMAINS`. Within 8
of 64 bits, on a host that is not one of the matching brands' domains, the tab gets the warning badge
and a title naming the brand. It never blocks, never changes the API verdict, and is outside the 140
features. Reference hashes come from `python -m phishguard_ml brand-icons`, which fetches
`https://<brand domain>/favicon.ico` from the brands' own sites only: 29 of 35 brands on 2026-11-08
(binance, dropbox, facebook, fedex, linkedin and mastercard gave no readable /favicon.ico). Only the
hashes are stored.

**Why the favicon, not a screenshot:** a screenshot of the user's page would need more permission
and could hold personal data; a favicon is small, public and copied by phishing kits. The favicon is
read from a data: URL or the browser's favicon cache (Chrome and Edge `_favicon`, "favicon"
permission, developer.chrome.com/docs/extensions/how-to/ui/favicons); a favicon address on the web is
never fetched, so the check makes no contact with a possible phishing host. Firefox only gets the
check when it gives the favicon as a data: URL.

**Why 8 bits:** the closest two different companies' references are 9 bits apart (DocuSign, Visa),
so a limit of 8 means one brand's icon cannot match another's (a test checks this on the real file).
Brands of one company share an icon (Google and Gmail; Microsoft, Office 365, Outlook), so a match is
owned by every brand that matched. **Not evaluated:** no stored phishing snapshot has a favicon, so
there is no detection rate for D6; the thesis reports it as a built warning signal with that limit.
Browser and Pillow scale icons slightly differently, which the 8-bit margin is meant to absorb (not
yet measured in a real browser).

**Viva explanation:** the check targets brand impersonation the URL and text models can miss: a page
that looks like PayPal on a new domain. A perceptual hash survives small changes in scaling and
colour that would break an exact hash, and comparing only against a brand's own domains avoids
warning on the real site.

## 2026-11-06 — Extension: first visit and API downtime (Phase 7)

**Decision:** a URL rated block is replaced by the warning page after it starts loading; a session
`declarativeNetRequest` rule then stops repeat visits before they load. Verdicts are cached for an
hour. If the API is down or has no model, the extension does nothing (fail-open) and the gateway
retries the same email later without acting (fail-safe: nothing is lost).

**Why:** a rule cannot wait for an API answer, and holding every navigation until the API answers
(up to 6.5 s) would make browsing unusable.

**Alternative not chosen:** fail-closed, which would block all browsing whenever the API is down.

**Viva explanation:** on a first visit the page may appear for a moment, and a user could interact
with it during that time. This is a real limit of an API-based check in MV3, stated in the thesis.

## 2026-11-06 — LSTM trained on Colab, not on this PC (Phase 3)

**Decision (you agreed):** `ml/train_text_queue.ps1` trains the CNN only; `ml/colab/train_lstm.py` trains the LSTM on a Colab GPU with the same search.

**Why:** measured on this CPU, with other training running, the LSTM needs 342–1,183 hours per run
and more threads did not help. The CNN needs 6–14 hours. The queue would have stopped at the LSTM for
weeks with the CNN still waiting.


**Viva explanation:** the numbers are rough upper estimates from small samples on a busy CPU, but a
free CPU several times faster would still be far too slow. The script is a copy of the repository
design, and a test proves it gives the same predictions on a CPU, so the device is the only difference.

## 2026-11-08 — GoPhish admin certificate: ours, and always checked (Phase 6)

**Decision:** `make gophish-cert` makes a certificate naming `gophish`, `localhost` and
`127.0.0.1`; GoPhish uses it (mounted over the one it would generate), and the API trusts exactly
that file (`PHISHGUARD_GOPHISH_CA_FILE`). The API container gets the certificate folder only, not
the key. Certificate checks are never switched off.

**Why:** GoPhish 0.12.1 generates a self-signed certificate with no host name, so a checked
connection fails ("IP address mismatch"), and the only way to use it would be to stop checking.
Found on 2026-11-08 when running the campaign endpoints against real GoPhish.

**Alternative not chosen:** `verify=False` (anyone on the path could read the GoPhish API key and
participant addresses), or turning TLS off on the admin port.

**Viva explanation:** the API sends participant addresses and the GoPhish API key over this
connection, so it must know it is talking to our GoPhish; trusting one known certificate is the
simplest way to do that on a single machine.

## 2026-11-08 — CORS for the dashboard only (Phase 8)

**Decision:** the API allows cross-origin requests from `PHISHGUARD_DASHBOARD_ORIGINS` only
(default: the Vite dev server), methods GET and POST, headers `X-API-Key` and `Content-Type`, no
credentials.

**Why:** the dashboard runs on another origin and sends `X-API-Key`, so the browser asks first;
without CORS every dashboard request failed. The unit tests did not show it because they fake
`fetch`. The extension is not affected (its host permission lets it call the API).

**Viva explanation (CORS):** CORS does not protect the API (the key does); it only decides which web pages
a browser lets read the answers. Listing exact origins, rather than `*`, means a script on any other
site cannot read answers from the local API through the user's browser.

## 2026-11-09 — Extension: checking before the page is shown, options C + D (Phase 7)

**Decision (you chose C + D, Docs/extension_precheck_proposal.md):** two rule-based checks before a
page loads, keeping everything else as before.
- **C, blocklist:** every 5 minutes the extension fetches `GET /extension/blocked-hosts` and installs
  one rule that sends those hosts to the warning page before they load. The API lists a host when it
  rated a URL on it block in the last 7 days, unless anything on the same registered domain was
  rated allow in the last 30 days (at most 1,000 hosts, newest first).
- **D, first visits:** a GET page load to a host this browser has not visited goes first to the
  extension's checking page, which waits at most 2 s (provisional, to be set from measured stage-1
  latency) for the API. Block goes to the warning page; any other answer opens the page and
  remembers the host; no answer opens it and lets the host through for this browser session.
- Rule order: open once (4) > block (3) > visited or unchecked hosts (2) > the check (1).

**Changed from the proposal, and why:**
- **Hosts, not domains or URLs:** a whole registered domain would block every site on shared
  hosting; a URL often carries the victim's address or a token in its path or query, and would be
  sent to every extension. The "allow on the same domain" exception guards shared hosts.
- **Visited hosts are stored in plain text, not hashed:** the browser's rule engine can match only
  plain host names. They stay in `chrome.storage.local` and are never sent anywhere (like history).
- **Only GET page loads are checked:** redirecting a form submission would lose its data.

**Checked:** unit tests (`precheck.test.ts`, `test_extension_api.py`), and in headless Edge with the
built extension (2026-11-09): a host on the blocklist went to the warning page before loading; a first
visit to example.com went through the checking page to the site; the second visit went straight
through. URL models were not trained yet, so the API gave no verdict and the "unchecked" path was the
one exercised; the "allow, remember the host" path is unit-tested only.

**Viva explanation:** Chrome extensions cannot hold a page while asking a server, so the extension
decides with rules prepared in advance: known phishing hosts are stopped outright, and only the first
visit to an unknown host waits, which is where new phishing sites are. Sites already visited are not
slowed down, the page still opens when the API is down (fail-open, as before), and the user can still
open a blocked page once.

## 2026-11-09 — Withdrawal deletes the participant's data, in two steps (Phase 6)

**Decision:** a withdrawn participant can be deleted (`POST /admin/simulation/participants/{id}/delete`,
and "Delete" on the dashboard): their record, events and samples are deleted in PhishGuard, and their
address is removed from every group PhishGuard made in GoPhish (`pg-…`; a group left empty is deleted,
because GoPhish refuses an empty group). GoPhish also keeps a copy of each target in the results of
campaigns already sent; those are erased per campaign, once it is completed and its events fetched
(`.../campaigns/{id}/erase-gophish`, "Erase GoPhish results"). The delete answer says how many
campaigns still hold such copies. Deleting needs withdrawal first; erasing needs a completed campaign.

**Why:** the information sheet promises "your records are then deleted", and the request had said
GoPhish entries would be removed by hand. It now matches what the software does. This is the
exception to keeping study data with no deletion date (2026-11-07 entry).

**Checked:** on real GoPhish 0.12.1 (local container, no campaign, no email): updating a group
removes one address, an empty group is refused (400), deleting a group works, and deleting a
campaign that does not exist answers 404. Tests with GoPhish faked: groups of other tools are never
touched, the address is matched without case, and nothing about the person is in any answer.

**Viva explanation:** deletion is two steps because GoPhish copies each recipient into a campaign's
results when it is sent; removing one person from those results is not possible through its API, so
the whole campaign's results are erased once PhishGuard has saved its own (address-free) events.

## 2026-11-09 — Simulated emails use a fictional organisation, never the participants' employer

**Decision:** the simulated phishing emails are sent as a fictional, invented organisation
(Kestrelmoor Institute, Parcelwren, Lumacloud). They do not imitate Nansana Municipal Council — the
participants' real employer — or any other real body, even though every participant is Council staff.
The ethics request (Attachment C) and the code's real-brand refusal both enforce this.

**Why:** impersonating the participants' own employer would raise the deception well beyond what the
study needs, could be read as the employer endorsing or running the test, and conflicts with the
project's standing safeguard that landing pages and senders never imitate a real brand. The research
question is about whether retraining on failed-simulation data improves detection; it does not need a
real-employer lure to be answered.

**Alternative:** branding the emails as internal Nansana Municipal Council mail (as first suggested
when filling in the ethics request). Not chosen for the reasons above; if a real-employer lure is ever
judged necessary, it is a decision for the ethics committee and supervisor to make explicitly, not a
default.

**Viva explanation:** using invented organisations keeps the manipulation to the minimum the design
requires (an unexpected but low-harm email), separates "did the model learn to detect the lure" from
"did people trust their employer", and keeps one consistent safeguard across the code, the templates
and the ethics submission.

## 2026-11-09 — Data-protection basis stated for the ethics request

**Decision:** the study cites Uganda's Data Protection and Privacy Act, 2019 and the Data Protection
and Privacy Regulations, 2021 (Personal Data Protection Office under NITA-U) as the governing law, and
the EU GDPR (Regulation (EU) 2016/679) as an international reference for its principles.

**Why:** the participants and the researcher are in Uganda, so the Ugandan Act governs; GDPR is named
because it is the widely recognised international benchmark a committee will expect a data-handling
study to follow.

**Alternative:** naming only GDPR (common in student templates). Not chosen because the applicable law
is Ugandan; GDPR alone would misstate the legal basis. Exact regulation numbers are to be confirmed
against the Gazette before submission.

## 2026-11-11 — CNN text model can be trained on a Colab GPU

**Decision:** added `ml/colab/train_cnn.py`, a standalone 1D-CNN trainer for a Colab/Kaggle GPU,
alongside the existing `train_lstm.py` and `train_distilbert.py`. `text_colab.MODEL_FILES` now accepts
`cnn_1d`, so a GPU CNN run imports through `text-import` like any other text model. Three new tests in
`test_text_models.py` check that on a CPU the standalone CNN gives the same predictions and searches
the same space as `training/text_train.py`, and that a run imports and reports as a normal text model.

**Why:** the CNN was the last text model still tied to the PC's CPU (via `train_text_queue.ps1`,
~6 h email + ~14 h URL). Moving it to the GPU frees the PC and shortens the text-model critical path.
The parity tests guarantee the GPU result is the same model the thesis describes, so cross-model
comparison (LSTM / CNN / DistilBERT) stays valid; only the device differs.

**Alternative:** keep training the CNN on CPU locally. Not chosen because it needlessly occupies the
machine the tabular queue already saturates, with no methodological benefit. The local CPU path
remains available and is skipped automatically once a GPU-trained CNN is registered (whichever is
imported first for a given modality/input is the registered one; the CNN must not be trained in both
places for the same input).

## 2026-11-11 — Stage-1 live-URL band set to 0.0108 / 0.9892 (fetch ~20%)

**Decision:** after the tabular queue finished (all 9 feature sets, `url/live_stage1` exit 0 at
07:55, `QUEUE FINISHED` 08:22), ran `phishguard_ml choose-band` and set
`PHISHGUARD_STAGE1_BAND_LOW=0.010810810810810811`,
`PHISHGUARD_STAGE1_BAND_HIGH=0.9891891891891892` in `.env`. These are the LightGBM `target_share=0.20`
boundaries. LightGBM is the served stage-1 model M1 (lowest OOF log loss among the three on
`url/live_stage1`: lightgbm 0.0633, xgboost 0.0660, random_forest 0.0773; `band.py` serves the
lowest-log-loss model, so the band is read off its table).

**Why:** the band is the "uncertain" middle on M1's calibrated score; scores outside it are decided at
stage 1 (no page fetch), scores inside it are sent to stage 2 (live fetch). The goal is to decide as
many URLs as possible at stage 1 while keeping the errors M1 makes alone negligible. At `0.20`, ~80%
of URLs decide at stage 1 and only ~20% are fetched, while M1's stage-1 miss rate falls to 0.29% and
its stage-1 FPR to 0.04% — both an order of magnitude below the URL model's own development error
(~3% each), so the cascade's own decisions add almost nothing to the error budget. This is the knee of
the trade-off: versus the provisional 0.15–0.85 band (≈ the 0.05 row), it cuts stage-1 miss 4.4×
(1.28%→0.29%) and FPR 9× (0.38%→0.04%) for 15 percentage points more fetching.

**Alternatives:** (a) the provisional 0.15–0.85 band fetches only ~5% but leaves a 1.28% stage-1 miss
rate — too many fresh phishing URLs decided "allow" without their page. (b) `target_share=0.30`
(0.005–0.995) barely improves the miss rate (0.29%→0.14%) and slightly *raises* FPR (0.04%→0.05%) while
fetching 50% more pages — a poor trade. (c) `0.50` reaches a 0.04% miss but fetches every other URL,
defeating the point of a cheap stage 1. 0.20 is the smallest fetch share at which the stage-1 errors
are already negligible.

**Viva note:** the band is chosen on development out-of-fold predictions only (cross-fitted
calibration), never on the locked test set; `choose-band` reads `url/live_stage1/<model>/oof.parquet`.
The band governs only *when to fetch a page*, not the final allow/warn/block thresholds, which are
unchanged.

## 2026-11-11 — Ethics approval confirmed; simulation gate opened (reference 110427)

**Decision:** set `PHISHGUARD_ETHICS_APPROVAL_REF=110427` in `.env`, satisfying the software's
"no approval, no launch" gate (`services/simulation/campaigns.py`). Supporting documents received
and signed:
- **IBSTU Research Ethics Committee approval**, reference **110427**, signed by the Committee Chair
  **Male Henry Kenneth** and (separately) by the supervisor **Christopher Ayesiga**.
- **Nansana Municipal Council authorisation**, Ref **CRM10427**, Office of the Town Clerk (signed
  "NAKINTU GRACE, FOR Town Clerk", stamped), designating **Kitonsa Habibu, ICT Department** as the
  Council's contact; conditions mirror the ethics request's safeguards.

**Why the earlier reservation is withdrawn:** on 2026-11-11 an earlier approval document carried the
student number (011250360) as its reference and appeared to be chaired by the supervisor, which would
not have been independent. The documents received now resolve both points — the committee chair
(Male Henry Kenneth) is a different person from the supervisor, and the reference (110427) is a
distinct institutional number — and the host organisation has independently authorised the study.

**What this does and does not do:** setting the reference flips `simulations_allowed` to true and
removes the approval blocker only. It launches nothing. Each campaign still independently requires a
draft campaign, a participant list with recorded, non-withdrawn consent, a template that names a
fictional organisation (real-brand names are refused), and a contact address for the explanation
page. The running API must be restarted to read the new value.

**Open cleanup (not blocking):** the signed Attachments A, B and D state the withdrawal deadline as
"11 January 2026" — a past date, clearly a typo for **11 January 2027** (section 6 of the approval
says 2027). The repository's `Docs/ethics_request.md` still says "11 December 2026". These should be
reconciled to one authoritative date (11 January 2027) before the first round.

## 2026-11-11 — Invented template-organisation names re-checked before Round 1

**Decision:** re-ran the web search on the three invented organisation names used in the simulation
templates, as the ethics request commits to doing before the first round. Result: no real
organisation uses any of the three exact names.
- **Kestrelmoor Institute** — not found (closest, unrelated: "Kestrel Institute", a different body).
- **Parcelwren** — not found (closest, unrelated: ParcelWorks, Parcelly, Parcel2Go).
- **Lumacloud** — not found (closest, unrelated: FileCloud, Egnyte).

**Why:** the templates must name only fictional organisations; the request promised a fresh search
immediately before Round 1 and a change if any name turned out to be real. All three remain clear, so
no template needs renaming. If a round is delayed, repeat this check before sending.
