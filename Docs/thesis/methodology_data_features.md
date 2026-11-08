# Methodology: data and features (draft)

**DRAFT for the thesis.** Every number comes from `Docs/data_card.md`, `PROGRESS.md` or
`Docs/decisions.md` as of 2026-11-08. Items in [brackets] still need a figure, a citation or a check.
Section numbers are placeholders: renumber them to match the proposal.

## 3.1 Overview

PhishGuard detects phishing in two modalities, URLs and emails, with separate models for each
(decision D5). This chapter describes how the research dataset was built, how it was labelled and
split, and how each sample is turned into the 140 engineered features (F1–F140) used by the tabular
models and the text inputs used by the text models. Every step is a script in the `ml/` package, so
the dataset can be rebuilt from the original sources. The raw data is not redistributed.

## 3.2 Data sources

All sources were downloaded on 2026-11-02 (Table 3.1).

**Table 3.1: Data sources**

| Source | Modality | Label | What was taken | Records parsed |
|---|---|---|---|---|
| PhishTank verified online list | URL | phishing | verified entries; submission time used as the source date | 51,456 |
| OpenPhish community feed | URL | phishing | one URL per line, no dates | 300 |
| Tranco top-sites list | URL | legitimate | top 100,000 domains as `https://<domain>/`, plus one deeper page per site (Section 3.4) | 100,000 home pages |
| Nazario phishing corpus (2004–2025) | email | phishing | every message | 11,965 |
| SpamAssassin public corpus, ham only | email | legitimate | the three 2003 ham archives (`easy_ham`, `easy_ham_2`, `hard_ham`) | 4,150 |
| Enron corpus (2015-05-07 release) | email | legitimate | received mail only, deterministic 10% sample | 20,346 |

The Tranco list was limited to the top 100,000 domains because the long tail of the top million
contains many parked or infrastructure-only domains. The Enron sample excludes folders whose names
contain `sent`, `all_documents` or `discussion_threads`. Sent mail is written by the mailbox owner,
whereas phishing is received mail, and the other two folder types copy other folders. A message is
kept if the SHA-256 hash of its path falls in the lowest 10%, so the sample is identical on every
rebuild without a random seed. The SpamAssassin spam archives were not used, because spam is not
phishing.

The PhishTank file lists only phishes that were still online on the download day, but their
submission dates span 2011–2026, mostly 2023–2026 (2023: 6,724; 2024: 16,169; 2025: 7,657;
2026: 19,618). The phishing URLs are therefore described as PhishTank's verified online list
downloaded on 2026-11-02, plus OpenPhish (decision D9).

Each source's terms of use were checked [cite each]. URLhaus was considered but is used only in the
blocklist lookup baseline. Its terms (abuse.ch, section 7.3) forbid using its data to train AI models
without written consent, so no model learns from it.

A small set of recent legitimate emails from the author's own mailbox, with personal content removed,
is kept for evaluation only. It is never part of the dataset or the split. [Give its size once
collected.]

## 3.3 Cleaning and de-duplication

Every source is converted to one record format (Table 3.2) and stored as Parquet, which keeps column
types and handles large email bodies safely. CSV was rejected because it loses types and breaks on
commas and newlines inside emails.

**Table 3.2: Record format**

| Field | Meaning |
|---|---|
| `sample_id` | UUID version 5 from the sample type and content hash, so the same content gets the same id |
| `sample_type` | `url` or `email` |
| `raw_content` | the URL, or the full email as received |
| `label` | `phishing` or `legitimate`, from the source |
| `attack_category` | Section 3.5; empty for legitimate samples |
| `source`, `source_date`, `collected_at` | provenance |
| `group_key` | the split grouping key (Section 3.7) |
| `content_hash` | SHA-256 of the normalised content, used for de-duplication |
| `snapshot_ref` | URLs only: where the page, DNS, TLS and RDAP evidence is stored |

**URLs** are put into a canonical form before hashing: the scheme and host are lower-cased, default
ports and the fragment are dropped, and an empty path becomes `/`. The path and query are kept as they
are, because they are case-sensitive. Entries that are not usable http(s) URLs were rejected (7 from
PhishTank).

**Emails** count as duplicates when they share a subject and body, ignoring whitespace and case.
Empty emails were rejected (45 from Nazario). Malformed headers never stop the pipeline. Every header
read goes through one function that returns an empty value instead of raising an error.

**De-duplication** kept 183,931 records and removed 4,286 duplicates. In 6 cases the same content
appeared with both labels, and the phishing copy was kept, since a phishing report is direct evidence.
Table 3.3 shows the records after de-duplication.

**Table 3.3: Records after cleaning**

| Modality | Phishing | Legitimate |
|---|---|---|
| URL | 51,592 (PhishTank 51,294; OpenPhish 298) | 117,586 (Tranco home pages and deeper pages) |
| Email | 9,429 (Nazario) | 22,916 (Enron 18,808; SpamAssassin 4,108) |

## 3.4 URL evidence: page snapshots and registration data

URL features need the page, DNS records, the TLS certificate and the domain's registration data. These
were captured once per URL by a **snapshot collector**, as close to collection time as possible,
because phishing pages go offline quickly. Phishing URLs were captured first, then the legitimate ones.

**Safety.** Phishing pages are fetched only by the snapshot collector, inside its own container, with
plain HTTP GET requests. No JavaScript is run, no forms are submitted and no binary files are
downloaded. In addition:

- each redirect is checked separately;
- hosts resolving to private, loopback, link-local or reserved addresses are never contacted;
- the connection goes to the address that was just checked, which stops DNS rebinding;
- bodies that are not HTML are not read, and pages are capped at 2 MB;
- no cookies are kept;
- the container has no database or encryption secrets, drops all Linux capabilities and runs as a
  non-root user;
- the snapshot code refuses to run outside that container.

Stored pages are research data, read only as text. To avoid biasing the dataset, the data folder was
excluded from antivirus scanning [state this in the ethics and threats-to-validity sections].

**Deeper legitimate pages (decision D10a).** Tranco gives domains, so every legitimate URL would
otherwise be a home page, while phishing URLs have paths and queries. A model could then separate the
classes by URL shape alone. While snapshotting, each Tranco home page therefore contributed one
same-site deeper page, chosen deterministically from its links, as an extra legitimate URL. Because
of time limits, snapshots covered every phishing URL and the top 30,000 Tranco sites, with one deeper
page each.

**Registration data (RDAP).** Registration data was queried separately, once per registered domain,
directly at each registry's RDAP server found in IANA's bootstrap file (RFC 9224 [cite]). There was
one request at a time per registry, a 0.5 s pause between requests, and growing waits after HTTP 429
or 5xx answers. 105,445 of 108,480 domains answered. Registries that refused requests were respected,
and the rest stayed missing (Section 3.8).

**What the snapshots showed.** Most live phishing pages contain no credential form in the HTML that
may be fetched without JavaScript. In 23,708 live pages without a category, only 3% contained
`<form`, 49% redirected by meta refresh or JavaScript, and 58% contained takedown, parking or
bot-check wording. Many phishing snapshots therefore describe a takedown, not the attack. This affects
labelling (Section 3.5), and it is why URL results are also reported per snapshot status.

## 3.5 Labelling

The binary label (phishing or legitimate) comes from the source. None of the sources give an attack
category, so each phishing sample gets the first category whose rule matches (decision D1):

1. **malware:** the URL path ends in a risky file extension (for example `.exe`, `.scr`, `.zip`, `.iso`);
2. **brand_impersonation:** a known brand appears in the URL, page title or email text, but the
   registered domain is not that brand's; or, for PhishTank URLs, PhishTank's own `target` field names
   a brand;
3. **credential_harvest:** the page has a password field or a login form, or the email asks the reader
   to sign in or verify an account;
4. **spear:** the email addresses the recipient or their organisation by name;
5. **unknown:** none of the above.

Ordered rules were chosen over hand-labelling because they are transparent, repeatable and can be
checked by an examiner. Hand-labelling over 60,000 phishing samples was not feasible. [Report the
agreement between the rules and a hand-checked sample, if this is done.] The word lists are published
in the code.

PhishTank's `target` field was added because the page-based rules can label only about 4,900 URLs
(Section 3.4). It names one of 93 brands for 5,138 of 51,463 rows, and is skewed towards Allegro
(1,899). [Check how PhishTank assigns `target`, by submitter or verifier.] The final category counts
are given in the data card [insert table from the refreshed data card]. "Unknown" remains the largest
URL category, which is the honest outcome when the attack is not visible without JavaScript.

## 3.6 Dataset size and balance

The proposal planned 175,000 samples. The public phishing-email corpus is too small for that, so the
dataset uses the largest balanced set available when the split was made, with each modality 50%
phishing and 50% legitimate (decision D3). Oversampling was rejected, because it would put copies of
the same email on both sides of the split. Only URL records with a snapshot were sampled, so that
missing evidence could not mark one class (Section 3.7).

**Table 3.4: Final dataset**

| Modality | Phishing | Legitimate | Total |
|---|---|---|---|
| URL | 51,592 | 51,592 | 103,184 |
| Email | 9,429 | 9,429 | 18,858 |
| **Total** | | | **122,042** |

[Give how many legitimate emails came from Enron and how many from SpamAssassin.]

## 3.7 The split

The split was made once, with seed 42, and is frozen. Its file hashes are recorded and checked before
every training run. **15% of samples form a locked test set**, used only once, in the final
evaluation. The remaining 85% form the development set, used for 5-fold stratified group
cross-validation. There is no separate validation set.

**Grouping (decision D4).** Near-duplicates from one attacker or sender must not appear in both
training and test, so samples are split in groups:

- emails by sender address, and Enron emails by mailbox owner (grouping by sender domain would put all
  of Enron, which shares `enron.com`, on one side);
- legitimate URLs by their Tranco site, shared with that site's deeper page;
- phishing URLs by the site owner:
  - on hosting platforms in the private section of the Public Suffix List, the customer site is the
    group (`evil.web.app`, not `web.app`);
  - on popular sites listed in Tranco (for example link shorteners), each link is its own group,
    unless its snapshot redirected to a non-popular site, in which case it joins that site's group.

**A rejected first split.** The first split grouped all URLs by registered domain. It passed the
group and duplicate checks but failed stratification: 58.9% of phishing URLs sat on 15 shared
platforms, so whole platforms became single groups, and the test set held 26% of the phishing URLs
but only 2.7% of the legitimate ones. No model had seen it. It was replaced by the grouping above,
after inspecting only class and category shares, never model results. The rejected split is kept
for reference.

**Result.** The locked test set holds 18,271 samples (15.0%: URLs 15.0%, emails 14.8%; every
category 14.2–15.3%, except URL malware at 16.7% of 18 samples). The five development folds hold
20,754–20,755 samples each. No group appears in two parts and no content appears twice. URLs and emails
are split separately.

Only one function in the training code can open the split, and it returns development rows only. A
test fails if any other code reads the split.

## 3.8 Known biases in the data

These biases are handled in the design and are reported as threats to validity:

- **Email age gap.** The legitimate emails are old (Enron mostly 2000–2002; the SpamAssassin ham is
  dated 2002), while most phishing emails are from 2005–2025. A model could learn "old versus new".
  This is handled by the time-clue normaliser (Section 3.9), by also reporting results without the
  age-sensitive features, and by the recent own-mailbox check set.
- **Corpus headers.** The Enron release removed delivery headers (Received and Return-Path appear in 0%
  of Enron emails, compared with 100% of Nazario), and its Message-IDs end in `@thyme`. Header features
  would therefore identify Enron, which is 82% of the legitimate emails, not phishing. The headline
  email results use no header features (F96–F115). Header features are evaluated only on SpamAssassin
  against Nazario, and results are also reported per legitimate source.
- **Corpus words.** Words such as `enron` (37.5% of legitimate emails, 0% of phishing) and the Nazario
  owner's address (`jose`, `monkey`) identify the corpus. These are replaced before any text model
  sees the email. Corpus style and topics remain (for example `energy`), so the false-positive rate is
  reported per legitimate source and on the own-mailbox set.
- **Tranco membership.** Every legitimate URL comes from Tranco, so the Tranco features (F57–F58)
  separate the classes by construction. URL results are also reported without them.
- **URL shape.** Legitimate URLs are home pages or one deeper page per site. URL results are also
  reported without path features, and with a host-only text input.
- **Missing registration data.** Many country-code registries have no RDAP server, and some
  registries common in phishing refused requests. URL results are also reported without the RDAP
  features.
- **Offline or empty pages.** The share of external links (F84) is missing for 64.6% of phishing and
  32.1% of legitimate URLs, because no page with links was available. Missingness itself therefore
  carries class information. URL results are also reported on samples with a page. [Check that the
  report contains this row.]

## 3.9 Feature extraction

Each sample is turned into the 140 features of the proposal's Appendix A, in a fixed order and with
fixed names (Table 3.5). The full catalogue is in Appendix [A]. The same extractor code is used for
training and for live scans, which prevents differences between training and serving. A hash of the
extractor code is stored with every feature table and model, and a model built from other code is
refused.

**Table 3.5: Feature groups**

| Features | Group | Count | Input |
|---|---|---|---|
| F1–F45 | URL lexical | 45 | the URL string |
| F46–F65 | Domain and TLS | 20 | stored RDAP, DNS and TLS evidence |
| F66–F95 | HTML and JavaScript | 30 | the stored page (read as text, never run) |
| F96–F115 | Email headers | 20 | the raw email |
| F116–F140 | Email text | 25 | the normalised subject and body |

**Modalities.** URL records get F1–F95 and emails get F96–F140. The other modality's features are
missing. Pages linked from emails are never fetched.

**Missing values.** One missing value (NaN) is used for both "not applicable" and "could not be
measured". XGBoost and LightGBM learn which way to send missing values, so missingness is used without
inventing a number. A sentinel such as −1 was rejected because it collides with real values (F133
ranges from −1 to 1). The missing rate of every feature, per class, is reported in the data card.

**Measured at capture time.** Registration data was fetched hours or days after the page. A phishing
domain taken down in between shows a fresh "last changed" date, which would reveal the label. All ages
(domain, certificate) are therefore measured at the capture time stored in the snapshot, and F51 is
missing when "last changed" is later than the capture. Registries that hold no registrant details
(for example Verisign for `.com`) give missing values for F50 and F52, not 0.

**External lists.** Lists used by features come from dated external sources, never from the dataset,
which would leak the test set:

- F26 (suspicious TLD): the 20 TLDs with the highest Phishing Domain Score in Interisle Consulting
  Group's report for May 2025 to April 2026 [cite];
- F27 (URL shortener): a public list of 1,454 shortener domains (CC BY-SA 4.0) at a pinned version
  [cite];
- F109 (suspicious mailer): the three X-Mailer rules of Apache SpamAssassin 4.0.2. No published list
  names phishing kits, so F109 is almost always 0.

The word lists for urgency, threat, reward, financial terms, greetings and calls to action, and the
weights of F138, were written by hand before any model was trained and were never tuned on the data.
They are published in the code, so they cannot leak the test set.

**Text libraries.** F129 uses `pyspellchecker` 0.9.1 and F133 uses `vaderSentiment` 3.3.2 (both MIT,
both offline). F130 is the Flesch reading ease, computed with the published formula [cite].

**Not implemented.** F65 (suspicious ASN) needs an IP-to-network dataset and an abuse list, which were
not collected. It stays in the vector to keep the fixed list, but is always missing, so the models
ignore it.

**Email normalisation.** A time-clue normaliser hides the age gap:

- `Date` and `Delivery-Date` values, and the timestamp in `Received`, become `<DATE>`;
- `X-Mailer`, `User-Agent` and `X-MimeOLE` become `<MAILER>`;
- years from 1990 to 2039 in the subject and body become `<YEAR>`.

The header features (F96–F115) are computed from the raw email, and the text features (F116–F140) from
the normalised one. Otherwise the normaliser would erase F109 and F110, and the "without age-sensitive
features" check would compare nothing. Header authentication features (F96–F101) read only the
`Authentication-Results` headers already in the email. No live DNS lookup is made, since old DKIM keys
no longer exist.

**The feature table.** The extractor ran on all 169,178 URL and 32,345 email records in about 50
minutes on 10 workers. A page was available for 85,944 URL records and missing for 83,234, and no page
was unreadable.

## 3.10 Feature sets used in the experiments

To test the biases in Section 3.8, every model is trained on several feature sets (Table 3.6).

**Table 3.6: Feature sets**

| Modality | Set | What it leaves out | Purpose |
|---|---|---|---|
| URL | `all` | nothing (F1–F95) | main RQ1 result |
| URL | `no_path` | every URL lexical feature that reads the path, query or fragment, including whole-URL counts such as F1; 15 host-only features remain | URL shape (D10c) |
| URL | `no_rdap` | F46–F52 and F55 (F55 can use RDAP name servers) | missing registration data |
| URL | `no_tranco` | F57–F58 | Tranco membership |
| URL | `live_stage1` (M1) | everything needing contact with the site, plus RDAP and Tranco; 48 features | deployed first stage |
| URL | `live` (M2) | RDAP, Tranco and F55; 84 features | deployed second stage |
| Email | `no_header` | F96–F115 | **headline email result** |
| Email | `all` | nothing (F96–F140) | comparison |
| Email | `no_age` | F96–F101, F109, F110 | age gap |

## 3.11 Text model inputs

The LSTM, the 1D-CNN and DistilBERT read raw text instead of features:

- **URLs** are read as characters (up to 200), in two versions: the full URL, and only the scheme and
  host. The host-only version shows how much of the URL score comes from URL shape.
- **Emails** are read as the subject and body after the time-clue normaliser, with no other headers.
  The LSTM and CNN use the first 400 words, with a vocabulary of 30,000 built from the training folds
  only. Corpus names are replaced with `<ORG>` and years are removed (Section 3.8).

The same function prepares text for training and for live scans. The text models use the same five
folds as the tabular models. [Text model training settings and tuning belong in the models section.]
