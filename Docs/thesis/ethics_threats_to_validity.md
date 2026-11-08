# Ethics and threats to validity (draft)

**DRAFT for the thesis.** Facts come from `Docs/decisions.md`, `Docs/data_card.md`,
`Docs/ethics_request.md`, `PROGRESS.md` and `Docs/CLAUDE.md`, as of 2026-11-08. Items in [brackets]
still need a figure, a citation or a check. Section numbers are placeholders.

## 6.1 Ethics

### Data sources and their terms

Each source's terms were checked before use [cite each]:

- the OpenPhish community feed is for "academic, independent, or personal research", with no
  redistribution to third parties;
- the Nazario corpus is CC BY 4.0, which requires attribution;
- the Enron corpus asks users to be sensitive to the privacy of the people involved; only received
  mail is used, and corpus words that identify it are hidden from the text models;
- the SpamAssassin ham stays under its senders' copyright, with hostnames obfuscated;
- PhishTank's terms ask for an identifying User-Agent and limit downloads without an app key.

**URLhaus.** The abuse.ch terms (effective 4 November 2025, section 7.3) forbid using its data "to
customise, train, or otherwise improve any artificial intelligence model or product" without
Spamhaus's written consent. URLhaus is therefore used only in the blocklist lookup baseline, which
compares a URL with a list and trains nothing. No model sees URLhaus data, and it is not part of
`ti_score`.

**VirusTotal and OTX.** The free VirusTotal API must not be used in commercial products or services,
and multiple accounts must not be used to get around its limits. [Check both providers' terms of
service on using results as model input, and state the result: neither page could be read
automatically at the time of writing.]

**No redistribution.** Raw data is never published. The public repository contains the scripts that
rebuild the dataset from the original sources.

### Handling live phishing pages

Phishing pages are fetched only by the snapshot collector, inside its container, with plain HTTP GET:
no JavaScript is run, no forms are submitted and no binary files are downloaded. Further safeguards are
listed in Section 3.4: redirect checks, refusal of private addresses, connecting only to the checked
address, no secrets in the container, and code that refuses to run outside it.

Stored phishing pages are research data, read only as text and never opened in a browser. Windows
Defender quarantined some of them, which would have removed the most typical phishing pages and biased
the dataset. The data folder alone was therefore excluded from scanning, and the one quarantined page
was restored. [Confirm this wording.]

### Simulations

Simulations target only consenting adult volunteers and test mailboxes the researcher controls, after
university ethics approval. **Approval has been requested and is pending** [update with the date and
reference]. The software refuses to launch a campaign without an approval reference.

The safeguards are described in Section 5.9:

- recorded, unwithdrawn consent for every target;
- a fictional organisation, with names of real brands refused;
- an explanation page shown as soon as a link is opened, which has no form, so no password can be
  entered;
- capture switched off as a second control;
- results reported as totals only;
- a training sample made from the template's text, never from participant data.

Participants are told in advance that unannounced simulated emails will arrive. This limited deception
is necessary, because announcing each email would change the behaviour being measured. Everyone gets a
debrief at the end of the study.

**Personal data.** PhishGuard stores participants' email addresses encrypted, with a keyed hash for
look-ups. GoPhish itself stores each participant's email address, IP address and browser with every
event, in its own database. PhishGuard does not copy the IP address or browser. Withdrawal deletes a
participant's PhishGuard records; their GoPhish entry is removed by hand.

**Questions put to the ethics committee:**
- whether data may be kept with no planned deletion date, as the researcher proposed, and if not, what
  period applies;
- what further safeguards are needed if the researcher's own students or staff take part.

[Record the committee's answers.]

## 6.2 Threats to validity

Each threat is listed with how the design handles it and what remains.

**Table 6.1: Threats to validity**

| Threat | What it is | How the design handles it | What remains |
|---|---|---|---|
| Email age gap | Legitimate emails are old (Enron mostly 2000–2002, SpamAssassin ham 2002); most phishing emails are from 2005–2025. A model could learn "old versus new". | Time-clue normaliser (dates, mailer names and years replaced); results also without the age-sensitive features F96–F101, F109, F110; a recent own-mailbox check set for evaluation only. | Writing style and topics still differ by era. The own-mailbox set is small [give its size]. |
| Enron headers | The Enron release has no delivery headers (0% Received or Return-Path, against 100% for Nazario), and its Message-IDs end in `@thyme`. Header features identify the corpus. | Headline email results use no header features; header features are evaluated only on SpamAssassin against Nazario; FPR per legitimate source. | The development results show it: with header features, the FPR was 0% on Enron and 6.2% on SpamAssassin (development, soft vote) [update]. |
| Corpus words | Words such as `enron`, `jose` and `monkey` identify the source corpus. | Replaced with `<ORG>` and years removed before any text model was trained. | Corpus style and topics remain (for example `energy`, forwarded-mail markers). FPR per source and on the own-mailbox set. |
| Tranco membership | Every legitimate URL comes from Tranco, so F57–F58 separate the classes by construction. | Results also without F57–F58; the deployed models leave them out. | Legitimate URLs are popular sites; less-visited legitimate sites are not represented. |
| URL shape | Legitimate URLs are home pages, or one deeper page per site; phishing URLs have long paths. | One deeper page per Tranco site (D10a); results without path features; a host-only text model. | The deeper pages are one per site and chosen from home-page links, so they are still not typical of all legitimate URLs. |
| Missing registration data | RDAP is missing more often for some registries, some of them common in phishing. | Missing values kept as missing, with the reason; per-class missing rates in the data card; results without the RDAP features; deployed models without them. | Missingness itself can still carry class information in the `all` results. |
| Takedown pages | Many phishing pages were offline or showed a takedown, parking or bot-check page at capture time. | Results per snapshot status, and on samples with a page; "unknown" kept as the honest category. | Page features partly describe takedowns, not attacks. Per-category URL results rest on about 4,900 labelled URLs. |
| PhishTank `target` skew | Brand labels from PhishTank's `target` field are skewed (Allegro 1,899 of 5,138). | Used only for the attack category, which is reported as it comes out. | Per-brand conclusions are weak. [State how PhishTank assigns `target`.] |
| TI circularity | The phishing URLs come from PhishTank and OpenPhish, which also feed threat-intelligence services, so `ti_score` may repeat the label. | Feed-named engines removed from the VirusTotal count; same-day lookups; the "flagged on the day" share and `ti_score` alone are reported. | Feeds can reach VirusTotal and OTX through other engines and pulses: the first real answers (2026-11-08) list 93 engines, among them "PhishFort" and "Phishing Database", which are not our sources and stay in the count but may take in PhishTank or OpenPhish reports. RQ2 runs on a subset sized to the free API limits. |
| Small simulation sample | Few volunteers give low power for RQ3. | Size-matched arms (B and C differ only in k samples), 5 seeds per round, group-bootstrap CIs. | An inconclusive RQ3 result is possible, and will be reported as such. |
| Template leakage | A model could learn the simulation templates rather than phishing. | Simulation-holdout templates are never used for training, and every retrained model is checked on them; C must also beat B on fresh feed data. | A small number of templates limits how far the result generalises. |
| Single-level tuning | Tuning and development evaluation use the same folds, so development scores are slightly optimistic. | Stated; the locked test set, used once, gives the unbiased estimate. | Development comparisons between close models may be affected. |
| Less tuning for text models | LSTM and CNN get 10 trials on one fold, DistilBERT none, against 50 trials over five folds for tabular models. | Stated as a limitation of the comparison. | Text models may be under-estimated relative to tabular models. Resumed searches used a different seed for their remaining trials. |
| Baseline tuned on our data | SpamAssassin's rule scores were probably tuned on its own public ham corpus, which is one of our legitimate sources. | FPR per legitimate source. | The baseline's FPR on SpamAssassin ham may be optimistic. |
| External TLD list overlap | The F26 suspicious-TLD list comes from Interisle's report for May 2025 to April 2026, which overlaps the collection period. | The list is external and not derived from our split. | TLDs heavily used in our phishing feeds will also rank high in the report. |
| Dataset size | The planned 175,000 samples were not reachable with public phishing-email corpora; 122,042 were used, and the email set (18,858) is much smaller than the URL set (103,184). | Every usable sample was used, without oversampling; URLs and emails are reported separately. | Email results have wider confidence intervals. |

[Add any threat found during the final evaluation.]
