# Data card

Filled in during Phase 1 and updated whenever the dataset changes. Every number here must
come from a script output, not be typed by hand.

## Sources

| Source | Type | Label | Date range | Licence / terms | Raw count | After cleaning |
|---|---|---|---|---|---|---|
| PhishTank | URL | phishing | | | | |
| OpenPhish | URL | phishing | | | | |
| Tranco top sites | URL | legitimate | | | | |
| Nazario corpus | email | phishing | | | | |
| SpamAssassin public corpus | email | legitimate | 2002–2005 | | | |
| Enron | email | legitimate | 2001–2002 | | | |
| Own mailbox check set | email | legitimate | | evaluation only | | |

## Final dataset

| | URL | Email | Total |
|---|---|---|---|
| Phishing | | | |
| Legitimate | | | |
| Total | | | 175,000 |

### By attack category

| Category | Count | Labelling rule (decision D1) |
|---|---|---|
| credential_harvest | | |
| brand_impersonation | | |
| malware | | |
| spear | | |
| unknown | | |

## Split

| Set | Samples | Phishing | Legitimate |
|---|---|---|---|
| Locked test (15%) | | | |
| Development (85%) | | | |

Seed 42; grouping key per decision D4; split file hash: ``

## Missing values

Share of samples with a missing snapshot, WHOIS, DNS or TLS record, per source.

## Known biases and limitations

- Email age gap: legitimate emails (2001–2005) are much older than the phishing data
  (proposal §3.6.1).
- Phishing pages that went offline before the snapshot was taken have no HTML features.
