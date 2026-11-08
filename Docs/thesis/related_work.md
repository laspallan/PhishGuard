# 2 Related work (draft)

**Before keeping any sentence, read the source it cites.** Every source is in `reading_list.md` and
was checked on the web, but this draft was written from short notes on each paper, not from the
papers themselves. Figures from the industry reports must be taken from the report PDFs. [brackets]
mark what is still missing.

## 2.1 Phishing as a problem

Phishing and spoofing are among the most reported kinds of cybercrime (FBI IC3, 2026), and anti-
phishing groups record hundreds of thousands of phishing attacks every quarter (APWG, 2026). Social
engineering, which now also arrives by SMS and phone, remains a major way into organisations
(Verizon, 2026). [Add one or two figures, from the PDFs.]

## 2.2 Approaches to phishing detection

Surveys group detection methods into three families: **lists** of known phishing sites,
**similarity** to the sites being imitated, and **machine learning** on features of the URL, the page
or the email (Zieni et al., 2023). Deep-learning detectors form a growing part of the field (Do et
al., 2022).

**Lists and blocklists** are precise for what they contain, but they are reactive. Measurements at
scale found that phishing campaigns are short-lived, and that blocklists often list a site only hours
after its first victims visited it (Oest et al., 2020a); their speed and coverage are inconsistent,
and sites that evade crawlers are listed late or not at all (Oest et al., 2020b).

**Feature-based machine learning** generalises beyond known sites. Tree ensembles are strong
baselines on URL features; Sahingoz et al. (2019) report 97.98% accuracy with a random forest. This
project uses random forests together with the gradient-boosting libraries XGBoost (Chen & Guestrin,
2016) and LightGBM (Ke et al., 2017).

**Models on the raw text** learn their own representation. URLNet uses character- and word-level
convolutional networks on the URL (Le et al., 2018). Transformers have been reported to do better at
very low false-positive rates: URLTran, a BERT-style model, reached a true-positive rate of 86.8%
against 71.2% for a CNN baseline at an FPR of 0.01% (Maneriker et al., 2021). DistilBERT is a smaller,
faster version of BERT that keeps most of its performance (Sanh et al., 2019), which makes it a
practical choice where latency matters; PhishGuard uses it as the slow second stage of a cascade.

## 2.3 How detectors are evaluated, and where evaluations go wrong

A recurring finding is that published results overstate how detectors perform in use.

- Arp et al. (2022) reviewed 30 security papers at top venues and identified ten common pitfalls,
  among them sampling bias, label inaccuracy, data snooping and inappropriate baselines.
- In malware classification, random train/test splits inflate performance compared with splits that
  respect time and realistic class ratios (Pendlebury et al., 2019), and deployed classifiers degrade
  as the data drifts (Barbero et al., 2022).
- For phishing specifically, Das et al. (2020) argue that research often ignores security needs such
  as real-time detection, active attackers, dataset quality and the base-rate fallacy, and
  benchmarking showed that class imbalance hurts detectors and that retraining alone does not defeat
  new attacks (El Aassal et al., 2020). A recent dataset paper reports label noise and unrealistic
  base rates in public phishing datasets and proposes time-split benchmarks (Dalton et al., 2025;
  preprint).

These findings shape PhishGuard's method: a split by group so that near-identical samples never sit on
both sides, a locked test set used once, results per legitimate source, and a fresh-data test over
time in RQ3 (Chapters 3 and 4). [Consider a sentence on base rates: the dataset is balanced, which
real traffic is not.]

## 2.4 Threat intelligence and VirusTotal

Services such as VirusTotal aggregate the verdicts of many scanning engines. Their labels are not
ground truth: engines change their verdicts over time, "trusted" engines are not always accurate, and
correlated engines should not be counted as independent votes (Zhu et al., 2020). For URLs, engines
detect phishing unevenly and update with a lag, and some phishing pages were detected by none of the
engines (Peng et al., 2019).

Two consequences for this project: the `ti_score` threshold and counting choices matter, which is why
the formula was fixed before any answer was seen; and the engines that are themselves fed by the
project's sources (PhishTank, OpenPhish) are removed from the count, to limit circularity (Section
4.8). [No study was found that measures, as RQ2 does, what TI adds to a trained detector's false-
positive rate; confirm with your own search before claiming it.]

## 2.5 Visual similarity and brand impersonation

Many phishing pages imitate a known brand, which visual methods exploit. VisualPhishNet compares
screenshots against a list of trusted brands to detect zero-day phishing (Abdelnabi et al., 2020).
Phishpedia detects and matches logos to identify the brand being imitated, which gives explainable
verdicts without phishing training data (Lin et al., 2021), and combining the brand check with a check
for credential-taking intent cut false alarms by 86.5% (Liu et al., 2022). The favicon alone has also
been used as a brand signal (Chiew et al., 2018). These detectors are, however, easy to evade, for
example by removing or altering logos, and they do poorly on large sets of real phishing sites
compared with curated benchmarks (Ji et al., 2025).

PhishGuard's visual check (D6) is deliberately small: a perceptual hash of the favicon, used only to
warn. No peer-reviewed study of perceptual hashing of favicons was found, so the hashing approach is
this project's own choice, and it has no measured detection rate (Chapter 8).

## 2.6 Phishing simulations and training

Organisations send simulated phishing emails to train staff. Large field studies question how much
the attached training helps: in a 15-month study with 14,000 employees, embedded training did not
make employees more resilient, while employees reporting phishing helped detect campaigns quickly
(Lain et al., 2022); a randomised controlled trial with about 19,500 employees found that annual and
embedded training reduced click rates by only about 2% (Ho et al., 2025). Such results support
technical controls alongside training.

Deception-based phishing experiments raise ethical questions about consent and debriefing (Finn &
Jakobsson, 2007), and the Menlo Report sets out general principles for research on information and
communication technology: respect for persons, beneficence, justice, and respect for law and public
interest (Dittrich & Kenneally, 2012). Chapter 6 describes how this study follows them.

What these studies measure is people. A failed simulation is also a labelled example of a phishing
email that worked, but no study was found that feeds simulation data back into a detector and
separates its effect from simply retraining on fresh data. [Confirm with your own search; this is the
gap RQ3 addresses.]

## 2.7 Calibration and comparing classifiers

Modern neural networks are often poorly calibrated (Guo et al., 2017), and boosted trees and other
classifiers also give distorted probabilities that Platt scaling or isotonic regression can correct
(Niculescu-Mizil & Caruana, 2005). PhishGuard calibrates every model before combining them, because
soft voting and fixed thresholds assume comparable probabilities. To compare two classifiers trained
once, McNemar's test is recommended over resampled t-tests (Dietterich, 1998); comparisons over many
datasets call for other tests (Demšar, 2006), which is not the situation here. [Add a bootstrap
reference after checking it, e.g. Efron & Tibshirani, 1993.]

## 2.8 The gap this thesis addresses

[Draft to check against the sources once read.] Detection research reports high accuracy, but often
on splits and datasets that overstate it (2.3). Threat intelligence is widely used, but its labels are
noisy and its added value to a trained detector is seldom measured directly (2.4). Simulations are
common, but their data is not usually used to improve detection, and when it is, its effect is not
separated from that of fresh data (2.6). PhishGuard addresses these three points with a group-split
evaluation and a once-only locked test set (RQ1), a with-and-without comparison of threat intelligence
on the same folds (RQ2), and a size-matched comparison of retraining with and without simulation data
(RQ3).
