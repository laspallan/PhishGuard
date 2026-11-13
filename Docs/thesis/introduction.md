# 1 Introduction (draft)

Square brackets mark what is still missing: [result] for a number that does not exist yet. Citations
come only from `reading_list.md`, where each source was checked on the web; read each one before
keeping the sentence it supports. Full references are in the thesis bibliography (to be compiled).

## 1.1 Background and problem

Phishing remains one of the most common ways attackers get a first foothold in an organisation
(FBI IC3, 2026; APWG, 2026; Verizon, 2026) [add figures only from the report PDFs themselves]. It works because it targets people, not software: a convincing email or a page that
looks like a known login screen can lead a user to give away a password or open a harmful file.

Two kinds of defence are widely used. **Signature and blocklist systems** (rule-based spam filters,
URL blocklists) are fast and precise for what they already know, but they react only after a message
or a site has been seen and reported; blocklists often list a phishing site only hours after its
first victims, and miss evasive sites altogether (Oest et al., 2020a, 2020b). **Machine-learning
detectors** generalise from features of the URL, the page and the email, and can flag messages and
sites no list contains yet (Das et al., 2020; Do et al., 2022; Zieni et al., 2023). Published results
for these detectors are often very high, but many are measured on old benchmark datasets, with random
splits that let near-duplicate samples sit on both sides, and seldom on data collected after the
model was trained (El Aassal et al., 2020; Arp et al., 2022). In security ML generally, random
splits overstate performance compared with splits that respect time (Pendlebury et al., 2019).

A third ingredient, **threat intelligence** (TI) from services such as VirusTotal and AlienVault OTX,
can tell a detector what other systems already think of a URL. Its verdicts are not ground truth:
VirusTotal engines disagree, change their labels over time and detect phishing URLs unevenly (Peng
et al., 2019; Zhu et al., 2020). Whether TI lowers a detector's false alarms or just repeats what the
blocklists say is rarely tested directly.

Finally, organisations run **phishing simulations** to train staff, although large field studies
found that the training attached to them changed behaviour little (Lain et al., 2022; Ho et al.,
2025). A failed simulation is, however, a labelled example of a phishing email that worked on real
people. Such data is seldom fed back into the detector, and when it is, the gain is not usually
separated from the effect of simply retraining on more recent data [no such controlled comparison was
found in the reading so far; confirm with your own search before claiming it].

## 1.2 Aim

This project builds and evaluates **PhishGuard**, a phishing detection and simulation platform, and
uses it to answer three questions under controlled conditions: how well an ensemble detects phishing
compared with a signature system, whether live threat intelligence reduces false positives, and
whether data from failed simulations improves detection over time beyond what fresh data alone gives.

## 1.3 Research questions

- **RQ1:** How accurately does the ensemble detect phishing emails and webpages compared with a
  signature-based baseline?
- **RQ2:** What is the effect of live threat intelligence (VirusTotal, AlienVault OTX, URLhaus) on the
  false positive rate?
- **RQ3:** Does retraining with data from failed simulations improve detection over time, compared
  with a static model and with a model retrained on the same amount of fresh feed data without
  simulation data?

Two refinements were made during the work, for reasons given in the chapters cited:

- **RQ1 has a signature baseline for emails only** (SpamAssassin, Section 4.7). Every phishing URL was
  taken from a blocklist on the day it was collected, so a blocklist baseline would detect all of them
  by construction.
- **RQ2 uses VirusTotal and AlienVault OTX.** URLhaus's terms do not allow its data to be used to train
  AI models, so it appears only as a blocklist in the RQ3 rounds, never as a model input (Section 6.1).

## 1.4 Approach in brief

- A dataset of [result: final size, e.g. 122,042] URLs and emails from public phishing feeds and
  legitimate sources, de-duplicated and split by group so that near-identical samples never fall on
  both sides; a **locked test set** is set aside and used exactly once, after every model is frozen
  (Chapter 3).
- 140 hand-defined features (F1–F140) from one extractor shared by training and the live system, and
  six models: random forest, XGBoost and LightGBM on the features; LSTM, 1D-CNN and DistilBERT on the
  raw text; combined by soft voting, stacking and a cascade (Chapter 4).
- A live system: an API, a browser extension, an email gateway and a dashboard, with page fetching
  confined to an isolated container (Chapter 5).
- RQ2 on a subset of fresh URLs looked up in VirusTotal and OTX on the day they were collected,
  comparing the same models with and without a `ti_score` input (Section 4.8).
- RQ3 as a controlled experiment: a static model (A), a model retrained on fresh feed data (B), and the
  same model with some new samples replaced, size for size, by samples from failed simulations (C),
  evaluated each month on data it has not seen, with five seeds (Section 4.10). Simulations target only
  consenting participants, use a fictional organisation, and never collect what is typed.

## 1.5 Contributions

The central contribution is the **loop**, not any one of its parts. Detection, phishing simulation and
retraining are each well studied on their own; they are rarely joined, and the detector is rarely the
thing that consumes the simulation's output. The remaining contributions are the methods that let the
loop be measured honestly.

1. **An integrated, self-improving phishing-defence loop, built as a working system.** PhishGuard
   closes the circuit between three parts that are usually studied apart. The deployed detector scans
   URLs and emails; phishing simulations against consenting staff produce labelled examples of
   phishing that worked on real people; and those examples are fed back as training data for the
   detector's next retraining round. The loop is implemented end to end — an API, a browser extension,
   an email gateway, a dashboard, and the simulation and retraining harness — rather than described in
   the abstract, and a single feature extractor serves both training and the live system, so the
   detector that is evaluated is the detector that runs. A failed simulation yields a sample built only
   from the lure's own text, never from a participant's behaviour or identity. (Whether the loop
   improves detection over time is RQ3, evaluated over [result: number of] monthly rounds in
   Chapter 7; the contribution here is the controlled, deployed loop itself.)
2. An evaluation of the detector on a group-split dataset with a once-only locked test set, with
   results reported separately for URLs and emails and with time clues in old email corpora removed —
   so that the accuracy claimed for the loop's detector is not inflated by near-duplicate leakage.
3. A direct test of what live threat intelligence adds to a trained detector, with the circularity
   between feeds and TI services measured, not assumed away.
4. A controlled, size-matched experiment that isolates the loop's own effect: a static model (A), a
   model retrained on fresh feed data (B), and the same model with some fresh samples replaced, size
   for size, by samples from failed simulations (C). This separates the effect of the simulation data
   from the effect of simply retraining on more recent data, a comparison not found in the reviewed
   literature. Simulation samples are, by construction, barred from the locked test set, so the loop
   cannot inflate the headline (RQ1) result.
5. An open-source implementation, including the data collection, the safety controls for handling live
   phishing pages and for running simulations ethically, and the scripts that rebuild every reported
   number. Raw datasets are not redistributed; the scripts rebuild them.

[Trim to what the results support once they exist. The RQ3 result (contribution 4) is pending the
monthly rounds; until then, claim the loop as built and controlled, not as proven to help.]

## 1.6 Scope

In scope: English-language emails and web URLs; a single deployment on one machine; simulations with
a small group of consenting participants at [institution], subject to ethics approval [reference].
Out of scope: attachments and malware analysis, phishing by SMS or voice, images inside emails,
large-scale deployment, and any interaction with phishing pages beyond one plain page request.

## 1.7 Structure of the thesis

- Chapter 2 reviews related work.
- Chapter 3 describes the data and the features.
- Chapter 4 describes the models, the evaluation and the experiments for RQ1–RQ3.
- Chapter 5 describes the system that was built.
- Chapter 6 covers ethics and threats to validity.
- Chapter 7 presents the results.
- Chapter 8 answers the research questions, states the limitations and suggests further work.
