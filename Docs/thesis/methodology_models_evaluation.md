# Methodology: models and evaluation (draft)

**DRAFT for the thesis.** Facts come from `Docs/decisions.md`, `PROGRESS.md`, `Docs/CLAUDE.md` and
the docstrings in `ml/`, as of 2026-11-08. No locked-test result exists yet; nothing here is a final
result. Items in [brackets] still need a figure, a citation or a check. Section numbers are
placeholders.

## 4.1 Overview

URLs and emails have separate models of the same six types (decision D5): three tabular models on
the engineered features (random forest, XGBoost, LightGBM) and three text models on raw text (LSTM,
1D-CNN, DistilBERT). Their probabilities are calibrated and combined by two ensembles. A cascade lets
the slow text model decide only when the fast ensemble is unsure. Everything in this chapter is fitted
and compared on the development set (85% of the data) with 5-fold group cross-validation. The locked
test set (15%) is used once, at the end (Section 4.9).

## 4.2 Tabular models

**Models.** Random forest (scikit-learn 1.9.1), XGBoost 3.2.0 (Chen & Guestrin, 2016) and LightGBM 4.7.0 (Ke et al., 2017) [cite random forest and scikit-learn]. All
three accept missing values (NaN) directly, which was checked on the installed versions, so no
imputation is needed (Section 3.9).

**Out-of-fold predictions.** For each of the five development folds, a model is trained on the other
four and predicts the held-out fold. Every development sample therefore gets exactly one prediction
from a model that never saw it. Calibration, ensembles and all development results are built from
these out-of-fold (OOF) predictions.

**Tuning.** Hyper-parameters are tuned with Optuna (TPE sampler, seed 42) [cite]. The objective is
the log loss of the OOF predictions over all five folds, with 50 trials per model and feature set.
Log loss was chosen because it scores the probabilities themselves, which calibration, the ensembles
and the 0.60 / 0.90 thresholds all depend on, and it needs no threshold. F1 at 0.5 was rejected
because it ignores how confident a model is.

**Single-level, not nested.** Tuning and evaluation use the same folds, so the development scores are
slightly optimistic. Nested cross-validation would remove this, but would multiply the training time
by about five. The optimism is stated, and the locked test set gives the unbiased estimate.

**Final model.** After tuning, each model is refitted on all development rows with the best settings.
It is saved with its calibrator, a version id and hashes of the feature code, the split and the model
file, in a model registry. Mean absolute SHAP values (TreeExplainer) are saved for each final model
[cite SHAP].

## 4.3 Text models

**Inputs** (Section 3.11). URLs are read as characters (up to 200), as the full URL and as the scheme
and host only. Emails are read as words (the first 400 of the normalised subject and body), with a
vocabulary of 30,000 built from the training folds only, so held-out text cannot leak into it.

**LSTM and 1D-CNN.** Both use the same five folds as the tabular models, so all models are compared on
the same samples. Early stopping watches a group-aware 10% slice of the training rows, never the
held-out fold. The LSTM is a two-layer bidirectional network [describe the CNN layers]. Optuna runs 10
trials on fold 0 only, searching the learning rate (10⁻⁴ to 3×10⁻³, log scale), embedding size (64 or
128), dropout (0.1 to 0.5), batch size (64 or 128) and, for the LSTM, hidden size (64, 128 or 256),
with at most 10 epochs and a patience of 2 [give the CNN's search space]. The final model is trained on
all development rows for the median number of epochs that early stopping chose across the folds.

**DistilBERT** (Sanh et al., 2019) uses fixed settings, without tuning: a learning rate of 2×10⁻⁵ and at most 3
epochs, the usual choices for this model. Tuning would multiply the GPU time.

**Hardware.** The tabular models and the CNN were trained on the project PC's CPU. The LSTM was too
slow there: rough estimates, measured while the tabular models used the CPU, were 342–429 hours per
URL run and 592–1,183 hours per email run. The LSTM and DistilBERT were therefore trained on a cloud
GPU (Google Colab) [state any other service used]. Only development rows were exported for this. The
locked test set never left the PC. A standalone script reproduces the repository's LSTM exactly; on a
CPU, both give the same predictions. Results are imported only after checks that the split, the text
code, the samples, the labels and the folds all match.

**Resumed searches.** A cloud session can stop mid-run. Finished trials and folds are saved, and a
resumed search draws its remaining trials with a different seed. The search is still valid, but it is
not the exact search an uninterrupted run would make. [State which runs were resumed; at the time of
writing, the URL `text_full` LSTM was resumed after 3 of 10 trials.]

**Limitation.** The text models get far less tuning than the tabular models: 10 trials on one fold, or
none for DistilBERT, against 50 trials over five folds. Comparisons between the two families must be
read with this in mind.

## 4.4 Calibration

Each model's OOF probabilities are calibrated with isotonic regression (Niculescu-Mizil & Caruana, 2005), **cross-fitted** by
fold. A sample in fold k is calibrated by a calibrator fitted on the other folds' predictions, so no
sample is calibrated with its own label. A test flips one fold's labels and checks that this fold's
calibrated values do not change. The calibrator used in deployment is fitted on all OOF predictions.
Isotonic regression was chosen over Platt (sigmoid) scaling because tree-model scores are often not
sigmoid-shaped, and tens of thousands of OOF predictions are enough for isotonic regression not to
overfit.

## 4.5 Ensembles, thresholds and the cascade

**Soft voting** averages the three tabular models' calibrated probabilities.

**Stacking** fits a logistic regression on the three models' raw OOF probabilities, as log-odds,
cross-fitted by fold. Raw rather than calibrated inputs are used because the cross-fitted calibrators
of the other folds were fitted with this fold's labels, so stacking calibrated values would leak them.
The logistic regression calibrates its own output.

**Decisions.** Block if p ≥ 0.90, warn if p ≥ 0.60, otherwise allow. These are the planned defaults.
Any change would be chosen on development OOF predictions only. A helper exists to find the threshold
for a target false-positive rate, if that is preferred later [state whether it is used].

**Cascade.** The fast tabular soft vote decides alone outside [0.30, 0.80] (inclusive). Inside that
band, DistilBERT is asked and its calibrated probability is used. For URLs the cascade uses the
deployed `live` feature set and DistilBERT on the full URL; for emails, `no_header` and DistilBERT on
the subject and body. Its CPU latency is measured [give the figure once DistilBERT is trained].

**Live URL stage-1 band.** Live URL scans use a separate two-stage design (Chapter 5). The band of
stage-1 scores that triggers a page fetch is chosen on M1's development OOF predictions for a target
share of fetched URLs, never on the locked test set [give the chosen band and share].

## 4.6 Metrics

All development results are computed on the calibrated OOF predictions at threshold 0.5:

- accuracy, precision, recall, F1 and the false-positive rate (FPR);
- the FPR at the warn (0.60) and block (0.90) thresholds;
- the expected calibration error (ECE, 10 bins);
- the FPR **per legitimate source** (for emails, Enron and SpamAssassin separately), because a model
  can score well by recognising a corpus (Section 3.8);
- 95% confidence intervals by **group bootstrap**, which resamples whole groups (registered sites,
  senders) rather than single samples. Samples within a group are correlated, so resampling single
  samples would give intervals that are too narrow. 1,000 resamples are used;
- an **exact McNemar test** (two-sided binomial test on the discordant pairs; Dietterich, 1998) comparing each
  model with the soft vote.

URLs and emails are always reported separately, and each URL and email result is also reported on the
feature sets of Section 3.10. The targets are accuracy above 95% and an FPR below 5%. Results are
reported as they are, including any targets that are missed.

## 4.7 Signature baseline (decision D2)

RQ1 compares the ensemble with a signature-based baseline.

**Emails.** Apache SpamAssassin 4.0.1, from the Debian 13 package, with the rules it ships. `sa-update`
was never run, so the rule set is fixed. Bayes and auto-learning are off. It runs in its own container
with no network and as a non-root user. An email counts as detected when its score reaches the
required score (5.0). Raw emails are scored, as a deployed filter would see them. A smoke test on 300
real emails flagged 82 of 100 Nazario, 3 of 100 SpamAssassin ham and 0 of 100 Enron emails, at about
0.08 s per email [replace with the development result].

**URLs.** RQ1 has no URL baseline. Every phishing URL was taken from the blocklists on its collection
day, so a blocklist lookup would find all of them by construction. URLhaus is used in the RQ3 rounds
instead, where blocklists from earlier days are compared with URLs first seen later. No model learns
from URLhaus data (Chapter 6).

## 4.8 RQ2: the effect of threat intelligence

RQ2 asks what live threat intelligence does to the false-positive rate. A `ti_score` (0–100) is one
extra model input, kept outside the 140 features so models can be compared with and without it.

**The score** (fixed before any real answer was seen):

- VirusTotal: 100 × min(1, (malicious + 0.5 × suspicious) / 5), counted per engine, with engines named
  after the feeds of the phishing URLs (PhishTank, OpenPhish) left out;
- AlienVault OTX: 100 × min(1, pulses / 5);
- `ti_score` is the higher of the two. "Not found" counts as 0; an error leaves that provider out; if
  both are left out, the score is missing.

The higher of the two is used because either source alone is evidence, and an average would halve the
score whenever one provider has not yet seen a new URL. The scale was not tuned. Tree models are
unaffected by any monotonic rescaling of one input, so the combination matters more than the scale.

**The subset (decision D7).** The free VirusTotal API allows 500 lookups a day at 4 a minute, and must
not be used commercially. Threat intelligence is therefore recorded for a subset, at collection time:

- 250 new phishing URLs a day from the daily collector, each looked up within about a day of
  collection;
- 250 legitimate development URLs a day, in a fixed random order, never more than the phishing URLs
  that day, and never from the locked test set;
- planned for 8 days, so 2,000 of each [give the real size].

**The comparison.** On the subset only, the three tabular models and their soft vote use the `live`
feature set, with and without `ti_score`. Both arms use the same rows, the same 5 group folds and the
hyper-parameters already tuned for `url/live`, so the only difference is `ti_score`. The FPR (at 0.5
and at the warn and block thresholds), F1, group-bootstrap CIs and a McNemar test between the arms are
reported. Also reported are `ti_score` alone as a rule, the share of phishing URLs VirusTotal had
already flagged on the day, and the median time from collection to lookup.

## 4.9 The locked test set and the final evaluation

The locked test set is read once, in the final evaluation. Several guards enforce this:

- one module of the training code can open the split, and it returns development rows only; a test
  fails if any other training or evaluation code reads the split;
- the final evaluation refuses to run without an explicit flag confirming that every model is frozen;
- it logs each access before reading, and refuses a model version that was evaluated before;
- it saves every prediction, and a separate report step computes every final number from the saved
  predictions without opening the test set again, so every number can be reproduced;
- ensembles in the final evaluation use only what was fixed on the development set (the calibrators,
  and a stacker fitted on OOF predictions).

## 4.10 RQ3: retraining with simulation data

RQ3 asks whether retraining with samples from failed simulations improves detection over time,
compared with a static model and with a model retrained on the same amount of fresh feed data. In
round r, three arms use the same model type, features, hyper-parameters and seed:

| Arm | Training data |
|---|---|
| A (static) | the development set only |
| B | development data plus every fresh feed sample up to month M+r−1 |
| C | B, with k fresh phishing samples replaced by k simulation samples (same size, same labels) |

All three are scored on the fresh feed data of month M+r and on the simulation-holdout set (samples
from templates never used for training). C against B is the main comparison, because the only
difference between them is the k samples. There are at least three monthly rounds with 5 seeds each.
Arms are scored at threshold 0.5 on uncalibrated probabilities, the same for every arm, because
calibrating would add another fitted step that differs between arms. Differences get group-bootstrap
95% CIs and an exact McNemar test. Tests check that B and C receive the same number of new samples and
the same label balance, and that no simulation sample can enter the locked test set.

**Promotion rule.** A retrained model is promoted only if F1 improves and the FPR does not rise on
both the locked test set and the simulation-holdout set (in rounds after the final evaluation).

Simulations need university ethics approval, which is pending (Chapter 6). [State the number of
rounds, k and the number of participants once known.]
