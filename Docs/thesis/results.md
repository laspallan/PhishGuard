# Results (draft structure)

Every number in this chapter is copied from a file the pipeline writes, never typed from memory.
`make results` recomputes all of these files in one command, from the saved predictions (it never
opens the locked test set, and it reruns only analyses that have been run before).
Each table below names its source file and the command that rebuilds it; to update the chapter,
rerun the command and paste the table again. Development numbers (cross-validation) and final
numbers (locked test set) are never mixed in one table, and results are reported as they are,
including those that do not favour PhishGuard.

| Source file | Command | Contents |
|---|---|---|
| `data/models/results.md` | `python -m phishguard_ml report` | development results, every model and feature set |
| `data/models/rq2/results.md` / `.json` | `python -m phishguard_ml rq2` | RQ2 arms on the TI subset |
| `data/models/final/final_results.md` / `.json` | `python -m phishguard_ml final-report` | locked-test results (after `final-eval`) |
| `data/models/final/recent_email_check.json` | `final-report` | FPR on recent legitimate emails from own mailbox |
| `experiment_results` table (dashboard: Experiments) | RQ3 harness | RQ3 rounds, arms A/B/C, 5 seeds |

## 7.1 Development results (model selection only)

Purpose: show how the models and ensembles compare during development, and justify the choices
frozen before the final run. Not evidence for the research questions.

Table 7.1 — URL soft-vote ensemble per feature set (development, 5-fold out-of-fold, calibrated,
threshold 0.5; n = 87,706; source `data/models/results.md`, `python -m phishguard_ml report`). The
per-model rows (random forest, XGBoost, LightGBM, stacker) and within-set McNemar tests are in
`results.md`; the soft vote is shown here as the headline model for each feature set.

| Feature set | Accuracy | Precision | Recall | F1 [95% CI] | FPR [95% CI] | ECE |
|---|---|---|---|---|---|---|
| all        | 0.9957 | 0.9959 | 0.9955 | 0.9957 [0.9952, 0.9962] | 0.0041 [0.0035, 0.0047] | 0.0007 |
| no_path    | 0.9944 | 0.9946 | 0.9941 | 0.9944 [0.9938, 0.9949] | 0.0054 [0.0048, 0.0062] | 0.0007 |
| no_rdap    | 0.9956 | 0.9956 | 0.9956 | 0.9956 [0.9951, 0.9961] | 0.0044 [0.0038, 0.0050] | 0.0008 |
| no_tranco  | 0.9866 | 0.9904 | 0.9827 | 0.9866 [0.9856, 0.9875] | 0.0095 [0.0086, 0.0104] | 0.0017 |
| live (M2)  | 0.9847 | 0.9891 | 0.9802 | 0.9846 [0.9837, 0.9856] | 0.0108 [0.0099, 0.0117] | 0.0016 |

The live cascade's stage-1 model (`live_stage1`, M1) soft vote scores F1 0.9768 [0.9756, 0.9780],
FPR 0.0150; its served member is LightGBM (F1 0.9776, lowest OOF log loss 0.0633), on which the
stage-1 band is set (§ 7.2 / `decisions.md` 2026-11-11). URL text models on the same folds
(`results.md`): on `text_full`, DistilBERT F1 0.9789 [0.9779, 0.9799], 1D-CNN 0.9651, LSTM 0.9737;
on `text_host`, DistilBERT 0.9541, 1D-CNN 0.9445, LSTM 0.9478. DistilBERT is the strongest URL text
model, and the full URL string carries more signal than the host alone.

Table 7.2 — email soft-vote ensemble per feature set, with the DistilBERT cascade and the
SpamAssassin baseline (development, 5-fold out-of-fold, calibrated, threshold 0.5; n = 16,065;
source `results.md`). Baseline run complete 2026-11-08; `no_age` trained 2026-11-11.

| Model / feature set | Accuracy | Precision | Recall | F1 [95% CI] | FPR [95% CI] | ECE |
|---|---|---|---|---|---|---|
| no_header (soft vote)       | 0.9501 | 0.9626 | 0.9365 | 0.9494 [0.9420, 0.9557] | 0.0364 [0.0301, 0.0437] | 0.0062 |
| no_header + DistilBERT cascade | 0.9702 | 0.9821 | 0.9578 | 0.9698 [0.9646, 0.9749] | 0.0174 [0.0130, 0.0222] | 0.0038 |
| all (soft vote)             | 0.9923 | 0.9908 | 0.9938 | 0.9923 [0.9884, 0.9948] | 0.0092 [0.0045, 0.0171] | 0.0019 |
| no_age (soft vote)          | 0.9915 | 0.9895 | 0.9937 | 0.9916 [0.9874, 0.9943] | 0.0106 [0.0054, 0.0186] | 0.0012 |
| SpamAssassin baseline       | 0.7637 | 0.9914 | 0.5321 | 0.6925 [0.6581, 0.7301] | 0.0046 [0.0021, 0.0084] | –      |

Email text models on the same folds (`results.md`, `email/text_body`): DistilBERT F1 0.9865
[0.9836, 0.9889], FPR 0.0149; 1D-CNN F1 0.9811, FPR 0.0167; LSTM F1 0.9742, FPR 0.0230. DistilBERT
is the strongest and is the cascade's text member.
- Text models (LSTM, 1D-CNN, DistilBERT) against the tabular models on the same folds.
  [2026-11-12: all nine text models trained on Colab GPUs and imported (LSTM ×3, DistilBERT ×3,
  CNN ×3). DistilBERT is best in every text table (email F1 0.9865, url_full 0.9789, url_host 0.9541);
  the full URL string beats the host alone (0.9789 vs 0.9541). The tabular URL ensembles (F1 ~0.996)
  still lead every text model; on email the DistilBERT cascade (0.9698) and the `all` soft vote
  (0.9923) lead.]
- Feature importance: mean |SHAP| for XGBoost and LightGBM (`shap_report.py`). [figure]

Points to discuss (already visible in development, to be confirmed or not by the final run):
- The SpamAssassin corpus has a much higher false-positive rate than Enron in every email model
  (about 6% against 0%). Report it per legitimate source, as `fpr_by_legitimate_source` does.
- SpamAssassin finds about half the phishing emails (recall 0.53) but raises fewer false alarms
  than the header-free ensemble (FPR 0.5% against 3.6% in development). Discuss this trade-off
  openly: the ensemble's gain is in recall, not in false positives, unless the final run says
  otherwise.
- `no_tranco` costs about 0.9 accuracy points on URLs: part of the URL result rests on the
  popularity list.

## 7.2 RQ1: detection performance on the locked test set

- Table 7.3: final URL and email results with 95% bootstrap CIs (grouped by `group_key`), ECE,
  FPR at the warn and block thresholds (from `final_results.md`). [after `final-eval`]
- McNemar tests between the soft vote and each other model (development table; the final run
  evaluates each frozen model once).
- Recent-email check: FPR on own-mailbox emails (`recent_email_check.json`). [needs the `.eml` set]
- Latency: median and p95 per stage, from the deployed API (`/admin/overview`). [after Phase 5]

## 7.3 RQ2: does threat intelligence add to the models?

**Status: numbers below are from five recording days (run 2026-11-12, n = 2,500). The recording
window is still open; rerun `python -m phishguard_ml rq2` when it closes and paste the refreshed
table over this one. With the extra two days the TI gain crossed into significance — see the
reading.**

Table 7.4 — `url/live` soft vote on the TI subset, same rows, folds and tuned parameters in
every arm (source: `data/models/rq2/results.md`):

| Model | n | Accuracy | Precision | Recall | F1 [95% CI] | FPR [95% CI] | ECE | McNemar p vs soft vote without ti_score |
|---|---|---|---|---|---|---|---|---|
| soft_vote_without_ti | 2500 | 0.9684 | 0.9665 | 0.9704 | 0.9685 [0.9497, 0.9804] | 0.0336 [0.0243, 0.0437] | 0.0051 | – |
| soft_vote_with_ti | 2500 | 0.9752 | 0.9722 | 0.9784 | 0.9753 [0.9597, 0.9849] | 0.0280 [0.0198, 0.0375] | 0.0065 | 0.0300 |
| ti_score_alone | 2500 | 0.7816 | 0.9916 | 0.5680 | 0.7223 [0.6859, 0.7450] | 0.0048 [0.0016, 0.0089] | 0.2133 | 0.0000 |

From `rq2/results.json` (2026-11-12): n = 2,500 (1,250 phishing, 1,250 legitimate); `ti_score`
missing for 38; **58.9% of fresh phishing was flagged by VirusTotal on the day of collection**;
median 4.2 hours from collection to lookup.

Reading of the table (five days; rerun when the recording window closes):
- Adding `ti_score` to the soft vote improves every headline number, and with five days the paired
  difference is now **statistically significant** (exact McNemar p = 0.030): F1 0.9685 → 0.9753,
  FPR 3.4% → 2.8%. At three days (n = 1,500) it was not yet significant (p = 0.108); report both so
  the viva sees that the TI benefit becomes detectable only as the subset grows — a modest effect.
- `ti_score` alone is **significantly worse** than the models (p < 0.0001): recall 0.57 — it
  misses more than two fifths of fresh phishing — while its precision (0.992) and FPR (0.005) are
  the best in the table. Threat intelligence is right when it fires; it fires too late.
- The mechanism is the lag: only about three fifths (58.9%) of fresh phishing is known to
  VirusTotal on the day it is collected, so the model features carry the rest.
- OTX check (3-day subset, 2026-11-11): the early "no pulses at all" observation does
  **not** hold — 19 of 1,500 answers had at least one OTX pulse (maximum 21), and some of those
  were on **legitimate** URLs. `ti_score` is still driven almost entirely by VirusTotal; say
  that, and note that pulses alone would misfire on legitimate sites.
- Threats: circularity through feed-fed engines (Chapter 6, TI circularity row).

## 7.4 RQ3: does the feedback loop help over time?

- Figure 7.1: F1 per monthly round for arms A (static), B (fresh feed only) and C (fresh feed plus
  simulation samples), mean of 5 seeds, on fresh data (Experiments page computes the same means).
- Table 7.5: per round, F1 and FPR with CIs, McNemar C against B, promotion decisions.
- Simulation-holdout results reported separately (never pooled with fresh-feed results).
  [needs ethics approval, then three monthly rounds]

## 7.5 Visual-similarity check (D6) and other components

- D6 has no detection rate: none of the stored phishing snapshots has a favicon. Report it as a
  built and unit-tested component, with the 8-bit limit and its reason (closest two brands 9 bits
  apart), and the 6 brands without a readable icon.
- Extension and gateway: functional checks only (Phase 7 end-to-end test).
