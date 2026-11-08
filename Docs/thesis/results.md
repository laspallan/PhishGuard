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

- Table 7.1: URL models, feature sets `all`, `no_path`, `no_rdap`, `no_tranco`, `live` (from
  `results.md`). [paste when the training queue has finished]
- Table 7.2: email models, `no_header`, `all`, `no_age`, with the SpamAssassin baseline row
  (baseline run complete 2026-11-08; paste from `results.md` once `no_age` has trained).
- Text models (LSTM, 1D-CNN, DistilBERT) against the tabular models on the same folds.
  [LSTM email and url_host are in; url_full and DistilBERT wait for a GPU]
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

- Table 7.4: soft vote without `ti_score`, with `ti_score`, and `ti_score` alone, same folds and
  parameters (from `rq2/results.md`). [after 8 days of lookups, about 2026-11-16]
- Also report from `rq2/results.json`: n, share of phishing flagged by VirusTotal on the day of
  collection, `ti_score` missing count, median hours from collection to lookup.
- Early observation to check against the full subset: in the first answers OTX had no pulses for
  any URL, so `ti_score` came from VirusTotal alone. If that holds, say so plainly.
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
