# 8 Conclusion (draft)

The answers below are placeholders until the final results exist; each must be written from the
tables in Chapter 7, including answers that go against PhishGuard. The limitations are already known
and are listed now so they are not forgotten.

## 8.1 Answers to the research questions

**RQ1 (ensemble against a signature baseline).** [result: final F1, recall and FPR with 95% CIs for
URLs and for emails, from `final_results.md`; the SpamAssassin baseline on the same emails; McNemar.]
State separately: email results without the time-dependent features (F96–F101, F109, F110), the FPR
per legitimate source, and the FPR on recent own-mailbox emails. URLs have no signature baseline, for
the reason in Section 1.3.

**RQ2 (threat intelligence and false positives).** [result: FPR with and without `ti_score` on the TI
subset, CIs, McNemar; `ti_score` alone; share of phishing already flagged on the day.] If OTX keeps
adding nothing, as in the first answers, say that the effect measured is VirusTotal's. Interpret any
gain together with the circularity threat (Section 6.2).

**RQ3 (simulation data over time).** [result: F1 and FPR per round for A, B and C, mean of 5 seeds,
the C − B difference with CIs, on fresh data and on the simulation-holdout set.] The main answer is C
against B. If simulations could not run (no ethics approval in time), say so and report the harness
as built and tested on replayed data only.

## 8.2 Limitations

**Data**
- The legitimate emails are much older than the phishing emails (Enron 2001–2002, SpamAssassin
  2002–2005). Time clues were removed and results are also given without the time features, but the
  age gap may still leave other traces a model can learn.
- In development, the SpamAssassin legitimate emails had a far higher false-positive rate than Enron
  (about 6% against 0%) [update from the final results]: the detector is sensitive to the kind of
  legitimate email it is shown.
- Legitimate URLs come from popularity lists, and leaving out the popularity features cost about one
  accuracy point in development: part of the URL result rests on popularity, which a new legitimate
  site would not have.
- No raw dataset is redistributed, so others must rebuild it with the published scripts; feeds change
  over time, so a rebuild will not be identical.

**RQ2**
- The TI subset is small (planned 2,000 URLs per class [real size]) because of the free API limits.
- Phishing URLs come from feeds that also reach TI services, partly through engines other than the
  two that were removed; `ti_score` may partly repeat the label.

**RQ3**
- Few participants from one institution, over [number] rounds; simulation samples come from a handful
  of templates, so C learns from little variety.
- Simulations depend on ethics approval; their timing limited the number of rounds.

**System**
- The browser extension checks a page after it starts loading, so a blocked page can appear briefly on
  a first visit (decisions.md, Phase 7).
- The visual-similarity check (D6) has no measured detection rate: no stored phishing snapshot had a
  favicon. It covers 29 of 35 brands.
- The LSTM for full URLs and DistilBERT needed a GPU that was only partly available
  [update: which runs completed].
- Everything was deployed and measured on a single machine; latency figures do not describe a
  production deployment.

## 8.3 Further work

- A recent, licensed corpus of legitimate emails, to remove the age gap rather than work around it.
- Checking pages before they are shown in the browser, and measuring D6 on phishing pages with
  favicons.
- A larger, longer simulation study across several organisations, with more varied templates.
- Paid or research access to TI services, to run RQ2 on the full dataset rather than a subset.
- [Add any direction the results suggest.]

## 8.4 Closing summary

[Two or three sentences, written last: what PhishGuard showed, and how far it can be trusted.]
