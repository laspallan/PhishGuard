"""RQ2 (Phase 4): does live threat intelligence change the false-positive rate? (decisions.md,
2026-11-08, agreed).

Recording (`ti-record`, once a day):
- phishing: URLs from the collector's batch of today or yesterday, outside the frozen split, so each
  is looked up within about a day of collection (D7: TI only at collection time);
- legitimate: development legitimate URLs, never the locked test set, in a fixed random order;
- each day at most PER_CLASS_PER_DAY of each and never more legitimate than phishing, so the subset
  stays balanced. Every raw answer goes to data/ti_responses/ with the sample id and label.

Experiment (`rq2`): the subset only, the `live` feature set with and without `ti_score`. The same
rows, 5 group folds and the hyper-parameters already tuned for url/live in both arms, so the only
difference is `ti_score`. Calibrated soft vote of the three tabular models, `ti_score` alone as a
rule, CIs, McNemar between the arms. Writes data/models/rq2/results.json and results.md.
"""

import asyncio
import hashlib
import json
from collections import Counter
from collections.abc import Iterable
from datetime import UTC, date, datetime, timedelta

import numpy as np
from sklearn.model_selection import StratifiedGroupKFold

from phishguard.models.enums import Label, Modality
from phishguard.services.features.extractor import FEATURE_NAMES
from phishguard.services.intel.recorder import TIRecorder
from phishguard.services.intel.scoring import compute_ti_score, vt_component
from phishguard_ml import paths
from phishguard_ml.data.records import SampleRecord, read_records
from phishguard_ml.evaluation import report
from phishguard_ml.features import matrix
from phishguard_ml.training import calibration, devdata, ensembles, tabular

PER_CLASS_PER_DAY = 250  # 2 x 250 = VirusTotal's 500 public lookups a day
FEATURE_SET = "live"
SEED = 42
MIN_PER_CLASS = 50


def responses_dir():
    return paths.data_dir() / "ti_responses"


def results_dir():
    return paths.models_dir() / "rq2"


def recordings() -> list[dict]:
    """Every RQ2 line (lines without a sample id come from live lookups and are skipped)."""
    lines = []
    for path in sorted(responses_dir().glob("ti_*.jsonl")):
        for text in path.read_text(encoding="utf-8").splitlines():
            line = json.loads(text)
            if line.get("sample_id"):
                lines.append(line)
    return lines


def _order(record: SampleRecord) -> str:
    """A fixed random order that does not depend on the order of the files."""
    return hashlib.sha256(f"rq2:{record.sample_id}".encode()).hexdigest()


def fresh_phishing(day: date) -> list[SampleRecord]:
    """Phishing URLs the collector found today or yesterday (UTC)."""
    found = []
    for d in (day, day - timedelta(days=1)):
        path = paths.processed_dir() / "monthly" / d.isoformat()[:7] / f"{d.isoformat()}.parquet"
        if path.exists():
            found += [
                r
                for r in read_records(path)
                if r.sample_type is Modality.URL and r.label is Label.PHISHING
            ]
    return found


def choose(
    day: date, phishing: list[SampleRecord], legitimate: list[SampleRecord], lines: list[dict],
    per_class: int = PER_CLASS_PER_DAY,
) -> list[SampleRecord]:  # fmt: skip
    """Today's lookups, phishing and legitimate alternating, balanced, never repeated."""
    done = {line["sample_id"] for line in lines}
    today = Counter(line["label"] for line in lines if line["queried_at"][:10] == day.isoformat())
    room = per_class - max(today["phishing"], today["legitimate"])
    new_phishing = sorted((r for r in phishing if str(r.sample_id) not in done), key=_order)
    new_legitimate = sorted((r for r in legitimate if str(r.sample_id) not in done), key=_order)
    n = max(0, min(room, len(new_phishing), len(new_legitimate)))
    return [r for pair in zip(new_phishing[:n], new_legitimate[:n], strict=True) for r in pair]


async def record(records: Iterable[SampleRecord], vt, otx, recorder: TIRecorder) -> int:
    count = 0
    for r in records:
        vt_answer, otx_answer = await asyncio.gather(
            vt.get_url_report(r.raw_content), otx.get_url_general(r.raw_content)
        )
        extra = {
            "sample_id": str(r.sample_id),
            "label": r.label.value,
            "source": r.source.value,
            "collected_at": r.collected_at.isoformat(),
        }
        recorder.record(r.raw_content, {"vt": vt_answer, "otx": otx_answer}, extra)
        count += 1
    return count


def record_day(vt, otx, *, day: date | None = None, per_class: int = PER_CLASS_PER_DAY) -> dict:
    if not (vt.api_key and otx.api_key):
        raise RuntimeError(
            "set PHISHGUARD_VIRUSTOTAL_API_KEY and PHISHGUARD_ALIENVAULT_OTX_API_KEY in .env first"
        )
    day = day or datetime.now(UTC).date()
    legitimate = [
        r for r in devdata.development_records(Modality.URL) if r.label is Label.LEGITIMATE
    ]
    chosen = choose(day, fresh_phishing(day), legitimate, recordings(), per_class)
    done = asyncio.run(record(chosen, vt, otx, TIRecorder(responses_dir())))
    return {"day": day.isoformat(), "looked_up": done, "subset": Counter(
        line["label"] for line in {x["sample_id"]: x for x in recordings()}.values()
    )}  # fmt: skip


def first_answers(lines: list[dict]) -> dict[str, dict]:
    """The first lookup of each sample: the one closest to its collection."""
    first: dict[str, dict] = {}
    for line in sorted(lines, key=lambda x: x["queried_at"]):
        first.setdefault(line["sample_id"], line)
    return first


def _hours(line: dict) -> float:
    asked = datetime.fromisoformat(line["queried_at"])
    return (asked - datetime.fromisoformat(line["collected_at"])).total_seconds() / 3600


def subset(lines: list[dict]) -> devdata.DevData:
    """Features of the `live` set for every recorded sample, plus the folds."""
    answers = first_answers(lines)
    names = devdata.feature_set(Modality.URL, FEATURE_SET)
    dev = devdata.load_development(Modality.URL, FEATURE_SET)
    dev_rows = {sid: i for i, sid in enumerate(dev.sample_ids)}
    fresh = {}
    for path in sorted((paths.processed_dir() / "monthly").glob("*/*.parquet")):
        fresh.update({str(r.sample_id): r for r in read_records(path)})
    columns = [FEATURE_NAMES.index(n) for n in names]
    matrix._init_worker({})  # no Tranco ranks: the live set has no Tranco features
    ids, X, y, groups, sources = [], [], [], [], []
    for sid, line in answers.items():
        if line["label"] == "legitimate":
            if sid not in dev_rows:
                raise ValueError(f"{sid} is not a development URL")
            i = dev_rows[sid]
            X.append(dev.X[i])
            groups.append(dev.groups[i])
        else:
            values, _ = matrix.features_of(fresh[sid])
            X.append(np.asarray([values[c] for c in columns], dtype=float))
            groups.append(fresh[sid].group_key)
        ids.append(sid)
        y.append(int(line["label"] == "phishing"))
        sources.append(line["source"])
    y = np.asarray(y)
    if min(int(y.sum()), int((1 - y).sum())) < MIN_PER_CLASS:
        raise ValueError(f"fewer than {MIN_PER_CLASS} recorded samples in one class")
    folds = np.empty(len(y), dtype=int)
    splitter = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=SEED)
    for fold, (_, held_out) in enumerate(splitter.split(np.zeros(len(y)), y, groups)):
        folds[held_out] = fold
    return devdata.DevData(ids, np.vstack(X), y, folds, groups, sources, names)


def ti_scores(lines: list[dict], sample_ids: list[str]) -> np.ndarray:
    answers = first_answers(lines)
    scores = [
        compute_ti_score(answers[s]["response"]["vt"], answers[s]["response"]["otx"])
        for s in sample_ids
    ]
    return np.array([np.nan if s is None else s for s in scores], dtype=float)


def _soft_vote(data: devdata.DevData, params: dict[str, dict]) -> np.ndarray:
    calibrated = [
        calibration.cross_fitted(tabular.out_of_fold(m, params[m], data), data.y, data.folds)
        for m in tabular.MODELS
    ]
    return ensembles.soft_vote(calibrated)


def tuned_params() -> dict[str, dict]:
    params = {}
    for m in tabular.MODELS:
        path = tabular.run_dir("url", FEATURE_SET, m) / "run.json"
        if not path.exists():
            raise FileNotFoundError(f"train url/{FEATURE_SET} first: {path} is missing")
        params[m] = json.loads(path.read_text())["params"]
    return params


def run(n_boot: int = 1000) -> dict:
    lines = recordings()
    without = subset(lines)
    ti = ti_scores(lines, without.sample_ids)
    with_ti = devdata.DevData(
        without.sample_ids, np.column_stack([without.X, ti]), without.y, without.folds,
        without.groups, without.sources, [*without.feature_names, "ti_score"],
    )  # fmt: skip
    params = tuned_params()
    p_without, p_with = _soft_vote(without, params), _soft_vote(with_ti, params)
    rule = np.nan_to_num(ti, nan=0.0) / 100  # a missing ti_score counts as "nothing known"
    y, groups = without.y, np.asarray(without.groups, dtype=object)
    sources = np.asarray(without.sources, dtype=object)
    reference = (p_without >= report.THRESHOLD).astype(int)
    rows = [
        report._row("soft_vote_without_ti", y, p_without, groups, sources, None, n_boot),
        report._row("soft_vote_with_ti", y, p_with, groups, sources, reference, n_boot),
        report._row("ti_score_alone", y, rule, groups, sources, reference, n_boot),
    ]
    answers = first_answers(lines)
    phishing = [answers[s] for s, label in zip(without.sample_ids, y, strict=True) if label]
    flagged = [vt_component(a["response"]["vt"]) for a in phishing]
    result = {
        "n": int(len(y)),
        "n_phishing": int(y.sum()),
        "ti_score_missing": int(np.isnan(ti).sum()),
        "phishing_flagged_by_virustotal_on_the_day": float(
            np.mean([f is not None and f > 0 for f in flagged])
        ),
        "median_hours_from_collection_to_lookup_phishing": float(
            np.median([_hours(a) for a in phishing])
        ),
        "rows": rows,
    }
    results_dir().mkdir(parents=True, exist_ok=True)
    (results_dir() / "results.json").write_text(json.dumps(result, indent=1))
    text = report.markdown(
        {f"url/{FEATURE_SET} on the TI subset (n={len(y)})": rows},
        title="RQ2: threat intelligence (5-fold CV, out-of-fold, threshold 0.5)",
        reference="soft vote without ti_score",
    )
    (results_dir() / "results.md").write_text(text, encoding="utf-8")
    return result
