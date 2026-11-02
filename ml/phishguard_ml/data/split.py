"""Step 8: sample the balanced dataset, then make the split ONCE (seed 42, decision D4).

- Each modality is 50% phishing / 50% legitimate. Phishing samples are drawn per attack
  category in proportion to what is available (stratified sampling, proposal Section 3.4).
- 15% locked test set, 85% development set with 5 stratified group folds. Groups (registered
  domain / sender / Enron mailbox) never cross a boundary.
- The split is written to data/splits/ with SHA-256 hashes in manifest.json and is never
  overwritten. verify_split() fails if any file changed.
"""

import hashlib
import json
from collections import Counter, defaultdict
from datetime import UTC, datetime

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq
from sklearn.model_selection import StratifiedGroupKFold

from phishguard.models.enums import Label, Modality
from phishguard_ml import paths
from phishguard_ml.data.records import SampleRecord, Source, read_records, write_records

SEED = 42
TEST_FOLDS_OF_20 = 3  # 3/20 = 15% locked test set
DEV_FOLDS = 5
EXCLUDED_SOURCES = frozenset({Source.OWN_MAILBOX})  # evaluation-only check set


class InsufficientDataError(ValueError):
    pass


class SplitExistsError(FileExistsError):
    pass


class SplitChangedError(RuntimeError):
    pass


def _allocate(available: dict[str, int], wanted: int) -> dict[str, int]:
    """Proportional allocation with largest remainders, never more than available."""
    total = sum(available.values())
    if wanted > total:
        raise InsufficientDataError(f"need {wanted}, only {total} available")
    exact = {k: wanted * v / total for k, v in available.items()}
    counts = {k: int(x) for k, x in exact.items()}
    for key in sorted(exact, key=lambda k: exact[k] - counts[k], reverse=True)[
        : wanted - sum(counts.values())
    ]:
        counts[key] += 1
    return counts


def sample_dataset(
    records: list[SampleRecord], *, n_url: int, n_email: int, seed: int = SEED
) -> list[SampleRecord]:
    if n_url % 2 or n_email % 2:
        raise ValueError("n_url and n_email must be even (50/50 per modality)")
    rng = np.random.default_rng(seed)
    pools: dict[tuple, list[SampleRecord]] = defaultdict(list)
    for r in sorted(records, key=lambda r: str(r.sample_id)):  # order-independent
        if r.source in EXCLUDED_SOURCES:
            continue
        category = r.attack_category.value if r.attack_category else "none"
        pools[(r.sample_type, r.label, category)].append(r)

    chosen: list[SampleRecord] = []
    for modality, n in ((Modality.URL, n_url), (Modality.EMAIL, n_email)):
        for lab in (Label.PHISHING, Label.LEGITIMATE):
            strata = {k[2]: len(v) for k, v in pools.items() if k[:2] == (modality, lab)}
            if not strata:
                if n:
                    raise InsufficientDataError(f"no {modality.value} {lab.value} samples")
                continue
            try:
                allocation = _allocate(strata, n // 2)
            except InsufficientDataError as error:
                raise InsufficientDataError(f"{modality.value} {lab.value}: {error}") from None
            for category, k in allocation.items():
                pool = pools[(modality, lab, category)]
                picks = rng.choice(len(pool), size=k, replace=False)
                chosen.extend(pool[i] for i in sorted(picks))
    return chosen


def _stratum(r: SampleRecord) -> str:
    category = r.attack_category.value if r.attack_category else "none"
    return f"{r.sample_type.value}|{r.label.value}|{category}"


def make_split(dataset: list[SampleRecord], *, seed: int = SEED) -> list[dict]:
    """Rows of {sample_id, set ('test'|'dev'), fold (0-4, or None for test)}."""
    strata = np.array([_stratum(r) for r in dataset])
    groups = np.array([r.group_key for r in dataset])
    if any(g is None for g in groups):
        raise ValueError("every record needs a group_key before splitting")
    index = np.arange(len(dataset))

    outer = StratifiedGroupKFold(n_splits=20, shuffle=True, random_state=seed)
    folds = outer.split(index, strata, groups)
    test_index = np.concatenate([next(folds)[1] for _ in range(TEST_FOLDS_OF_20)])
    is_test = np.zeros(len(dataset), dtype=bool)
    is_test[test_index] = True
    dev_index = index[~is_test]

    fold = np.full(len(dataset), -1)
    inner = StratifiedGroupKFold(n_splits=DEV_FOLDS, shuffle=True, random_state=seed)
    for k, (_, val) in enumerate(inner.split(dev_index, strata[dev_index], groups[dev_index])):
        fold[dev_index[val]] = k

    return [
        {
            "sample_id": str(r.sample_id),
            "set": "test" if is_test[i] else "dev",
            "fold": None if is_test[i] else int(fold[i]),
        }
        for i, r in enumerate(dataset)
    ]


def _sha256(path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_split(dataset: list[SampleRecord], rows: list[dict], settings: dict) -> dict:
    folder = paths.splits_dir()
    manifest_path = folder / "manifest.json"
    if manifest_path.exists():
        raise SplitExistsError(
            f"{folder} already holds the frozen split; it is never overwritten. "
            "Move it away by hand only if you are deliberately starting the study again."
        )
    folder.mkdir(parents=True, exist_ok=True)
    write_records(dataset, folder / "dataset.parquet")
    table = pa.Table.from_pylist(
        rows,
        schema=pa.schema([("sample_id", pa.string()), ("set", pa.string()), ("fold", pa.int8())]),
    )
    pq.write_table(table, folder / "split.parquet")

    by_set = Counter((row["set"], row["fold"]) for row in rows)
    manifest = {
        "created_at": datetime.now(UTC).isoformat(),
        "seed": SEED,
        "settings": settings,
        "samples": len(rows),
        "test": sum(v for (s, _), v in by_set.items() if s == "test"),
        "dev_folds": {str(f): v for (s, f), v in sorted(by_set.items()) if s == "dev"},
        "sha256": {
            "dataset.parquet": _sha256(folder / "dataset.parquet"),
            "split.parquet": _sha256(folder / "split.parquet"),
        },
    }
    manifest_path.write_text(json.dumps(manifest, indent=2))
    return manifest


def verify_split() -> dict:
    folder = paths.splits_dir()
    manifest = json.loads((folder / "manifest.json").read_text())
    for name, expected in manifest["sha256"].items():
        if _sha256(folder / name) != expected:
            raise SplitChangedError(f"{name} changed since the split was made")
    return manifest


def load_split() -> tuple[list[SampleRecord], list[dict]]:
    verify_split()
    folder = paths.splits_dir()
    return read_records(folder / "dataset.parquet"), pq.read_table(
        folder / "split.parquet"
    ).to_pylist()
