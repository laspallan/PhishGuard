"""The development set as arrays, for one modality and one feature set.

This is the only training module that opens the frozen split, and it keeps **development rows
only**: the locked test set is used once, in Phase 8 (a test checks that no other training or
evaluation module reads the split). The feature matrix must have been built by the current
feature code (`feature_code_hash`), so a model never trains on stale features.

Feature sets (the ablations of the plan):
- url / all            F1–F95
- url / no_path        without every F1–F45 feature that reads the path, query or fragment
                       (decision D10c: legitimate Tranco URLs are mostly home pages)
- url / no_rdap        without F46–F52 (registration data is missing more often for one class)
- url / no_tranco      without F57, F58 (legitimate URLs come from Tranco: leaks by construction)
- email / all          F96–F140
- email / no_header    F116–F140 only (headline email result: Enron lacks delivery headers)
- email / no_age       without the age-sensitive F96–F101, F109, F110
"""

from dataclasses import dataclass

import numpy as np
import pyarrow.parquet as pq

from phishguard.models.enums import Label, Modality
from phishguard.services.features.extractor import AGE_SENSITIVE, FEATURE_NAMES
from phishguard.services.features.extractor import feature_code_hash as current_feature_hash
from phishguard_ml.data.split import load_split
from phishguard_ml.features.matrix import features_path

# F1–F45 features that use only the scheme / host / port (kept by url/no_path).
HOST_ONLY_FEATURES: frozenset[str] = frozenset(
    {
        "hostname_length", "has_ip_address", "uses_https", "has_port", "num_subdomains",
        "subdomain_length", "tld_length", "suspicious_tld", "is_shortened", "has_punycode",
        "has_mixed_script", "hostname_entropy", "brand_in_subdomain", "hostname_digit_ratio",
        "hostname_vowel_ratio",
    }
)  # fmt: skip
RDAP_FEATURES = FEATURE_NAMES[45:52]  # F46–F52
TRANCO_FEATURES = ("tranco_rank", "in_tranco_top_1m")  # F57, F58


def feature_set(modality: Modality, name: str) -> list[str]:
    if modality is Modality.URL:
        base = list(FEATURE_NAMES[:95])
        drop = {
            "all": set(),
            "no_path": set(FEATURE_NAMES[:45]) - HOST_ONLY_FEATURES,
            "no_rdap": set(RDAP_FEATURES),
            "no_tranco": set(TRANCO_FEATURES),
        }
    else:
        base = list(FEATURE_NAMES[95:])
        drop = {
            "all": set(),
            "no_header": set(FEATURE_NAMES[95:115]),
            "no_age": set(AGE_SENSITIVE),
        }
    if name not in drop:
        raise ValueError(f"unknown feature set {name!r} for {modality.value}: {sorted(drop)}")
    return [f for f in base if f not in drop[name]]


class StaleFeaturesError(RuntimeError):
    """The feature matrix was built by different feature code; rebuild it first."""


@dataclass(frozen=True)
class DevData:
    sample_ids: list[str]
    X: np.ndarray  # n x k, NaN = missing
    y: np.ndarray  # 1 = phishing
    folds: np.ndarray  # 0..4
    groups: list[str]
    sources: list[str]
    feature_names: list[str]


def load_development(modality: Modality, feature_set_name: str = "all") -> DevData:
    table = pq.read_table(features_path())
    built_with = (table.schema.metadata or {}).get(b"feature_code_hash", b"").decode()
    if built_with != current_feature_hash():
        raise StaleFeaturesError(
            "features.parquet was built by other feature code; run `python -m phishguard_ml "
            "features` again"
        )
    records, rows = load_split()
    dev_fold = {row["sample_id"]: row["fold"] for row in rows if row["set"] == "dev"}
    chosen = [r for r in records if str(r.sample_id) in dev_fold and r.sample_type is modality]
    names = feature_set(modality, feature_set_name)
    position = {sid: i for i, sid in enumerate(table.column("sample_id").to_pylist())}
    index = [position[str(r.sample_id)] for r in chosen]
    columns = [np.asarray(table.column(n).to_numpy(), dtype=float)[index] for n in names]
    return DevData(
        sample_ids=[str(r.sample_id) for r in chosen],
        X=np.column_stack(columns) if columns else np.empty((len(chosen), 0)),
        y=np.array([r.label is Label.PHISHING for r in chosen], dtype=int),
        folds=np.array([dev_fold[str(r.sample_id)] for r in chosen], dtype=int),
        groups=[r.group_key for r in chosen],
        sources=[r.source.value for r in chosen],
        feature_names=names,
    )
