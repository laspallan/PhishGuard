"""The development set as arrays, for one modality and one feature set.

This is the only training module that opens the frozen split, and it keeps **development rows
only**: the locked test set is used once, in Phase 8 (a test checks that no other training or
evaluation module reads the split). The feature matrix must have been built by the current
feature code (`feature_code_hash`), so a model never trains on stale features.

Feature sets (the ablations of the plan):
- url / all            F1–F95
- url / no_path        without every F1–F45 feature that reads the path, query or fragment
                       (decision D10c: legitimate Tranco URLs are mostly home pages)
- url / no_rdap        without F46–F52 and F55, which falls back to RDAP name servers
                       (registration data is missing more often for one class)
- url / no_tranco      without F57, F58 (legitimate URLs come from Tranco: leaks by construction)
- url / live           M2, the deployed full model (D11c): without RDAP F46-F52, Tranco F57-F58,
                       F55 (it falls back to RDAP name servers) and F65 (always missing)
- url / live_stage1    M1, the deployed no-contact model (D11b): F1-F45, F53, F54, F56 only,
                       everything a scan knows without contacting the target host
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
from phishguard.services.text_input import text_for
from phishguard_ml.data.records import SampleRecord
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
# Live scans have no RDAP, so every feature that reads it stays out of the deployed models.
LIVE_DROPPED = {*RDAP_FEATURES, *TRANCO_FEATURES, "num_name_servers", "suspicious_asn"}
STAGE1_DNS_FEATURES = ("num_a_records", "has_mx_record", "dns_min_ttl")  # F53, F54, F56


def feature_set(modality: Modality, name: str) -> list[str]:
    if modality is Modality.URL:
        base = list(FEATURE_NAMES[:95])
        drop = {
            "all": set(),
            "no_path": set(FEATURE_NAMES[:45]) - HOST_ONLY_FEATURES,
            "no_rdap": {*RDAP_FEATURES, "num_name_servers"},
            "no_tranco": set(TRANCO_FEATURES),
            "live": LIVE_DROPPED,
            "live_stage1": set(FEATURE_NAMES[45:95]) - set(STAGE1_DNS_FEATURES),
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


class LockedTestNotConfirmedError(RuntimeError):
    """The locked test set is opened once, in Phase 8, only after you confirm."""


def load_locked_test(
    modality: Modality, feature_set_name: str, text_input: str | None, *, confirmed: bool = False
) -> "DevText":
    """The locked test rows. Only `evaluation/final.py` may call this (a test checks that); it logs
    the access first. Features, plus the text for the text models when `text_input` is given."""
    if not confirmed:
        raise LockedTestNotConfirmedError("the locked test set needs an explicit confirmation")
    table = pq.read_table(features_path())
    if (table.schema.metadata or {}).get(b"feature_code_hash", b"").decode() != (
        current_feature_hash()
    ):
        raise StaleFeaturesError("features.parquet was built by other feature code")
    records, rows = load_split()
    locked = {row["sample_id"] for row in rows if row["set"] != "dev"}
    chosen = [r for r in records if str(r.sample_id) in locked and r.sample_type is modality]
    names = feature_set(modality, feature_set_name)
    position = {sid: i for i, sid in enumerate(table.column("sample_id").to_pylist())}
    index = [position[str(r.sample_id)] for r in chosen]
    columns = [np.asarray(table.column(n).to_numpy(), dtype=float)[index] for n in names]
    return DevText(
        sample_ids=[str(r.sample_id) for r in chosen],
        X=np.column_stack(columns) if columns else np.empty((len(chosen), 0)),
        y=np.array([r.label is Label.PHISHING for r in chosen], dtype=int),
        folds=np.full(len(chosen), -1, dtype=int),
        groups=[r.group_key for r in chosen],
        sources=[r.source.value for r in chosen],
        feature_names=names,
        texts=[text_for(modality.value, text_input, r.raw_content) for r in chosen]
        if text_input
        else [],
    )


@dataclass(frozen=True)
class DevText(DevData):
    """The same development rows, in the same order, with the text a text model reads."""

    texts: list[str]


def load_development_text(modality: Modality, text_input: str) -> DevText:
    """Development rows only, like `load_development`; needs no feature matrix."""
    records, rows = load_split()
    dev_fold = {row["sample_id"]: row["fold"] for row in rows if row["set"] == "dev"}
    chosen = [r for r in records if str(r.sample_id) in dev_fold and r.sample_type is modality]
    return DevText(
        sample_ids=[str(r.sample_id) for r in chosen],
        X=np.empty((len(chosen), 0)),
        y=np.array([r.label is Label.PHISHING for r in chosen], dtype=int),
        folds=np.array([dev_fold[str(r.sample_id)] for r in chosen], dtype=int),
        groups=[r.group_key for r in chosen],
        sources=[r.source.value for r in chosen],
        feature_names=[],
        texts=[text_for(modality.value, text_input, r.raw_content) for r in chosen],
    )


def development_records(modality: Modality) -> list[SampleRecord]:
    """The development records themselves (e.g. raw emails for the SpamAssassin baseline)."""
    records, rows = load_split()
    dev = {row["sample_id"] for row in rows if row["set"] == "dev"}
    return [r for r in records if str(r.sample_id) in dev and r.sample_type is modality]
