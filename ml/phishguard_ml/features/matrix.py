"""Feature matrix: F1–F140 for every record -> data/processed/features.parquet.

Calls the same extractor as the live API (phishguard.services.features.extractor). Everything a
URL needs was stored at collection time: snapshot files (meta.json, page.html, dns.json,
tls.json) and data/rdap/<registered domain>.json; nothing is fetched here.

Pages that exist but cannot be read (e.g. blocked by antivirus) are counted in the report and
treated as "no HTML", so a loss of pages is visible, never silent.
"""

import csv
import io
import json
import math
import zipfile
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

from phishguard.models.enums import Modality
from phishguard.services.evidence import build_url_evidence, rdap_domain
from phishguard.services.features import extractor
from phishguard.services.features.extractor import FEATURE_NAMES, UrlEvidence
from phishguard_ml import paths
from phishguard_ml.data.download import latest_download
from phishguard_ml.data.records import SampleRecord, Source

_ranks: dict[str, int] = {}


def features_path() -> Path:
    return paths.processed_dir() / "features.parquet"


def report_path() -> Path:
    return paths.processed_dir() / "features_report.json"


def load_tranco_ranks(folder: Path | None = None) -> dict[str, int]:
    """Registered domain -> rank from the downloaded Tranco list (all 1M entries)."""
    folder = folder or latest_download(Source.TRANCO)
    if folder is None:
        return {}
    ranks: dict[str, int] = {}
    with zipfile.ZipFile(folder / "top-1m.csv.zip") as archive:
        with archive.open(archive.namelist()[0]) as raw:
            for row in csv.reader(io.TextIOWrapper(raw, encoding="utf-8")):
                if len(row) == 2 and row[0].isdigit():
                    ranks.setdefault(row[1].strip().lower(), int(row[0]))
    return ranks


def _json(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


def url_evidence(record: SampleRecord) -> tuple[UrlEvidence, str]:
    """Evidence for one URL record, and how its page was found ("ok", "none", "unreadable").

    Reads the stored snapshot files; the backend's build_url_evidence (shared with the live
    API) turns them into UrlEvidence."""
    folder = paths.data_dir() / record.snapshot_ref if record.snapshot_ref else None
    page, page_state = None, "none"
    if folder and (folder / "page.html").exists():
        try:
            page = (folder / "page.html").read_bytes()
            page_state = "ok"
        except OSError:
            page_state = "unreadable"
    domain = rdap_domain(record.raw_content)
    evidence = build_url_evidence(
        record.raw_content,
        record.collected_at,
        meta=_json(folder / "meta.json") if folder else None,
        page=page,
        dns=_json(folder / "dns.json") if folder else None,
        tls=_json(folder / "tls.json") if folder else None,
        rdap=_json(paths.data_dir() / "rdap" / f"{domain}.json") if domain else None,
    )
    return evidence, page_state


def _init_worker(ranks: dict[str, int]) -> None:
    global _ranks
    _ranks = ranks


def features_of(record: SampleRecord) -> tuple[list[float], str]:
    if record.sample_type is Modality.URL:
        evidence, page_state = url_evidence(record)
        return extractor.url_features(evidence, _ranks), page_state
    return extractor.email_features(record.raw_content, _ranks), "email"


def build(
    records: list[SampleRecord], ranks: dict[str, int] | None = None, *, workers: int = 4
) -> dict:
    """Write the matrix and a report (row counts, page states, missing rate per feature)."""
    ranks = load_tranco_ranks() if ranks is None else ranks
    if workers <= 1:
        _init_worker(ranks)
        results = [features_of(r) for r in records]
    else:
        with ProcessPoolExecutor(workers, initializer=_init_worker, initargs=(ranks,)) as pool:
            results = list(pool.map(features_of, records, chunksize=200))

    columns = {"sample_id": [str(r.sample_id) for r in records]}
    columns |= {name: [values[i] for values, _ in results] for i, name in enumerate(FEATURE_NAMES)}
    code_hash = extractor.feature_code_hash()
    table = pa.table(columns).replace_schema_metadata({"feature_code_hash": code_hash})
    features_path().parent.mkdir(parents=True, exist_ok=True)
    pq.write_table(table, features_path())

    by_type = Counter(r.sample_type.value for r in records)
    missing = {}
    for modality, block in (("url", range(0, 95)), ("email", range(95, 140))):
        rows = [
            v for (v, _), r in zip(results, records, strict=True) if r.sample_type.value == modality
        ]
        for i in block:
            missing[FEATURE_NAMES[i]] = (
                round(sum(math.isnan(v[i]) for v in rows) / len(rows), 4) if rows else None
            )
    report = {
        "built_at": datetime.now(UTC).isoformat(),
        "feature_code_hash": code_hash,
        "rows": dict(by_type),
        "pages": dict(Counter(state for _, state in results if state != "email")),
        "missing_rate_in_own_modality": missing,
    }
    report_path().write_text(json.dumps(report, indent=1))
    return report
