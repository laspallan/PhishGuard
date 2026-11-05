"""Step 9: daily collection of fresh data for RQ3 (runs as the `collector` compose service).

Every day: download PhishTank and OpenPhish; once a month: Tranco. Only samples never seen
before (not in records.parquet, the frozen split, or an earlier batch) are kept. New phishing
URLs are snapshotted immediately, because phishing pages go offline within hours, then
labelled. Each day's batch is written to data/processed/monthly/<YYYY-MM>/<YYYY-MM-DD>.parquet.

This never reads or writes data/splits/ except to learn which samples to exclude.
"""

import json
import logging
import time
from datetime import UTC, date, datetime

import httpx

from phishguard_ml import paths
from phishguard_ml.data import clean, label, parse
from phishguard_ml.data.download import download_source, latest_download
from phishguard_ml.data.records import SampleRecord, Source, read_records, write_records
from phishguard_ml.data.snapshot import load_snapshot, snapshot_records

log = logging.getLogger(__name__)
DAILY_SOURCES = (Source.PHISHTANK, Source.OPENPHISH)


def monthly_dir():
    return paths.processed_dir() / "monthly"


def seen_ids() -> set:
    files = [paths.processed_dir() / "records.parquet", paths.splits_dir() / "dataset.parquet"]
    files += sorted(monthly_dir().glob("*/*.parquet"))
    seen = set()
    for path in files:
        if path.exists():
            seen.update(r.sample_id for r in read_records(path))
    return seen


def _tranco_due(day: date) -> bool:
    latest = latest_download(Source.TRANCO)
    return latest is None or latest.name[:7] != day.isoformat()[:7]


def collect_once(
    client: httpx.Client,
    *,
    day: date | None = None,
    take_snapshots: bool = True,
    tranco_limit: int = 100_000,
) -> dict:
    day = day or datetime.now(UTC).date()
    sources = list(DAILY_SOURCES) + ([Source.TRANCO] if _tranco_due(day) else [])
    rejects = parse.RejectCounter()
    found: list[SampleRecord] = []
    targets: dict[str, str] = {}
    for source in sources:
        folder = download_source(source, client=client, day=day)
        if source is Source.PHISHTANK:
            # same D1 brand rule as `label` on the training data, so categories are comparable
            targets = parse.phishtank_targets([folder])
        if source is Source.TRANCO:
            found.extend(parse.parse_tranco(folder, rejects, limit=tranco_limit))
        else:
            found.extend(parse.PARSERS[source](folder, rejects))

    seen = seen_ids()
    fresh, _ = clean.deduplicate(r for r in found if r.sample_id not in seen)
    if take_snapshots:
        fresh = snapshot_records(fresh)
    labelled = []
    for record in fresh:
        page = load_snapshot(record, "page.html")
        html = page.decode("utf-8", errors="replace") if page else None
        labelled.append(label.label_record(record, html, targets))

    out = monthly_dir() / day.isoformat()[:7] / f"{day.isoformat()}.parquet"
    if labelled:
        write_records(labelled, out)
    report = {
        "day": day.isoformat(),
        "sources": [s.value for s in sources],
        "found": len(found),
        "new": len(labelled),
        "rejected": dict(rejects),
        "file": str(out) if labelled else None,
    }
    log.info("collected %s", json.dumps(report))
    return report


def run_forever(interval_hours: float = 24.0) -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    with httpx.Client(timeout=httpx.Timeout(30.0, read=300.0), follow_redirects=True) as client:
        while True:
            try:
                collect_once(client)
            except Exception:  # keep collecting tomorrow even if one day fails
                log.exception("collection failed")
            time.sleep(interval_hours * 3600)
