"""Steps 3, 6 and 7 wired together: build the record set, label it, and count it.

build  -> data/processed/records.parquet      (all cleaned, de-duplicated records)
          data/processed/own_mailbox.parquet  (evaluation-only check set, kept apart)
          data/processed/build_report.json
label  -> data/processed/labelled.parquet
count  -> data/processed/counts.json
"""

import json
from collections import Counter
from dataclasses import asdict
from datetime import UTC, datetime

from phishguard_ml import paths
from phishguard_ml.data import clean, label, parse
from phishguard_ml.data.download import latest_download
from phishguard_ml.data.records import SampleRecord, Source, read_records, write_records
from phishguard_ml.data.snapshot import load_snapshot

TRAINING_SOURCES = (
    Source.PHISHTANK,
    Source.OPENPHISH,
    Source.TRANCO,
    Source.NAZARIO,
    Source.SPAMASSASSIN,
    Source.ENRON,
)


def records_path():
    return paths.processed_dir() / "records.parquet"


def labelled_path():
    return paths.processed_dir() / "labelled.parquet"


def build(*, tranco_limit: int = 100_000, enron_fraction: float = 0.1) -> dict:
    rejects = parse.RejectCounter()
    collected: list[SampleRecord] = []
    per_source: dict[str, int] = {}
    used_downloads: dict[str, str | None] = {}
    for source in TRAINING_SOURCES:
        folder = latest_download(source)
        used_downloads[source.value] = folder.name if folder else None
        if folder is None:
            per_source[source.value] = 0
            continue
        parser = parse.PARSERS[source]
        if source is Source.TRANCO:
            found = list(parser(folder, rejects, limit=tranco_limit))
        elif source is Source.ENRON:
            found = list(parser(folder, rejects, fraction=enron_fraction))
        else:
            found = list(parser(folder, rejects))
        per_source[source.value] = len(found)
        collected.extend(found)

    records, dedup = clean.deduplicate(collected)
    write_records(records, records_path())

    own_folder = paths.raw_dir() / Source.OWN_MAILBOX.value
    own = list(parse.parse_own_mailbox(own_folder, rejects)) if own_folder.exists() else []
    if own:
        write_records(own, paths.processed_dir() / "own_mailbox.parquet")

    report = {
        "built_at": datetime.now(UTC).isoformat(),
        "downloads_used": used_downloads,
        "settings": {"tranco_limit": tranco_limit, "enron_fraction": enron_fraction},
        "parsed_per_source": per_source,
        "rejected": dict(rejects),
        "dedup": {k: v for k, v in asdict(dedup).items() if k != "conflict_ids"},
        "records": len(records),
        "own_mailbox_records": len(own),
    }
    (paths.processed_dir() / "build_report.json").write_text(json.dumps(report, indent=2))
    return report


def label_all(urlhaus: frozenset[str] = frozenset()) -> Counter:
    records = read_records(records_path())
    labelled = []
    for record in records:
        page = load_snapshot(record, "page.html")
        html = page.decode("utf-8", errors="replace") if page else None
        labelled.append(label.label_record(record, html, urlhaus))
    write_records(labelled, labelled_path())
    return label.category_counts(labelled)


def count(records: list[SampleRecord] | None = None) -> dict:
    if records is None:
        path = labelled_path() if labelled_path().exists() else records_path()
        records = read_records(path)
    by_source = Counter(r.source.value for r in records)
    by_type_label = Counter(f"{r.sample_type.value}:{r.label.value}" for r in records)
    by_category = label.category_counts(records)
    years = Counter(
        f"{r.source.value}:{r.source_date.year}" for r in records if r.source_date is not None
    )
    urls = [r for r in records if r.sample_type.value == "url"]
    snapshot_share = sum(r.snapshot_ref is not None for r in urls) / len(urls) if urls else 0.0
    summary = {
        "counted_at": datetime.now(UTC).isoformat(),
        "total": len(records),
        "by_source": dict(sorted(by_source.items())),
        "by_type_label": dict(sorted(by_type_label.items())),
        "by_category": dict(sorted(by_category.items())),
        "source_date_years": dict(sorted(years.items())),
        "url_snapshot_coverage": round(snapshot_share, 4),
        "max_balanced": {
            kind: 2 * min(by_type_label[f"{kind}:phishing"], by_type_label[f"{kind}:legitimate"])
            for kind in ("url", "email")
        },
    }
    paths.processed_dir().mkdir(parents=True, exist_ok=True)
    (paths.processed_dir() / "counts.json").write_text(json.dumps(summary, indent=2))
    return summary
