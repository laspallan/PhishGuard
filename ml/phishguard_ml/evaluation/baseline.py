"""Signature baseline for emails (decision D2): SpamAssassin rule scores, Bayes off.

export:  development emails -> data/baseline/dev_emails.mbox (each gets an X-PhishGuard-Id
         header so results can be matched back; SpamAssassin does not keep the input order)
score:   the `spamassassin` compose service (no network) -> data/baseline/scored.mbox
import:  X-Spam-Status score / required per email -> data/models/baseline/email_spamassassin.parquet

Raw emails are scored (not the time-normalised view): the baseline is a deployed-style rule
filter. URLs have no baseline in RQ1: every phishing URL was taken from the blocklists
themselves on its collection day, so a lookup would find all of them by construction
(decided 2026-11-03); the URL lookup baseline is used in the RQ3 rounds.
"""

import mailbox
import re
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

from phishguard_ml import paths
from phishguard_ml.data.records import SampleRecord

ID_HEADER = "X-PhishGuard-Id"
_FROM_LINE = b"From phishguard@localhost Thu Jan  1 00:00:00 1970\n"
_ESCAPE = re.compile(rb"^(>*From )", re.MULTILINE)
_STATUS = re.compile(r"score=(-?[\d.]+)\s+required=(-?[\d.]+)")


def work_dir() -> Path:
    return paths.data_dir() / "baseline"


def result_path() -> Path:
    return paths.models_dir() / "baseline" / "email_spamassassin.parquet"


def export(records: list[SampleRecord]) -> Path:
    """Write the emails as one mbox (mboxrd escaping of body lines starting with "From ")."""
    work_dir().mkdir(parents=True, exist_ok=True)
    target = work_dir() / "dev_emails.mbox"
    with target.open("wb") as out:
        for record in records:
            raw = record.raw_content.replace("\r\n", "\n").encode("utf-8", "surrogateescape")
            out.write(_FROM_LINE)
            out.write(f"{ID_HEADER}: {record.sample_id}\n".encode())
            out.write(_ESCAPE.sub(rb">\1", raw).rstrip(b"\n") + b"\n\n")
    return target


def parse_scored(path: Path) -> dict[str, tuple[float, float]]:
    """sample_id -> (score, required) from SpamAssassin's output mbox."""
    found = {}
    for message in mailbox.mbox(path, create=False):
        sample_id = (message.get(ID_HEADER) or "").strip()
        status = " ".join(str(message.get("X-Spam-Status") or "").split())
        match = _STATUS.search(status)
        if sample_id and match:
            found[sample_id] = (float(match.group(1)), float(match.group(2)))
    return found


def import_scores(records: list[SampleRecord]) -> dict:
    scores = parse_scored(work_dir() / "scored.mbox")
    missing = [str(r.sample_id) for r in records if str(r.sample_id) not in scores]
    if missing:
        raise ValueError(f"{len(missing)} exported emails have no SpamAssassin result")
    ids = [str(r.sample_id) for r in records]
    table = pa.table(
        {
            "sample_id": ids,
            "score": [scores[i][0] for i in ids],
            "required": [scores[i][1] for i in ids],
            "detected": [scores[i][0] >= scores[i][1] for i in ids],
        }
    )
    version_file = work_dir() / "version.txt"
    version = version_file.read_text().strip() if version_file.exists() else ""
    table = table.replace_schema_metadata({"spamassassin_version": version})
    result_path().parent.mkdir(parents=True, exist_ok=True)
    pq.write_table(table, result_path())
    return {"emails": len(ids), "detected": int(sum(table.column("detected").to_pylist()))}


def load() -> dict[str, bool] | None:
    """sample_id -> detected, or None if the baseline has not been run."""
    if not result_path().exists():
        return None
    table = pq.read_table(result_path()).to_pydict()
    return dict(zip(table["sample_id"], table["detected"], strict=True))
