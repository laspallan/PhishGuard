"""Step 3: turn each source's raw download into SampleRecords.

Every parser reads one raw/<source>/<day>/ folder and yields records. Entries that cannot be
used are counted in a RejectCounter instead of being silently dropped.
"""

import csv
import hashlib
import io
import mailbox
import tarfile
import zipfile
from collections import Counter
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path

from phishguard_ml.data import clean
from phishguard_ml.data.download import load_manifest
from phishguard_ml.data.records import SampleRecord, Source

# Enron folders that are not received mail (sent by the owner) or are copies of other folders.
ENRON_SKIP_FOLDERS = ("sent", "all_documents", "discussion_threads")


class RejectCounter(Counter):
    """Counts rejected entries by reason, e.g. {"phishtank:bad_url": 3}."""


def _collected_at(folder: Path) -> datetime:
    times = [f["downloaded_at"] for f in load_manifest(folder)["files"]]
    return datetime.fromisoformat(min(times))


def _url_record(source: Source, raw_url: str, collected_at, rejects, **fields):
    normalised = clean.normalise_url(raw_url)
    if normalised is None:
        rejects[f"{source.value}:bad_url"] += 1
        return None
    return SampleRecord.create(
        source=source,
        raw_content=raw_url.strip(),
        hash_of=normalised,
        collected_at=collected_at,
        group_key=clean.url_group_key(normalised),
        **fields,
    )


def parse_phishtank(folder: Path, rejects: RejectCounter) -> Iterator[SampleRecord]:
    collected_at = _collected_at(folder)
    with (folder / "online-valid.csv").open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            if row.get("verified") != "yes":
                rejects["phishtank:not_verified"] += 1
                continue
            try:
                submitted = datetime.fromisoformat(row["submission_time"]).date()
            except (KeyError, ValueError):
                submitted = None
            record = _url_record(
                Source.PHISHTANK, row["url"], collected_at, rejects, source_date=submitted
            )
            if record:
                yield record


def parse_openphish(folder: Path, rejects: RejectCounter) -> Iterator[SampleRecord]:
    collected_at = _collected_at(folder)
    for line in (folder / "feed.txt").read_text(encoding="utf-8").splitlines():
        if line.strip():
            record = _url_record(Source.OPENPHISH, line, collected_at, rejects)
            if record:
                yield record


def parse_tranco(
    folder: Path, rejects: RejectCounter, *, limit: int = 100_000
) -> Iterator[SampleRecord]:
    """Top `limit` domains of the list, each as its https:// home page (rank kept in order)."""
    collected_at = _collected_at(folder)
    with zipfile.ZipFile(folder / "top-1m.csv.zip") as archive:
        name = archive.namelist()[0]
        with archive.open(name) as raw:
            reader = csv.reader(io.TextIOWrapper(raw, encoding="utf-8"))
            for rank, (_, domain) in enumerate(reader, start=1):
                if rank > limit:
                    break
                record = _url_record(Source.TRANCO, f"https://{domain}/", collected_at, rejects)
                if record:
                    yield record


def _email_record(
    source: Source, raw: bytes, collected_at, rejects, group_key: str | None = None
) -> SampleRecord | None:
    message = clean.parse_email(raw)
    basis = clean.email_hash_basis(message)
    if basis is None:
        rejects[f"{source.value}:empty_email"] += 1
        return None
    if group_key is None:
        sender = clean.sender_address(message)
        group_key = f"sender:{sender}" if sender else None
    record = SampleRecord.create(
        source=source,
        raw_content=clean.decode_raw(raw),
        hash_of=basis,
        collected_at=collected_at,
        source_date=clean.message_date(message),
        group_key=group_key,
    )
    if record.group_key is None:  # no sender: the sample is its own group
        record = record.model_copy(update={"group_key": f"sample:{record.content_hash}"})
    return record


def parse_nazario(folder: Path, rejects: RejectCounter) -> Iterator[SampleRecord]:
    collected_at = _collected_at(folder)
    for entry in load_manifest(folder)["files"]:
        box = mailbox.mbox(folder / entry["file"], create=False)
        try:
            for key in box.iterkeys():
                raw = box.get_bytes(key)
                record = _email_record(Source.NAZARIO, raw, collected_at, rejects)
                if record:
                    yield record
        finally:
            box.close()


def parse_spamassassin(folder: Path, rejects: RejectCounter) -> Iterator[SampleRecord]:
    collected_at = _collected_at(folder)
    for entry in load_manifest(folder)["files"]:
        with tarfile.open(folder / entry["file"], "r:bz2") as archive:
            for member in archive:
                if not member.isfile() or member.name.endswith("/cmds"):
                    continue
                raw = archive.extractfile(member).read()
                record = _email_record(Source.SPAMASSASSIN, raw, collected_at, rejects)
                if record:
                    yield record


def enron_selected(member_name: str, fraction: float) -> bool:
    """Deterministic sample: keep a message if the hash of its path falls under `fraction`."""
    value = int.from_bytes(hashlib.sha256(member_name.encode()).digest()[:8], "big")
    return value / 2**64 < fraction


def parse_enron(
    folder: Path, rejects: RejectCounter, *, fraction: float = 0.1
) -> Iterator[SampleRecord]:
    """Received mail from the maildir tarball; grouped by mailbox owner (decision D4)."""
    collected_at = _collected_at(folder)
    with tarfile.open(folder / "enron_mail_20150507.tar.gz", "r|gz") as archive:
        for member in archive:
            parts = member.name.split("/")
            if not member.isfile() or len(parts) < 4 or parts[0] != "maildir":
                continue
            owner, folder_name = parts[1], parts[2].lower()
            if any(skip in folder_name for skip in ENRON_SKIP_FOLDERS):
                rejects["enron:skipped_folder"] += 1
                continue
            if not enron_selected(member.name, fraction):
                continue
            raw = archive.extractfile(member).read()
            record = _email_record(
                Source.ENRON, raw, collected_at, rejects, group_key=f"enron:{owner}"
            )
            if record:
                yield record


def parse_own_mailbox(folder: Path, rejects: RejectCounter) -> Iterator[SampleRecord]:
    """Recent legitimate .eml files you exported (personal content removed) — evaluation only."""
    files = sorted(folder.glob("*.eml"))
    if not files:
        return
    collected_at = datetime.fromtimestamp(min(f.stat().st_mtime for f in files)).astimezone()
    for path in files:
        record = _email_record(Source.OWN_MAILBOX, path.read_bytes(), collected_at, rejects)
        if record:
            yield record


PARSERS = {
    Source.PHISHTANK: parse_phishtank,
    Source.OPENPHISH: parse_openphish,
    Source.TRANCO: parse_tranco,
    Source.NAZARIO: parse_nazario,
    Source.SPAMASSASSIN: parse_spamassassin,
    Source.ENRON: parse_enron,
    Source.OWN_MAILBOX: parse_own_mailbox,
}
