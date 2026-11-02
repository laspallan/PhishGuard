"""Step 2: download each source exactly as published (formats checked 2026-11-02).

Files go to data/raw/<source>/<YYYY-MM-DD>/ with a manifest.json recording, for every file,
the URL (secrets redacted), size, SHA-256 and download time. Raw files are never edited.

Only lists of URLs and email archives are downloaded here. Phishing *pages* are fetched only
by the snapshot collector, inside its container.
"""

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path

import httpx

from phishguard_ml import paths
from phishguard_ml.data.records import Source

DEFAULT_USER_AGENT = "PhishGuard-research/0.1 (MSc research; github.com/laspallan/PhishGuard)"
TIMEOUT = httpx.Timeout(30.0, read=300.0)
CHUNK = 1 << 20

NAZARIO_FILES = (
    "phishing0.mbox",
    "phishing1.mbox",
    "phishing2.mbox",
    "phishing3.mbox",
    "20051114.mbox",
    "private-phishing4.mbox",
    *(f"phishing-{year}" for year in range(2015, 2026)),
)
# Ham only: the corpus's spam is not phishing. The 2002 archives are earlier copies of these.
SPAMASSASSIN_FILES = (
    "20030228_easy_ham.tar.bz2",
    "20030228_easy_ham_2.tar.bz2",
    "20030228_hard_ham.tar.bz2",
)


@dataclass(frozen=True)
class RemoteFile:
    url: str
    filename: str
    secret: str | None = None  # part of the URL to redact in the manifest


def remote_files(source: Source) -> list[RemoteFile]:
    if source is Source.PHISHTANK:
        key = os.environ.get("PHISHGUARD_PHISHTANK_APP_KEY")
        base = "https://data.phishtank.com/data"
        url = f"{base}/{key}/online-valid.csv" if key else f"{base}/online-valid.csv"
        return [RemoteFile(url, "online-valid.csv", secret=key)]
    if source is Source.OPENPHISH:
        url = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
        return [RemoteFile(url, "feed.txt")]
    if source is Source.TRANCO:
        return [
            RemoteFile("https://tranco-list.eu/top-1m.csv.zip", "top-1m.csv.zip"),
            RemoteFile("https://tranco-list.eu/top-1m-id", "list-id.txt"),
        ]
    if source is Source.NAZARIO:
        return [RemoteFile(f"https://monkey.org/~jose/phishing/{n}", n) for n in NAZARIO_FILES]
    if source is Source.SPAMASSASSIN:
        base = "https://spamassassin.apache.org/old/publiccorpus"
        return [RemoteFile(f"{base}/{n}", n) for n in SPAMASSASSIN_FILES]
    if source is Source.ENRON:
        name = "enron_mail_20150507.tar.gz"
        return [RemoteFile(f"https://www.cs.cmu.edu/~enron/{name}", name)]
    raise ValueError(f"{source} has no download (own_mailbox files are added by hand)")


def user_agent(source: Source) -> str:
    # PhishTank asks for "phishtank/[username]".
    username = os.environ.get("PHISHGUARD_PHISHTANK_USERNAME")
    if source is Source.PHISHTANK and username:
        return f"phishtank/{username}"
    return os.environ.get("PHISHGUARD_HTTP_USER_AGENT", DEFAULT_USER_AGENT)


def redact(url: str, secret: str | None) -> str:
    return url.replace(secret, "<redacted>") if secret else url


def download_source(
    source: Source, *, client: httpx.Client, day: date | None = None, force: bool = False
) -> Path:
    """Download every file of `source` into raw/<source>/<day>/ and write manifest.json."""
    day = day or datetime.now(UTC).date()
    target = paths.raw_dir() / source.value / day.isoformat()
    manifest_path = target / "manifest.json"
    if manifest_path.exists() and not force:
        return target
    target.mkdir(parents=True, exist_ok=True)

    entries = []
    for remote in remote_files(source):
        destination = target / remote.filename
        tmp = destination.with_suffix(destination.suffix + ".part")
        digest = hashlib.sha256()
        size = 0
        with client.stream("GET", remote.url, headers={"User-Agent": user_agent(source)}) as r:
            r.raise_for_status()
            with tmp.open("wb") as handle:
                for chunk in r.iter_bytes(CHUNK):
                    handle.write(chunk)
                    digest.update(chunk)
                    size += len(chunk)
        os.replace(tmp, destination)
        entries.append(
            {
                "url": redact(remote.url, remote.secret),
                "file": remote.filename,
                "bytes": size,
                "sha256": digest.hexdigest(),
                "downloaded_at": datetime.now(UTC).isoformat(),
            }
        )

    manifest = {"source": source.value, "day": day.isoformat(), "files": entries}
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return target


def latest_download(source: Source) -> Path | None:
    """The newest raw/<source>/<day>/ folder that has a manifest, or None."""
    folder = paths.raw_dir() / source.value
    days = sorted(p for p in folder.glob("*") if (p / "manifest.json").exists())
    return days[-1] if days else None


def load_manifest(folder: Path) -> dict:
    return json.loads((folder / "manifest.json").read_text(encoding="utf-8"))


def make_client() -> httpx.Client:
    return httpx.Client(timeout=TIMEOUT, follow_redirects=True)
