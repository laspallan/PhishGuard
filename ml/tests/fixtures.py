"""Builders for tiny raw downloads in each source's real format (as observed 2026-11-02)."""

import io
import json
import tarfile
import zipfile
from pathlib import Path

DOWNLOADED_AT = "2026-11-02T09:00:00+00:00"


def email_bytes(
    subject: str = "Hello",
    body: str = "Body text",
    sender: str = "Bob <bob@example.org>",
    to: str = "Alice Smith <alice@uni.example>",
    date: str = "Mon, 4 Mar 2002 10:00:00 -0800",
    extra_headers: str = "",
) -> bytes:
    return (
        f"From: {sender}\nTo: {to}\nSubject: {subject}\nDate: {date}\n{extra_headers}"
        f"Content-Type: text/plain; charset=utf-8\n\n{body}\n"
    ).encode()


def write_download(folder: Path, files: dict[str, bytes], source: str) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    entries = []
    for name, content in files.items():
        (folder / name).write_bytes(content)
        entries.append({"file": name, "bytes": len(content), "downloaded_at": DOWNLOADED_AT})
    manifest = {"source": source, "day": "2026-11-02", "files": entries}
    (folder / "manifest.json").write_text(json.dumps(manifest))
    return folder


def phishtank_csv(rows: list[tuple[str, str, str]], targets: list[str] | None = None) -> bytes:
    header = (
        "phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target"
    )
    targets = targets or ["Other"] * len(rows)
    lines = [header] + [
        f"{i},{url},http://www.phishtank.com/phish_detail.php?phish_id={i},{submitted},"
        f"{verified},{submitted},yes,{target}"
        for i, ((url, submitted, verified), target) in enumerate(
            zip(rows, targets, strict=True), start=1
        )
    ]
    return ("\n".join(lines) + "\n").encode()


def tranco_zip(domains: list[str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        rows = "".join(f"{rank},{d}\n" for rank, d in enumerate(domains, start=1))
        archive.writestr("top-1m.csv", rows)
    return buffer.getvalue()


def mbox(messages: list[bytes]) -> bytes:
    return b"".join(b"From MAILER-DAEMON Thu Jan  1 00:00:00 2015\n" + m + b"\n" for m in messages)


def tar_archive(members: dict[str, bytes], mode: str) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode=mode) as archive:
        for name, content in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    return buffer.getvalue()
