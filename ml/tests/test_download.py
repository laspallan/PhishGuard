import hashlib
import json
from datetime import date

import httpx
import pytest

from phishguard_ml.data import download
from phishguard_ml.data.records import Source

DAY = date(2026, 11, 2)


def mock_client(responses: dict[str, bytes], seen: list[httpx.Request] | None = None):
    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request)
        body = responses.get(str(request.url))
        return httpx.Response(200, content=body) if body is not None else httpx.Response(404)

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_every_downloadable_source_has_files():
    for source in Source:
        if source is Source.OWN_MAILBOX:
            with pytest.raises(ValueError):
                download.remote_files(source)
        else:
            assert download.remote_files(source)


def test_download_writes_files_and_manifest(isolated_data_dir):
    feed = b"http://a.example/login\nhttp://b.example/x\n"
    url = download.remote_files(Source.OPENPHISH)[0].url

    folder = download.download_source(Source.OPENPHISH, client=mock_client({url: feed}), day=DAY)

    assert folder == isolated_data_dir / "raw" / "openphish" / "2026-11-02"
    assert (folder / "feed.txt").read_bytes() == feed
    manifest = json.loads((folder / "manifest.json").read_text())
    assert manifest["files"][0]["sha256"] == hashlib.sha256(feed).hexdigest()
    assert manifest["files"][0]["bytes"] == len(feed)
    assert download.latest_download(Source.OPENPHISH) == folder


def test_phishtank_key_goes_in_the_url_but_never_in_the_manifest(monkeypatch):
    monkeypatch.setenv("PHISHGUARD_PHISHTANK_APP_KEY", "SECRETKEY")
    monkeypatch.setenv("PHISHGUARD_PHISHTANK_USERNAME", "laspallan")
    url = "https://data.phishtank.com/data/SECRETKEY/online-valid.csv"
    seen: list[httpx.Request] = []

    folder = download.download_source(
        Source.PHISHTANK, client=mock_client({url: b"phish_id,url\n"}, seen), day=DAY
    )

    assert seen[0].headers["User-Agent"] == "phishtank/laspallan"
    manifest_text = (folder / "manifest.json").read_text()
    assert "SECRETKEY" not in manifest_text
    assert "<redacted>" in manifest_text


def test_existing_download_is_not_repeated_unless_forced():
    url = download.remote_files(Source.OPENPHISH)[0].url
    seen: list[httpx.Request] = []
    client = mock_client({url: b"x\n"}, seen)

    download.download_source(Source.OPENPHISH, client=client, day=DAY)
    download.download_source(Source.OPENPHISH, client=client, day=DAY)
    assert len(seen) == 1

    download.download_source(Source.OPENPHISH, client=client, day=DAY, force=True)
    assert len(seen) == 2


def test_http_error_leaves_no_manifest():
    with pytest.raises(httpx.HTTPStatusError):
        download.download_source(Source.OPENPHISH, client=mock_client({}), day=DAY)

    assert download.latest_download(Source.OPENPHISH) is None
