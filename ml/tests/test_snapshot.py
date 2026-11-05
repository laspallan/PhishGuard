"""Snapshot collector safety and behaviour, with all network access mocked."""

import json

import httpcore
import httpx
import pytest

from phishguard_ml.data import snapshot
from phishguard_ml.data.records import SampleRecord, Source

PUBLIC = {"site.example": ["93.184.216.34"], "next.example": ["93.184.216.35"]}


def fake_resolver(table):
    return lambda host: table.get(host, [])


def client_for(routes: dict[str, httpx.Response], seen: list[str] | None = None):
    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(str(request.url))
        return routes.get(str(request.url), httpx.Response(404))

    return httpx.Client(transport=httpx.MockTransport(handler))


@pytest.mark.parametrize(
    ("address", "allowed"),
    [
        ("93.184.216.34", True),
        ("127.0.0.1", False),
        ("10.1.2.3", False),
        ("192.168.0.10", False),
        ("169.254.169.254", False),  # cloud metadata endpoint
        ("::1", False),
        ("fe80::1", False),
    ],
)
def test_only_public_addresses_are_allowed(address, allowed):
    resolver = fake_resolver({"h.example": [address]})
    if allowed:
        snapshot.check_safe_target("http://h.example/", resolver)
    else:
        with pytest.raises(snapshot.UnsafeTargetError):
            snapshot.check_safe_target("http://h.example/", resolver)


def test_non_http_and_unresolvable_targets_are_refused():
    with pytest.raises(snapshot.UnsafeTargetError):
        snapshot.check_safe_target("ftp://site.example/", fake_resolver(PUBLIC))
    with pytest.raises(snapshot.UnsafeTargetError):
        snapshot.check_safe_target("http://nowhere.example/", fake_resolver(PUBLIC))


def test_html_page_is_stored_and_redirects_are_followed_hop_by_hop():
    routes = {
        "http://site.example/": httpx.Response(302, headers={"location": "http://next.example/p"}),
        "http://next.example/p": httpx.Response(
            200, headers={"content-type": "text/html; charset=utf-8"}, content=b"<html>hi</html>"
        ),
    }

    meta, html = snapshot.fetch_page(
        "http://site.example/", client_for(routes), fake_resolver(PUBLIC)
    )

    assert html == b"<html>hi</html>"
    assert meta["redirects"] == ["http://next.example/p"]
    assert meta["status"] == 200


def test_redirect_to_a_private_address_is_not_followed():
    routes = {
        "http://site.example/": httpx.Response(
            302, headers={"location": "http://internal.example/"}
        )
    }
    seen: list[str] = []
    resolver = fake_resolver({**PUBLIC, "internal.example": ["192.168.1.1"]})

    meta, html = snapshot.fetch_page("http://site.example/", client_for(routes, seen), resolver)

    assert html is None
    assert "non-public" in meta["skipped"]
    assert meta["unsafe_host"] is False  # the original host itself was fine
    assert seen == ["http://site.example/"]


def test_non_html_bodies_are_never_downloaded():
    body_read = []

    class Watching(httpx.ByteStream):
        def __iter__(self):
            body_read.append(True)
            yield b"MZ\x90\x00"

    routes = {
        "http://site.example/file": httpx.Response(
            200, headers={"content-type": "application/octet-stream"}, stream=Watching(b"")
        )
    }

    meta, html = snapshot.fetch_page(
        "http://site.example/file", client_for(routes), fake_resolver(PUBLIC)
    )

    assert html is None
    assert meta["skipped"].startswith("not HTML")
    assert body_read == []


def test_large_pages_are_truncated(monkeypatch):
    monkeypatch.setattr(snapshot, "MAX_BYTES", 10)
    routes = {
        "http://site.example/": httpx.Response(
            200, headers={"content-type": "text/html"}, content=b"x" * 100
        )
    }

    meta, html = snapshot.fetch_page(
        "http://site.example/", client_for(routes), fake_resolver(PUBLIC)
    )

    assert len(html) == 10
    assert meta["truncated"] is True


def test_too_many_redirects_stop():
    routes = {
        "http://site.example/": httpx.Response(302, headers={"location": "http://site.example/"})
    }
    meta, html = snapshot.fetch_page(
        "http://site.example/", client_for(routes), fake_resolver(PUBLIC)
    )

    assert html is None
    assert "redirects" in meta["skipped"]


def test_unsafe_host_gets_no_dns_or_tls(monkeypatch, isolated_data_dir):
    contacted = []
    monkeypatch.setattr(snapshot, "resolve", fake_resolver({"lan.example": ["10.0.0.5"]}))
    monkeypatch.setattr(snapshot, "dns_info", lambda h: contacted.append("dns"))
    monkeypatch.setattr(snapshot, "tls_info", lambda h: contacted.append("tls"))
    record = SampleRecord.create(
        source=Source.PHISHTANK,
        raw_content="http://lan.example/login",
        collected_at="2026-11-02T00:00:00+00:00",
    )

    ref, links = snapshot.take_snapshot(record, client_for({}))

    assert contacted == [] and links == []
    folder = isolated_data_dir / ref
    assert json.loads((folder / "meta.json").read_text())["unsafe_host"] is True
    assert sorted(p.name for p in folder.iterdir()) == ["meta.json"]


def test_snapshots_are_refused_outside_the_container(monkeypatch):
    monkeypatch.delenv(snapshot.CONTAINER_FLAG, raising=False)
    called = []
    monkeypatch.setattr(snapshot, "take_snapshot", lambda *a: called.append(a))
    url = SampleRecord.create(
        source=Source.PHISHTANK, raw_content="http://a.example/", collected_at="2026-11-02T00:00Z"
    )

    with pytest.raises(snapshot.NotInSnapshotContainerError):
        snapshot.snapshot_records([url])
    assert called == []


T = "2026-11-02T00:00Z"


def fake_take(calls: list, links_for: dict | None = None):
    """Stands in for take_snapshot: writes meta.json like the real one, records the call."""

    def take(record, client, cache=None, links=0):
        calls.append(record.raw_content)
        folder = snapshot.paths.snapshots_dir() / str(record.sample_id)
        folder.mkdir(parents=True, exist_ok=True)
        found = (links_for or {}).get(record.raw_content, [])[:links]
        (folder / "meta.json").write_text(json.dumps({"same_site_links": found}))
        return f"snapshots/{record.sample_id}", found

    return take


def test_snapshot_records_sets_snapshot_ref_for_urls_only(monkeypatch):
    monkeypatch.setenv(snapshot.CONTAINER_FLAG, "1")
    monkeypatch.setattr(snapshot, "take_snapshot", fake_take([]))
    url = SampleRecord.create(
        source=Source.TRANCO, raw_content="https://a.example/", collected_at=T
    )
    mail = SampleRecord.create(source=Source.ENRON, raw_content="Subject: x\n\ny", collected_at=T)

    updated = snapshot.snapshot_records([url, mail], workers=2)

    assert updated[0].snapshot_ref == f"snapshots/{url.sample_id}"
    assert updated[1].snapshot_ref is None


def test_phishing_first_links_added_and_resume_after_rebuild(monkeypatch):
    monkeypatch.setenv(snapshot.CONTAINER_FLAG, "1")
    calls: list[str] = []
    links = {"https://site.example/": ["https://site.example/about", "https://site.example/x"]}
    monkeypatch.setattr(snapshot, "take_snapshot", fake_take(calls, links))
    home = SampleRecord.create(
        source=Source.TRANCO,
        raw_content="https://site.example/",
        collected_at=T,
        group_key="domain:site.example",
    )
    phish = SampleRecord.create(
        source=Source.PHISHTANK, raw_content="http://bad.example/", collected_at=T
    )

    updated = snapshot.snapshot_records([home, phish], workers=1, links=1)

    assert calls == ["http://bad.example/", "https://site.example/", "https://site.example/about"]
    child = updated[-1]
    assert child.raw_content == "https://site.example/about"
    assert child.source is Source.TRANCO and child.group_key == "domain:site.example"
    assert all(r.snapshot_ref for r in updated)

    # A rebuild from the raw files loses snapshot refs and link records; running again must
    # fetch nothing and bring the link record back from meta.json.
    calls.clear()
    rebuilt = [home, phish]
    again = snapshot.snapshot_records(rebuilt, workers=1, links=1)

    assert calls == []
    assert [r.raw_content for r in again] == [r.raw_content for r in updated]
    assert all(r.snapshot_ref for r in again)


def test_only_option_limits_to_one_label(monkeypatch):
    monkeypatch.setenv(snapshot.CONTAINER_FLAG, "1")
    calls: list[str] = []
    monkeypatch.setattr(snapshot, "take_snapshot", fake_take(calls))
    home = SampleRecord.create(
        source=Source.TRANCO, raw_content="https://a.example/", collected_at=T
    )
    phish = SampleRecord.create(
        source=Source.PHISHTANK, raw_content="http://b.example/", collected_at=T
    )

    snapshot.snapshot_records([home, phish], only=snapshot.Label.PHISHING)

    assert calls == ["http://b.example/"]


def test_same_site_links_rules():
    html = (
        '<a href="/about">a</a> <a href="https://shop.site-test.com/item?id=3">b</a>'
        '<a href="https://other.example/x">c</a> <a href="/">home</a> <a href="#top">t</a>'
        '<a href="/report.pdf">p</a> <a href="javascript:void(0)">j</a>'
    )
    found = snapshot.same_site_links(html, "https://www.site-test.com/", limit=5)

    assert sorted(found) == [
        "https://shop.site-test.com/item?id=3",
        "https://www.site-test.com/about",
    ]
    assert snapshot.same_site_links(html, "https://www.site-test.com/", limit=1) == found[:1]


def test_run_cache_computes_once():
    cache = snapshot.RunCache()
    calls = []
    for _ in range(3):
        cache.get("dns", "site.example", lambda: calls.append(1) or {"ok": True})

    assert calls == [1]


def test_unresolvable_host_still_gets_dns_but_is_not_unsafe():
    meta, html = snapshot.fetch_page("http://gone.example/", client_for({}), fake_resolver(PUBLIC))

    assert html is None
    assert "does not resolve" in meta["skipped"]
    assert meta["unsafe_host"] is False


def test_broken_redirect_location_is_recorded_not_raised():
    routes = {"http://site.example/": httpx.Response(302, headers={"location": "http://[bad/"})}

    meta, html = snapshot.fetch_page(
        "http://site.example/", client_for(routes), fake_resolver(PUBLIC)
    )

    assert html is None
    assert "Invalid IPv6 URL" in meta["error"]


def test_broken_hrefs_are_skipped():
    html = '<a href="http://[bad/x">b</a><a href="/ok">o</a>'

    assert snapshot.same_site_links(html, "https://www.site-test.com/", 5) == [
        "https://www.site-test.com/ok"
    ]


def test_one_crashing_url_does_not_stop_the_run(monkeypatch, isolated_data_dir):
    monkeypatch.setenv(snapshot.CONTAINER_FLAG, "1")
    good_calls: list[str] = []
    good = fake_take(good_calls)

    def take(record, client, cache=None, links=0):
        if "boom" in record.raw_content:
            raise RuntimeError("unexpected")
        return good(record, client, cache, links)

    monkeypatch.setattr(snapshot, "take_snapshot", take)
    boom = SampleRecord.create(
        source=Source.PHISHTANK, raw_content="http://boom.example/", collected_at=T
    )
    fine = SampleRecord.create(
        source=Source.PHISHTANK, raw_content="http://fine.example/", collected_at=T
    )

    updated = snapshot.snapshot_records([boom, fine], workers=1)

    assert good_calls == ["http://fine.example/"]
    assert all(r.snapshot_ref for r in updated)
    meta = json.loads(
        (isolated_data_dir / "snapshots" / str(boom.sample_id) / "meta.json").read_text()
    )
    assert meta["error"] == "crash: RuntimeError: unexpected"


def test_empty_meta_from_a_killed_run_is_fetched_again(monkeypatch, isolated_data_dir):
    monkeypatch.setenv(snapshot.CONTAINER_FLAG, "1")
    calls: list[str] = []
    monkeypatch.setattr(snapshot, "take_snapshot", fake_take(calls))
    phish = SampleRecord.create(
        source=Source.PHISHTANK, raw_content="http://half.example/", collected_at=T
    )
    folder = isolated_data_dir / "snapshots" / str(phish.sample_id)
    folder.mkdir(parents=True)
    (folder / "meta.json").write_text("")  # what a run killed mid-write left on disk (seen once)
    already_ref = phish.model_copy(update={"snapshot_ref": f"snapshots/{phish.sample_id}"})

    snapshot.snapshot_records([already_ref], workers=1)

    assert calls == ["http://half.example/"]


def test_meta_is_written_atomically(isolated_data_dir):
    folder = isolated_data_dir / "snapshots" / "x"
    folder.mkdir(parents=True)
    snapshot._write_meta(folder, {"status": 200})

    assert json.loads((folder / "meta.json").read_text()) == {"status": 200}
    assert not (folder / "meta.json.tmp").exists()


# --- D11f: connections go to the address that was checked (no DNS rebinding) ---------------


def rebinding_resolver(first: list[str], then: list[str]):
    """A hostile name server: one answer for the safety check, another one afterwards."""
    answers = [first]

    def resolver(host):
        return answers.pop() if answers else then

    return resolver


class RecordingBackend(httpcore.NetworkBackend):
    """Stands in for the real socket layer: records where it was asked to connect."""

    def __init__(self):
        self.connected: list[tuple[str, int]] = []

    def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        self.connected.append((host, port))
        raise httpcore.ConnectError("offline test")


def test_pinned_backend_connects_to_the_checked_ip_only():
    inner = RecordingBackend()
    backend = snapshot.PinnedBackend(fake_resolver(PUBLIC), inner)
    with pytest.raises(httpcore.ConnectError):
        backend.connect_tcp("site.example", 443)
    assert inner.connected == [("93.184.216.34", 443)]


def test_pinned_backend_refuses_a_rebound_private_address():
    inner = RecordingBackend()
    backend = snapshot.PinnedBackend(rebinding_resolver(["93.184.216.34"], ["127.0.0.1"]), inner)
    backend.resolver("site.example")  # the safety check's lookup: public
    with pytest.raises(snapshot.UnsafeTargetError):
        backend.connect_tcp("site.example", 80)  # the connection's lookup: loopback
    assert inner.connected == []


def test_pinned_transport_connects_to_the_checked_ip():
    """Guards the httpx wiring: if an upgrade bypassed PinnedBackend, this would fail."""
    inner = RecordingBackend()
    transport = snapshot.PinnedTransport(fake_resolver(PUBLIC), inner)
    with httpx.Client(transport=transport, trust_env=False) as client:
        with pytest.raises(httpx.ConnectError):
            client.get("http://site.example/login")
    assert inner.connected == [("93.184.216.34", 80)]


def test_fetch_page_refuses_rebinding_between_check_and_connect():
    resolver = rebinding_resolver(["93.184.216.34"], ["10.0.0.5"])
    inner = RecordingBackend()
    client = httpx.Client(transport=snapshot.PinnedTransport(resolver, inner), trust_env=False)

    meta, html = snapshot.fetch_page("http://site.example/", client, resolver)

    assert html is None and inner.connected == []
    assert "non-public address 10.0.0.5" in meta["skipped"] and meta["unsafe_host"] is True


def test_tls_connects_to_the_checked_ip_and_refuses_private(monkeypatch):
    connected = []

    def fake_connect(address, timeout):
        connected.append(address)
        raise OSError("offline test")

    monkeypatch.setattr(snapshot.socket, "create_connection", fake_connect)
    assert "OSError" in snapshot.tls_info("site.example", resolver=fake_resolver(PUBLIC))["error"]
    assert connected == [("93.184.216.34", 443)]

    connected.clear()
    lan = fake_resolver({"lan.example": ["192.168.1.1"]})
    assert "UnsafeTargetError" in snapshot.tls_info("lan.example", resolver=lan)["error"]
    assert connected == []


def test_collector_client_ignores_proxy_settings_and_is_pinned():
    with snapshot.pinned_client() as client:
        assert client.trust_env is False
        assert isinstance(client._transport, snapshot.PinnedTransport)
