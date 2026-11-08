"""The live evidence collector, offline: network mocked, only the deadline logic runs for real."""

import base64
import json
import time

import httpx
import pytest

from phishguard_ml.data import evidence_worker as worker
from phishguard_ml.data import snapshot

URL = "https://site.example/login"
DNS = {"A": {"records": ["93.184.216.34"], "ttl": 60}}
TLS = {"verified": True}
PUBLIC = {"site.example": ["93.184.216.34"], "lan.example": ["10.0.0.5"]}


@pytest.fixture
def contacts(monkeypatch):
    """In the container, with fake DNS / TLS; records which functions were called."""
    called = []
    monkeypatch.setenv(snapshot.CONTAINER_FLAG, "1")
    monkeypatch.setattr(snapshot, "resolve", lambda host: PUBLIC.get(host, []))

    def fake_dns(host, lifetime):
        called.append("dns")
        return DNS

    def fake_tls(host, timeout):
        called.append("tls")
        return TLS

    monkeypatch.setattr(snapshot, "dns_info", fake_dns)
    monkeypatch.setattr(snapshot, "tls_info", fake_tls)
    return called


def _client(seen=None, delay=0.0):
    def handler(request):
        if seen is not None:
            seen.append(str(request.url))
        time.sleep(delay)
        return httpx.Response(200, headers={"content-type": "text/html"}, content=b"<html>x</html>")

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_stage_1_uses_dns_only_and_never_contacts_the_target(contacts):
    seen = []
    answer = worker.collect(URL, 1, client=_client(seen))

    assert seen == [] and contacts == ["dns"]
    assert answer["dns"] == DNS and answer["page_b64"] is None and answer["tls"] is None
    assert answer["late"] == []
    json.dumps(answer)  # Celery's serializer is JSON


def test_stage_2_adds_the_page_and_tls(contacts):
    answer = worker.collect(URL, 2, client=_client())

    assert base64.b64decode(answer["page_b64"]) == b"<html>x</html>"
    assert answer["dns"] == DNS and answer["tls"] == TLS and answer["late"] == []
    assert answer["meta"]["final_url"] == URL and "fetched_at" in answer["meta"]
    json.dumps(answer)


@pytest.mark.parametrize("stage", [1, 2])
def test_private_targets_get_no_dns_tls_or_fetch(contacts, stage):
    seen = []
    answer = worker.collect("http://lan.example/", stage, client=_client(seen))

    assert seen == [] and contacts == []
    assert answer["meta"]["unsafe_host"] is True and "non-public" in answer["meta"]["skipped"]


def test_host_that_does_not_resolve_still_gets_dns(contacts):
    answer = worker.collect("https://gone.example/", 1, client=_client())
    assert contacts == ["dns"] and "unsafe_host" not in answer["meta"]


def test_secret_looking_urls_never_reach_the_target_in_stage_2(contacts):
    seen = []
    answer = worker.collect("https://site.example/reset?token=abc", 2, client=_client(seen))

    assert seen == [] and contacts == []
    assert answer["refused"] is True and answer["page_b64"] is None


def test_a_slow_target_does_not_hold_up_the_answer(contacts, monkeypatch):
    def slow_tls(host, timeout):
        time.sleep(1.0)
        return TLS

    monkeypatch.setattr(snapshot, "tls_info", slow_tls)
    started = time.monotonic()
    answer = worker.collect(URL, 2, deadline_seconds=0.2, client=_client(delay=1.0))

    assert time.monotonic() - started < 0.8  # did not wait for the slow threads
    assert {"page", "tls"} <= set(answer["late"]) and answer["dns"] == DNS
    assert answer["page_b64"] is None and answer["tls"] is None


def test_fetch_page_past_its_deadline_contacts_nobody():
    seen = []
    meta, html = snapshot.fetch_page(
        URL, _client(seen), lambda host: PUBLIC.get(host, []), deadline=time.monotonic() - 1
    )
    assert html is None and meta["skipped"] == "deadline" and seen == []


def test_refused_outside_the_container(monkeypatch):
    monkeypatch.delenv(snapshot.CONTAINER_FLAG, raising=False)
    with pytest.raises(snapshot.NotInSnapshotContainerError):
        worker.collect(URL, 1)
    with pytest.raises(snapshot.NotInSnapshotContainerError):
        worker.run_worker(1)


def test_unknown_stage_is_refused(contacts):
    with pytest.raises(ValueError):
        worker.collect(URL, 3)
