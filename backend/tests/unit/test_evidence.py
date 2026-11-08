"""The shared evidence builder (D11 step 2): training matrix and live API use it alike."""

import base64
from datetime import UTC, datetime

import pytest

from phishguard.services.evidence import (
    build_url_evidence,
    evidence_from_answer,
    is_safe_to_fetch,
    page_charset,
    rdap_domain,
)
from phishguard.services.inference.evidence_client import request_evidence

T = datetime(2026, 11, 5, tzinfo=UTC)


def test_page_charset_uses_the_header_or_falls_back_to_utf8():
    assert page_charset("text/html; charset=ISO-8859-1") == "iso8859-1"
    assert page_charset('text/html; charset="windows-1252"') == "cp1252"
    assert page_charset("text/html; charset=no-such-codec") == "utf-8"
    assert page_charset(None) == "utf-8"


def test_rdap_domain_is_the_registered_domain():
    assert rdap_domain("https://a.b.example.co.uk/x") == "example.co.uk"
    assert rdap_domain("http://[broken") == ""
    assert rdap_domain("not a url") == ""


def test_page_is_decoded_with_its_charset_and_ages_use_the_fetch_time():
    meta = {
        "content_type": "text/html; charset=ISO-8859-1",
        "fetched_at": "2026-11-02T10:00:00+00:00",
        "final_url": "https://shop-test.com/b",
    }
    evidence = build_url_evidence(
        "https://shop-test.com/a", T, meta=meta, page="café".encode("latin-1"), dns={}, tls=None,
        rdap=None,
    )  # fmt: skip
    assert evidence.html == "café"
    assert evidence.captured_at == datetime(2026, 11, 2, 10, tzinfo=UTC)
    assert evidence.final_url == "https://shop-test.com/b"


def test_nothing_collected_means_no_page_and_collection_time():
    evidence = build_url_evidence(
        "https://gone-test.com/", T, meta=None, page=None, dns=None, tls=None, rdap=None
    )
    assert evidence.html is None and evidence.final_url is None and evidence.captured_at == T


@pytest.mark.parametrize(
    "url",
    [
        "https://shop-test.com/reset?token=abc",
        "https://shop-test.com/l?access_token=abc",
        "https://shop-test.com/l?sessionid=1",
        "https://shop-test.com/l?code=123456",
        "https://shop-test.com/l?api_key=1",
        "https://shop-test.com/l?sid=1",
        "https://shop-test.com/l?sig=1",
        "https://shop-test.com/l?otp=1",
        "https://shop-test.com/l?x=" + "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0fG",
        "https://user:pw@shop-test.com/",
        "http://[broken",
    ],
)
def test_urls_that_may_carry_a_secret_are_not_safe_to_fetch(url):
    assert not is_safe_to_fetch(url)


@pytest.mark.parametrize(
    "url",
    [
        "https://shop-test.com/",
        "https://shop-test.com/login",
        "https://shop-test.com/p?id=42&q=shoes",
        "https://shop-test.com/p?monkey=1&barcode=2&zipcode=3",  # "key" / "code" inside a word
    ],
)
def test_ordinary_urls_are_safe_to_fetch(url):
    assert is_safe_to_fetch(url)


def test_answer_becomes_evidence_and_rdap_is_never_used():
    answer = {
        "meta": {"fetched_at": "2026-11-02T10:00:00+00:00", "final_url": "https://a-test.com/"},
        "page_b64": base64.b64encode(b"<html>hi</html>").decode(),
        "dns": {"A": {"records": ["203.0.113.5"], "ttl": 60}},
        "tls": {"error": "x"},
    }
    evidence = evidence_from_answer("https://a-test.com/", T, answer)
    assert evidence.html == "<html>hi</html>" and evidence.dns == answer["dns"]
    assert evidence.tls == {"error": "x"} and evidence.rdap is None

    empty = evidence_from_answer("https://a-test.com/", T, {"meta": {}})
    assert empty.html is None and empty.dns is None and empty.captured_at == T


class _FakeJob:
    def __init__(self, outcome):
        self.outcome = outcome

    def get(self, timeout):
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome


class _FakeCelery:
    def __init__(self, outcome):
        self.outcome, self.calls = outcome, []

    def send_task(self, name, **kwargs):
        self.calls.append((name, kwargs))
        if isinstance(self.outcome, ConnectionError):
            raise self.outcome
        return _FakeJob(self.outcome)


def test_request_goes_to_the_evidence_queue_and_returns_the_answer():
    celery = _FakeCelery({"stage": 1})
    assert request_evidence("https://a-test.com/", 1, celery=celery) == {"stage": 1}
    name, kwargs = celery.calls[0]
    assert name == "phishguard.collect_evidence" and kwargs["queue"] == "evidence"
    assert kwargs["args"] == ["https://a-test.com/", 1, 6.0] and kwargs["expires"] == 6.5


@pytest.mark.parametrize("failure", [TimeoutError("late"), ValueError("task"), ConnectionError()])
def test_late_or_failed_evidence_is_none_never_an_error(failure):
    assert request_evidence("https://a-test.com/", 2, celery=_FakeCelery(failure)) is None
