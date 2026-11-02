import pytest

from phishguard_ml.data import clean
from phishguard_ml.data.records import SampleRecord, Source
from tests.fixtures import email_bytes

COLLECTED = "2026-11-02T09:00:00+00:00"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("HTTP://Example.COM", "http://example.com/"),
        ("https://example.com:443/a?b=1#frag", "https://example.com/a?b=1"),
        ("http://example.com:8080/Path", "http://example.com:8080/Path"),
        ("  http://example.com/x  ", "http://example.com/x"),
        ("http://example.com./", "http://example.com/"),
    ],
)
def test_normalise_url(raw, expected):
    assert clean.normalise_url(raw) == expected


@pytest.mark.parametrize(
    "raw",
    ["", "example.com", "ftp://example.com/", "http://", "http://exa mple.com", "http://x:99999/"],
)
def test_unusable_urls_are_rejected(raw):
    assert clean.normalise_url(raw) is None


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("login.paypal.com.evil.co.uk", "evil.co.uk"),
        ("www.google.com", "google.com"),
        ("192.168.1.1", "192.168.1.1"),
        ("sites.google.com", "google.com"),
    ],
)
def test_registered_domain(host, expected):
    assert clean.registered_domain(host) == expected


def test_url_group_key_uses_registered_domain():
    assert clean.url_group_key("http://a.b.evil.co.uk/x") == "domain:evil.co.uk"


def test_email_helpers_read_sender_date_and_body():
    message = clean.parse_email(email_bytes(body="Hi  there", sender="Bob <BOB@Example.org>"))

    assert clean.sender_address(message) == "bob@example.org"
    assert clean.message_date(message).isoformat() == "2002-03-04"
    assert clean.email_hash_basis(message) == "hello hi there"


def test_html_only_email_body_has_tags_removed():
    raw = (
        b"From: a@x.example\nSubject: S\nContent-Type: text/html\n\n"
        b"<p>Click <a href='http://x'>here</a></p>\n"
    )
    assert "click" in clean.email_hash_basis(clean.parse_email(raw))
    assert "<" not in clean.body_text(clean.parse_email(raw))


def test_empty_email_has_no_hash_basis():
    assert clean.email_hash_basis(clean.parse_email(b"From: a@x.example\n\n")) is None


def test_malformed_date_gives_none():
    message = clean.parse_email(email_bytes(date="not a date"))
    assert clean.message_date(message) is None


def test_decode_raw_replaces_invalid_bytes():
    assert clean.decode_raw(b"caf\xe9") == "caf�"


def record(source: Source, content: str) -> SampleRecord:
    return SampleRecord.create(source=source, raw_content=content, collected_at=COLLECTED)


def test_deduplicate_keeps_first_and_prefers_phishing_on_conflict():
    url = "https://example.org/"
    records = [
        record(Source.TRANCO, url),
        record(Source.PHISHTANK, url),
        record(Source.OPENPHISH, url),
        record(Source.PHISHTANK, "http://other.example/"),
    ]

    kept, report = clean.deduplicate(records)

    assert len(kept) == 2
    assert {r.source for r in kept} == {Source.PHISHTANK}
    assert report.duplicates == 2
    assert report.label_conflicts == 1
