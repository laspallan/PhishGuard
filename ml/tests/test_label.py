import pytest

from phishguard.models.enums import AttackCategory as C
from phishguard_ml.data import clean, label
from phishguard_ml.data.records import SampleRecord, Source
from tests.fixtures import email_bytes

LOGIN_PAGE = "<html><title>Sign in</title><form><input type='password' name=p></form></html>"


@pytest.mark.parametrize(
    ("url", "html", "expected"),
    [
        ("http://cdn.example/invoice.exe", None, C.MALWARE),
        ("http://paypal-security.example/login", None, C.BRAND_IMPERSONATION),
        ("https://www.paypal.com/signin", LOGIN_PAGE, C.CREDENTIAL_HARVEST),  # own domain
        ("http://x.example/", "<title>Netflix - update payment</title>", C.BRAND_IMPERSONATION),
        ("http://x.example/a", LOGIN_PAGE, C.CREDENTIAL_HARVEST),
        ("http://x.example/a", "<form>Please log in</form>", C.CREDENTIAL_HARVEST),
        ("http://x.example/a", "<p>hello</p>", C.UNKNOWN),
        ("http://x.example/a", None, C.UNKNOWN),
    ],
)
def test_url_rules(url, html, expected):
    assert label.label_url(url, html) is expected


def test_rules_apply_in_order_malware_first():
    assert label.label_url("http://paypal-help.example/app.apk", LOGIN_PAGE) is C.MALWARE


def message(**kwargs):
    return clean.parse_email(email_bytes(**kwargs))


def test_email_with_risky_attachment_is_malware():
    raw = (
        b"From: a@x.example\nTo: b@y.example\nSubject: Invoice\nMIME-Version: 1.0\n"
        b'Content-Type: multipart/mixed; boundary="B"\n\n'
        b"--B\nContent-Type: text/plain\n\nSee file\n"
        b"--B\nContent-Type: application/octet-stream\nContent-Disposition: attachment; "
        b'filename="invoice.zip"\n\nUEsDBA==\n--B--\n'
    )
    assert label.label_email(clean.parse_email(raw)) is C.MALWARE


def test_email_rules():
    brand = message(sender="PayPal <service@pp-alerts.example>", subject="Your PayPal account")
    assert label.label_email(brand) is C.BRAND_IMPERSONATION

    own = message(sender="PayPal <service@paypal.com>", subject="Verify your account now")
    assert label.label_email(own) is C.CREDENTIAL_HARVEST

    spear = message(to="Alice Smith <alice@uniexample.ac>", body="Dear Alice, the report is due.")
    assert label.label_email(spear) is C.SPEAR

    assert label.label_email(message(body="Nothing special here.")) is C.UNKNOWN


def test_legitimate_records_are_never_labelled():
    record = SampleRecord.create(
        source=Source.TRANCO,
        raw_content="https://x.example/a.exe",
        collected_at="2026-11-02T00:00Z",
    )
    assert label.label_record(record).attack_category is None


def test_label_record_sets_category_for_phishing():
    record = SampleRecord.create(
        source=Source.NAZARIO,
        raw_content=email_bytes(subject="Please verify your account").decode(),
        collected_at="2026-11-02T00:00Z",
    )
    labelled = label.label_record(record)

    assert labelled.attack_category is C.CREDENTIAL_HARVEST
    assert label.category_counts([labelled]) == {"email:credential_harvest": 1}


def test_malformed_headers_do_not_crash_labelling():
    # This To header (from a real Nazario message) makes Python's email parser raise
    # AttributeError when the header is read.
    raw = (
        b"From: a@x.example\nTo:\tunlisted-recipients:; (no To-header on input)\n\nPlease log in\n"
    )
    message = clean.parse_email(raw)
    with pytest.raises(AttributeError):
        str(message.get("To"))

    assert label.label_email(message) is C.CREDENTIAL_HARVEST


def test_phishtank_target_means_brand_impersonation_after_malware():
    assert label.label_url("http://x.example/a", "<p>hi</p>", phishtank_target="Allegro") is (
        C.BRAND_IMPERSONATION
    )
    assert label.label_url("http://x.example/a.apk", None, phishtank_target="Allegro") is (
        C.MALWARE
    )


def test_label_record_looks_up_the_target_by_normalised_url():
    record = SampleRecord.create(
        source=Source.PHISHTANK, raw_content="HTTP://X.example/a", collected_at="2026-11-02T00:00Z"
    )
    targets = {clean.normalise_url("http://x.example/a"): "Allegro"}

    assert label.label_record(record, None, phishtank_targets=targets).attack_category is (
        C.BRAND_IMPERSONATION
    )
