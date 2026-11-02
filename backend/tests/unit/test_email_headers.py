"""F96–F115. Hand-written emails; expected values worked out in the comments."""

import math
import re
from pathlib import Path

import pytest

from phishguard.services.features import email_headers
from phishguard.services.features.email_headers import AGE_SENSITIVE, FEATURE_NAMES, extract
from phishguard.services.features.email_parts import parse

CATALOGUE = Path(__file__).resolve().parents[3] / "Docs" / "features.md"
ROW = re.compile(r"^\| F(\d+) \| ([a-z0-9_]+) \|")

PHISH = """Received: from mx.bank-test.com by mail.inbox-test.com; Mon, 2 Nov 2026 10:05:00 +0000
Received: from relay.sender-test.net by mx.bank-test.com; Mon, 2 Nov 2026 10:00:00 +0000
Authentication-Results: mail.inbox-test.com; spf=softfail smtp.mailfrom=sender-test.net;
 dkim=none; dmarc=fail (p=REJECT sp=REJECT dis=QUARANTINE) header.from=bank-test.com
Return-Path: <bounce@sender-test.net>
From: "PayPal Security" <alerts@bank-test.com>
Reply-To: help@collect-test.org
To: you@inbox-test.com
Subject: Verify your account
Date: Mon, 2 Nov 2026 09:59:00 +0000
Message-ID: <abc@sender-test.net>
X-Mailer: Some Mailer 1.0
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="b"

--b
Content-Type: text/html; charset=utf-8

<p>Dear customer, <a href="https://collect-test.org/login">https://www.paypal.com/signin</a>
also see https://collect-test.org/login and http://other-test.com/x</p>
--b
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="Invoice.HTML"

PGh0bWw+
--b--
"""

PLAIN = """Message-ID: <1.JavaMail.evans@thyme>
Date: Mon, 14 May 2001 16:39:00 -0700 (PDT)
From: phillip.allen@enron.com
To: tim.belden@enron.com
Subject: Re: forecast

Here is our forecast.
"""


def features(raw, ranks=None):
    values = extract(parse(raw), ranks or {})
    return dict(zip(FEATURE_NAMES, values, strict=True))


def test_names_and_order_match_the_catalogue():
    rows = [ROW.match(line) for line in CATALOGUE.read_text(encoding="utf-8").splitlines()]
    assert list(FEATURE_NAMES) == [m[2] for m in rows if m and 96 <= int(m[1]) <= 115]


def test_age_sensitive_list_is_the_proposal_set():
    # F96-F101, F109, F110 (proposal Section 3.6.1)
    positions = sorted(FEATURE_NAMES.index(n) + 96 for n in AGE_SENSITIVE)
    assert positions == [96, 97, 98, 99, 100, 101, 109, 110]


def test_hand_checked_phishing_email():
    expected = {
        "spf_pass": 0,
        "spf_fail": 1,  # softfail
        "dkim_pass": 0,  # dkim=none
        "dkim_absent": 1,  # no DKIM-Signature header
        "dmarc_pass": 0,
        "dmarc_policy_strict": 1,  # p=REJECT
        "from_replyto_mismatch": 1,  # bank-test.com vs collect-test.org
        "from_returnpath_mismatch": 1,  # sender-test.net
        "display_name_spoof": 1,  # "PayPal Security" from bank-test.com
        "sender_in_tranco": 0,
        "num_received_headers": 2,
        "received_chain_inconsistent": 0,  # 10:00 then 10:05
        "message_id_domain_mismatch": 1,  # sender-test.net
        "suspicious_mailer": 0,
        "date_header_anomaly": 0,  # 6 minutes before receipt
        "html_only": 1,  # an HTML part and no text/plain part
        "num_attachments": 1,
        "risky_attachment_type": 1,  # Invoice.HTML
        "num_urls_in_email": 3,  # paypal.com/signin, collect-test.org/login, other-test.com/x
        "link_text_mismatch": 1,  # shows paypal.com, goes to collect-test.org
    }
    assert features(PHISH) == pytest.approx(expected)


def test_enron_style_email_without_delivery_headers():
    f = features(PLAIN, ranks={"enron.com": 50_000})
    for name in ("spf_pass", "spf_fail", "dkim_pass", "dmarc_pass", "dmarc_policy_strict"):
        assert math.isnan(f[name])  # no Authentication-Results
    assert f["dkim_absent"] == 1
    assert math.isnan(f["from_returnpath_mismatch"])  # no Return-Path to compare
    assert math.isnan(f["received_chain_inconsistent"])
    assert f["num_received_headers"] == 0
    assert f["message_id_domain_mismatch"] == 1  # "thyme" is not enron.com
    assert f["from_replyto_mismatch"] == 0
    assert f["sender_in_tranco"] == 1
    assert f["date_header_anomaly"] == 0  # a date, and no receipt time to compare
    assert f["html_only"] == 0 and f["num_attachments"] == 0 and f["num_urls_in_email"] == 0


def test_backwards_hop_and_missing_date():
    raw = (
        "Received: from b by c; Mon, 2 Nov 2026 08:00:00 +0000\n"  # newest, but 2 h earlier
        "Received: from a by b; Mon, 2 Nov 2026 10:00:00 +0000\n"
        "From: x@shop-test.com\n\nhi\n"
    )
    f = features(raw)
    assert f["received_chain_inconsistent"] == 1
    assert f["date_header_anomaly"] == 1  # no Date header


def test_date_far_from_receipt_and_spf_pass_from_received_spf():
    raw = (
        "Received: from a by b; Mon, 2 Nov 2026 10:00:00 +0000\n"
        "Received-SPF: Pass (sender SPF authorized)\n"
        "Date: Wed, 28 Oct 2026 10:00:00 +0000\n"
        "From: x@shop-test.com\n\nhi\n"
    )
    f = features(raw)
    assert f["date_header_anomaly"] == 1  # 5 days before receipt
    assert f["spf_pass"] == 1 and f["spf_fail"] == 0


def test_suspicious_mailer_list(monkeypatch):
    monkeypatch.setattr(email_headers, "SUSPICIOUS_MAILERS", (re.compile(r"Some Mailer"),))
    assert features(PHISH)["suspicious_mailer"] == 1


def test_broken_to_header_from_real_nazario_mail_does_not_crash():
    raw = "To:\tunlisted-recipients:; (no To-header on input)\nFrom: a@shop-test.com\n\nx\n"
    assert len(extract(parse(raw), {})) == len(FEATURE_NAMES)


@pytest.mark.parametrize(
    ("mailer", "suspicious"),
    [
        ("eGroups Message Poster", 1),
        ("Microsoft Outlook Express 6.00.2600.0000 abc", 1),  # malformed version string
        ("Microsoft Outlook Express 6.00.2800.1106", 0),  # normal version string
        ("mPOP web-mail 2.19", 1),
        ("Apple Mail (2.3654)", 0),
    ],
)
def test_spamassassin_ratware_rules(mailer, suspicious):
    raw = f"From: a@shop-test.com\nX-Mailer: {mailer}\n\nx\n"
    assert features(raw)["suspicious_mailer"] == suspicious
