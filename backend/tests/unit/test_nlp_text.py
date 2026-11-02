"""F116–F140. Expected values worked out by hand in the comments."""

import math
import re
from pathlib import Path

import pytest

from phishguard.services.features.email_parts import parse
from phishguard.services.features.nlp_text import FEATURE_NAMES, extract, syllables

CATALOGUE = Path(__file__).resolve().parents[3] / "Docs" / "features.md"
ROW = re.compile(r"^\| F(\d+) \| ([a-z0-9_]+) \|")

EMAIL = """From: "Support" <support@bank-test.com>
Subject: RE: Urgent: your account is suspended!
Content-Type: text/plain; charset=utf-8

Dear customer, your PayPal account is locked. Click here within 24 hours to verify your \
account: https://bank-test.com/login. Call +1 555 123 4567. Pay $50 now!
"""


def features(raw):
    return dict(zip(FEATURE_NAMES, extract(parse(raw)), strict=True))


def test_names_and_order_match_the_catalogue():
    rows = [ROW.match(line) for line in CATALOGUE.read_text(encoding="utf-8").splitlines()]
    assert list(FEATURE_NAMES) == [m[2] for m in rows if m and 116 <= int(m[1]) <= 140]


def test_hand_checked_email():
    f = features(EMAIL)
    # Body words (URL removed, digits are not words): Dear customer your PayPal account is
    # locked | Click here within hours to verify your account Call | Pay now = 7 + 9 + 2 = 18,
    # in 3 sentences. Letters 37 + 43 + 6 = 86, of which 6 upper case (D P P C C P).
    # Syllables (vowel groups): 12 + 13 + 2 = 27.
    expected = {
        "num_brand_mentions": 1,  # paypal
        "num_urgency_terms": 2,  # Urgent (subject), now
        "num_threat_terms": 2,  # suspended, locked ("lock" does not also match)
        "num_reward_terms": 0,
        "num_credential_terms": 1,  # "verify your account" ("login" was in the removed URL)
        "num_financial_terms": 1,  # paypal
        "generic_greeting": 1,  # "Dear customer"
        "subject_urgency_terms": 1,
        "fake_reply_subject": 1,  # "RE:" without In-Reply-To / References
        "subject_length": 38,
        "word_count": 18,
        "uppercase_ratio": 6 / 86,
        "exclamation_count": 2,  # subject + body
        "spelling_error_ratio": 0,  # 17 checkable words (PayPal excluded), all known
        "readability_score": 206.835 - 1.015 * (18 / 3) - 84.6 * (27 / 18),  # 73.845
        "avg_sentence_length": 6,
        "call_to_action_count": 1,  # click here
        "lexical_diversity": 16 / 18,  # "your" and "account" twice
        "num_currency_symbols": 1,  # $
        "num_phone_numbers": 1,  # +1 555 123 4567 (11 digits)
        "non_ascii_ratio": 0,
        "phishing_lexicon_score": 100 * (2 + 2 + 0 + 1 + 1 + 2 * 1) / 18,
        "deadline_mention": 1,  # within 24 hours
        "brand_sender_mismatch": 1,  # PayPal, sent from bank-test.com
    }
    assert {k: v for k, v in f.items() if k != "sentiment_polarity"} == pytest.approx(expected)
    assert -1 <= f["sentiment_polarity"] <= 1


def test_syllable_heuristic_by_hand():
    assert syllables("customer") == 3
    assert syllables("here") == 1  # silent final e
    assert syllables("table") == 2  # "-le" keeps its syllable
    assert syllables("rhythm") == 1  # y is a vowel; at least 1


def test_sentiment_direction():
    happy = features("From: a@x-test.com\n\nThank you, this is wonderful and great news!\n")
    sad = features("From: a@x-test.com\n\nThis is terrible, awful and a disaster.\n")
    assert happy["sentiment_polarity"] > 0 > sad["sentiment_polarity"]


def test_html_only_body_uses_visible_text_and_counts_non_ascii():
    raw = (
        "From: a@x-test.com\nSubject: Hi\nContent-Type: text/html; charset=utf-8\n\n"
        "<p>Café menu</p><script>var hidden = 1;</script>\n"
    )
    f = features(raw)
    assert f["word_count"] == 2  # "Café menu"; the script is not text
    assert f["non_ascii_ratio"] > 0


def test_real_reply_misspellings_and_empty_body():
    reply = features("From: a@x-test.com\nSubject: Re: lunch\nIn-Reply-To: <1@x-test.com>\n\nok\n")
    assert reply["fake_reply_subject"] == 0

    typos = features("From: a@x-test.com\n\nPleese verifiy your acount\n")
    assert typos["spelling_error_ratio"] == pytest.approx(3 / 4)  # pleese verifiy acount

    empty = features("From: a@x-test.com\n\n")
    assert empty["word_count"] == 0
    for name in ("uppercase_ratio", "readability_score", "lexical_diversity", "sentiment_polarity"):
        assert math.isnan(empty[name])
