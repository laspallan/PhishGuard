"""The combined F1–F140 extractor: names, order, modality blocks, code hash."""

import math
import re
from datetime import UTC, datetime
from pathlib import Path

from phishguard.models.detection import FEATURE_COUNT
from phishguard.services.features import extractor
from phishguard.services.features.extractor import (
    FEATURE_NAMES,
    UrlEvidence,
    email_features,
    url_features,
)

CATALOGUE = Path(__file__).resolve().parents[3] / "Docs" / "features.md"
ROW = re.compile(r"^\| F(\d+) \| ([a-z0-9_]+) \|")


def test_all_140_names_in_catalogue_order():
    rows = [ROW.match(line) for line in CATALOGUE.read_text(encoding="utf-8").splitlines()]
    assert list(FEATURE_NAMES) == [m[2] for m in rows if m]
    assert len(FEATURE_NAMES) == FEATURE_COUNT == 140  # the database column expects 140


def test_url_record_fills_f1_to_f95_only():
    evidence = UrlEvidence(
        url="https://login.shop-test.com/a",
        captured_at=datetime(2026, 11, 2, tzinfo=UTC),
        html="<title>Sign in</title><form><input type=password></form>",
    )
    values = url_features(evidence, {})
    assert len(values) == 140
    assert values[0] == len("https://login.shop-test.com/a")  # F1
    assert values[FEATURE_NAMES.index("num_password_fields")] == 1  # F67
    assert all(math.isnan(v) for v in values[95:])


def test_email_record_fills_f96_to_f140_only():
    raw = "From: a@shop-test.com\nSubject: Verify now\nDate: Mon, 2 Nov 2026 10:00:00 +0000\n\nhi\n"
    values = email_features(raw, {})
    assert len(values) == 140
    assert all(math.isnan(v) for v in values[:95])
    assert values[FEATURE_NAMES.index("dkim_absent")] == 1
    assert values[FEATURE_NAMES.index("subject_length")] == len("Verify now")


def test_text_features_use_the_normalised_email():
    # The year in the subject is replaced by <YEAR> (5 -> 6 characters) before F125.
    raw = "From: a@shop-test.com\nSubject: Tax 2001\n\nbody\n"
    values = email_features(raw, {})
    assert values[FEATURE_NAMES.index("subject_length")] == len("Tax <YEAR>")


def test_feature_code_hash_is_stable_hex():
    first = extractor.feature_code_hash()
    assert first == extractor.feature_code_hash()
    assert re.fullmatch(r"[0-9a-f]{64}", first)
