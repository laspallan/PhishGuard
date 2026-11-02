"""Guards Docs/features.md: exactly F1-F140, in order, unique names, group sizes as in Table 3.1."""

import re
from collections import Counter
from pathlib import Path

import pytest

CATALOGUE = Path(__file__).resolve().parents[3] / "Docs" / "features.md"
ROW = re.compile(r"^\| (F\d+) \| ([a-z0-9_]+) \| ([^|]+) \| ([^|]+) \|$")

# Proposal Table 3.1.
EXPECTED_GROUP_SIZES = {
    "URL lexical": 45,
    "Domain/SSL": 20,
    "HTML/JS": 30,
    "Email header": 20,
    "NLP text": 25,
}


@pytest.fixture(scope="module")
def rows() -> list[tuple[str, str, str]]:
    lines = CATALOGUE.read_text(encoding="utf-8").splitlines()
    matches = [ROW.match(line) for line in lines]
    return [(m[1], m[2], m[3].strip()) for m in matches if m]


def test_catalogue_has_f1_to_f140_in_order(rows):
    assert [fid for fid, _, _ in rows] == [f"F{i}" for i in range(1, 141)]


def test_feature_names_are_unique(rows):
    names = [name for _, name, _ in rows]
    assert len(set(names)) == len(names) == 140


def test_group_sizes_match_table_3_1(rows):
    assert Counter(group for _, _, group in rows) == EXPECTED_GROUP_SIZES


def test_groups_are_contiguous_ranges(rows):
    # F1-F45, F46-F65, F66-F95, F96-F115, F116-F140.
    groups_in_order = [group for _, _, group in rows]
    boundaries = [g for i, g in enumerate(groups_in_order) if i == 0 or g != groups_in_order[i - 1]]
    assert boundaries == list(EXPECTED_GROUP_SIZES)
