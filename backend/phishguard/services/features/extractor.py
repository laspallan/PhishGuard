"""F1–F140 for one record: the single function used by training (ml/) and by the live API.

URL records get F1–F95 (F96–F140 MISSING); email records get F96–F140 (F1–F95 MISSING), as
decided in P2-b. Header features read the raw email; text features read the time-normalised
email (Docs/decisions.md, 2026-11-02).
"""

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from importlib.resources import files
from urllib.parse import urlsplit

from phishguard.services.features import (
    domain_ssl,
    email_headers,
    html_js,
    nlp_text,
    url_lexical,
)
from phishguard.services.features.email_normalise import normalise_time_clues
from phishguard.services.features.email_parts import parse
from phishguard.services.features.missing import MISSING

FEATURE_NAMES: tuple[str, ...] = (
    url_lexical.FEATURE_NAMES
    + domain_ssl.FEATURE_NAMES
    + html_js.FEATURE_NAMES
    + email_headers.FEATURE_NAMES
    + nlp_text.FEATURE_NAMES
)
URL_FEATURE_COUNT = 95  # F1–F95
EMAIL_FEATURE_COUNT = 45  # F96–F140
AGE_SENSITIVE: tuple[str, ...] = email_headers.AGE_SENSITIVE


@dataclass(frozen=True)
class UrlEvidence:
    """Everything stored for one URL at collection time (see the snapshot collector)."""

    url: str
    captured_at: datetime
    html: str | None = None  # page body, None if offline / not HTML / not fetched
    final_url: str | None = None  # after redirects
    dns: dict | None = None
    tls: dict | None = None
    rdap: dict | None = None


def url_features(evidence: UrlEvidence, tranco_ranks: Mapping[str, int]) -> list[float]:
    try:
        host = urlsplit(evidence.url.strip()).hostname or ""
    except ValueError:
        host = ""
    values = (
        url_lexical.extract(evidence.url)
        + domain_ssl.extract(
            host,
            rdap=evidence.rdap,
            dns=evidence.dns,
            tls=evidence.tls,
            reference_time=evidence.captured_at,
            tranco_ranks=tranco_ranks,
        )
        + html_js.extract(evidence.html, evidence.final_url or evidence.url)
        + [MISSING] * EMAIL_FEATURE_COUNT
    )
    assert len(values) == len(FEATURE_NAMES)
    return values


def email_features(raw_email: str, tranco_ranks: Mapping[str, int]) -> list[float]:
    values = (
        [MISSING] * URL_FEATURE_COUNT
        + email_headers.extract(parse(raw_email), tranco_ranks)
        + nlp_text.extract(parse(normalise_time_clues(raw_email)))
    )
    assert len(values) == len(FEATURE_NAMES)
    return values


def feature_code_hash() -> str:
    """SHA-256 over the feature code and data files: changes whenever any feature could change.

    Stored with every feature matrix and model (Phase 3 registry), so a model is never used with
    features computed by different code.
    """
    package = files("phishguard.services.features")
    digest = hashlib.sha256()
    for name in sorted(p.name for p in package.iterdir() if p.name.endswith(".py")):
        digest.update(name.encode())
        digest.update((package / name).read_bytes())
    for name in sorted(p.name for p in (package / "data").iterdir() if p.name.endswith(".txt")):
        digest.update(name.encode())
        digest.update((package / "data" / name).read_bytes())
    return digest.hexdigest()
