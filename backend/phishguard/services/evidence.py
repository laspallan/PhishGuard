"""One builder from collected URL evidence to `UrlEvidence` (decision D11, step 2).

Used by the training feature matrix (ml/phishguard_ml/features/matrix.py, from the stored
snapshot files) and by the live scan path (from the evidence collector's answer, which has the
same parts in the same format). So a URL gets the same 140 values in training and in the API.

This module lives outside `phishguard.services.features` on purpose: it only assembles inputs,
and `feature_code_hash` covers the feature code alone.

The evidence parts are what the snapshot collector stores:
  meta  dict from meta.json (fetched_at, final_url, content_type, ...), or None
  page  raw page bytes (page.html), or None
  dns   dict from dns.json, or None
  tls   dict from tls.json, or None
  rdap  dict from data/rdap/<rdap_domain(url)>.json, or None
"""

import base64
import codecs
import re
from datetime import datetime
from urllib.parse import parse_qsl, urlsplit

from phishguard.services.features.extractor import UrlEvidence
from phishguard.services.features.hosts import split_host

# The evidence collector's Celery task and queue (Docs/live_url_scanning.md, section 2).
EVIDENCE_TASK = "phishguard.collect_evidence"
EVIDENCE_QUEUE = "evidence"
STAGE_NO_TARGET_CONTACT = 1  # DNS only: resolvers, never the target host
STAGE_FETCH = 2  # + page and TLS: the target host

_SECRET_NAME = re.compile(
    r"token|session|auth|otp|ticket|reset|passw|secret|signature"
    r"|(^|[^a-z])(code|key|sid|sig)($|[^a-z])"
)
_LONG_RANDOM = re.compile(r"[A-Za-z0-9_\-+/=%.]{32,}")


def is_safe_to_fetch(url: str) -> bool:
    """False if a GET could use up or expose a secret (decision D11d): one-time login links,
    password resets, unsubscribe confirmations. Such URLs never reach stage 2."""
    try:
        parts = urlsplit(url)
        if parts.username or parts.password:
            return False
    except ValueError:
        return False
    for name, value in parse_qsl(parts.query, keep_blank_values=True):
        if _SECRET_NAME.search(name.lower()) or _LONG_RANDOM.fullmatch(value):
            return False
    return True


def page_charset(content_type: str | None) -> str:
    """The charset named in a Content-Type header, if Python knows it; else UTF-8."""
    for part in (content_type or "").split(";"):
        key, _, value = part.strip().partition("=")
        if key.lower() == "charset" and value:
            try:
                return codecs.lookup(value.strip("\"' ")).name
            except LookupError:
                break
    return "utf-8"


def rdap_domain(url: str) -> str:
    """The registered domain whose RDAP record belongs to this URL ("" if none)."""
    try:
        host = urlsplit(url.strip()).hostname or ""
    except ValueError:
        return ""
    return split_host(host).registered_domain if host else ""


def build_url_evidence(
    url: str,
    collected_at: datetime,
    *,
    meta: dict | None,
    page: bytes | None,
    dns: dict | None,
    tls: dict | None,
    rdap: dict | None,
) -> UrlEvidence:
    """Assemble the evidence. Ages are measured from when the page was fetched (meta
    `fetched_at`), or from `collected_at` when there is no fetch time."""
    meta = meta or {}
    captured = meta.get("fetched_at")
    html = (
        page.decode(page_charset(meta.get("content_type")), errors="replace")
        if page is not None
        else None
    )
    return UrlEvidence(
        url=url,
        captured_at=datetime.fromisoformat(captured) if captured else collected_at,
        html=html,
        final_url=meta.get("final_url"),
        dns=dns,
        tls=tls,
        rdap=rdap,
    )


def evidence_from_answer(url: str, collected_at: datetime, answer: dict) -> UrlEvidence:
    """UrlEvidence from the collector's answer (JSON, so the page bytes are in base64)."""
    encoded = answer.get("page_b64")
    return build_url_evidence(
        url,
        collected_at,
        meta=answer.get("meta"),
        page=base64.b64decode(encoded) if encoded is not None else None,
        dns=answer.get("dns"),
        tls=answer.get("tls"),
        rdap=None,  # the deployed models do not use RDAP (D11c)
    )
