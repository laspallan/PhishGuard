"""F96–F115: email header and structure features, from the raw email (not the time-normalised
view: F109/F110 need the mailer name and dates; evaluation drops the age-sensitive features
AGE_SENSITIVE instead). Definitions decided here:

- F96–F101 read only results the receiving server wrote into the message
  (`Authentication-Results`, and `Received-SPF` for SPF); nothing is re-verified (old DKIM keys
  no longer exist; no live DNS). MISSING when no such result is present. F99 (no DKIM-Signature
  header) is always measurable. F101 reads a `p=` policy given in the dmarc result, e.g.
  "dmarc=pass (p=REJECT ...)"; MISSING if not given.
- Domains are compared as registered domains (eTLD+1). F102 = 0 without Reply-To (normal);
  F103/F108 are MISSING without Return-Path / Message-ID (nothing to compare).
- F107 = 1 if a Received header has no readable date, or a hop is more than one hour earlier than
  the hop before it (clock skew allowed); MISSING without Received headers.
- F110 = 1 if Date is missing or unreadable, or more than 24 hours from the newest Received
  date (the receipt time).
- F113 risky types: the shared RISKY_EXTENSIONS plus .htm/.html/.shtml (named in features.md).
- F114 counts distinct http(s) URLs in the decoded text and HTML bodies.
- F115 = 1 if a link's visible text is itself a URL or domain on another registered domain
  than the link's real target.
"""

import re
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
from pathlib import PurePosixPath
from urllib.parse import urlsplit

from phishguard.services.features.brands import brand_mismatch
from phishguard.services.features.email_parts import (
    EmailParts,
    address,
    domain_of_address,
)
from phishguard.services.features.hosts import split_host
from phishguard.services.features.lexicons import RISKY_EXTENSIONS, SUSPICIOUS_MAILERS
from phishguard.services.features.missing import MISSING

FEATURE_NAMES: tuple[str, ...] = (
    "spf_pass",
    "spf_fail",
    "dkim_pass",
    "dkim_absent",
    "dmarc_pass",
    "dmarc_policy_strict",
    "from_replyto_mismatch",
    "from_returnpath_mismatch",
    "display_name_spoof",
    "sender_in_tranco",
    "num_received_headers",
    "received_chain_inconsistent",
    "message_id_domain_mismatch",
    "suspicious_mailer",
    "date_header_anomaly",
    "html_only",
    "num_attachments",
    "risky_attachment_type",
    "num_urls_in_email",
    "link_text_mismatch",
)

# Features that date an email (proposal Section 3.6.1); evaluation reports results without them.
AGE_SENSITIVE: tuple[str, ...] = (
    "spf_pass",
    "spf_fail",
    "dkim_pass",
    "dkim_absent",
    "dmarc_pass",
    "dmarc_policy_strict",
    "suspicious_mailer",
    "date_header_anomaly",
)

RISKY_ATTACHMENT_EXTENSIONS = RISKY_EXTENSIONS | {".htm", ".html", ".shtml"}
_URL = re.compile(r"https?://[^\s<>\"'()]+", re.IGNORECASE)
_URL_LIKE_TEXT = re.compile(r"^(https?://)?([a-z0-9-]+\.)+[a-z]{2,}(:\d+)?(/\S*)?$", re.IGNORECASE)
_SKEW = timedelta(hours=1)
_DATE_GAP = timedelta(hours=24)


def _flag(condition: bool) -> float:
    return 1.0 if condition else 0.0


def _registered(domain: str) -> str:
    return split_host(domain).registered_domain if domain else ""


def _results(parts: EmailParts, method: str) -> list[str]:
    """`method=result` values (lower case) from Authentication-Results headers."""
    found = []
    for value in parts.all("authentication-results"):
        found += re.findall(rf"\b{method}\s*=\s*([a-z]+)", value.lower())
    return found


def _auth_features(parts: EmailParts) -> list[float]:
    spf = _results(parts, "spf")
    spf += [v.split()[0].lower() for v in parts.all("received-spf") if v.split()]
    dkim = _results(parts, "dkim")
    dmarc = _results(parts, "dmarc")
    policies = []
    for value in parts.all("authentication-results"):
        policies += re.findall(r"dmarc\s*=\s*[a-z]+\s*\(([^)]*)\)", value.lower())
    named = [m.group(1) for p in policies if (m := re.search(r"\bp\s*=\s*([a-z]+)", p))]
    return [
        _flag("pass" in spf) if spf else MISSING,
        _flag(bool({"fail", "softfail"} & set(spf))) if spf else MISSING,
        _flag("pass" in dkim) if dkim else MISSING,
        _flag(not parts.all("dkim-signature")),
        _flag("pass" in dmarc) if dmarc else MISSING,
        _flag(any(p in ("quarantine", "reject") for p in named)) if named else MISSING,
    ]


def _received_date(value: str) -> datetime | None:
    if ";" not in value:
        return None
    try:
        when = parsedate_to_datetime(value.rpartition(";")[2].strip())
    except (TypeError, ValueError, IndexError):
        return None
    return when if when.tzinfo else when.replace(tzinfo=UTC)


def _chain_inconsistent(received: list[str]) -> float:
    if not received:
        return MISSING
    dates = [_received_date(v) for v in received]  # newest first, as in the message
    if any(d is None for d in dates):
        return 1.0
    oldest_first = list(reversed(dates))
    return _flag(any(b < a - _SKEW for a, b in zip(oldest_first, oldest_first[1:], strict=False)))


def _date_anomaly(parts: EmailParts) -> float:
    value = parts.first("date")
    try:
        sent = parsedate_to_datetime(value) if value else None
    except (TypeError, ValueError, IndexError):
        sent = None
    if sent is None:
        return 1.0
    sent = sent if sent.tzinfo else sent.replace(tzinfo=UTC)
    received = [d for v in parts.all("received") if (d := _received_date(v))]
    return _flag(bool(received) and abs(received[0] - sent) > _DATE_GAP)


class _Links(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href") or ""
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._text).strip()))
            self._href = None


def _host_domain(url_or_domain: str) -> str:
    text = url_or_domain if "://" in url_or_domain else f"http://{url_or_domain}"
    try:
        host = urlsplit(text).hostname or ""
    except ValueError:
        return ""
    return _registered(host)


def _link_text_mismatch(html_bodies: list[str]) -> bool:
    for body in html_bodies:
        parser = _Links()
        try:
            parser.feed(body)
        except (AssertionError, ValueError):
            pass
        for href, text in parser.links:
            if text and _URL_LIKE_TEXT.match(text) and href.lower().startswith(("http:", "https:")):
                shown, target = _host_domain(text), _host_domain(href)
                if shown and target and shown != target:
                    return True
    return False


def _mailer_suspicious(parts: EmailParts) -> bool:
    mailer = parts.first("x-mailer") or ""
    return any(pattern.search(mailer) for pattern in SUSPICIOUS_MAILERS)


def extract(parts: EmailParts, tranco_ranks: Mapping[str, int]) -> list[float]:
    """F96–F115 in catalogue order."""
    display, sender = address(parts.first("from"))
    from_domain = _registered(domain_of_address(sender))
    reply_to = address(parts.first("reply-to"))[1]
    return_path = address(parts.first("return-path"))[1]
    message_id = (parts.first("message-id") or "").strip()
    message_id_domain = _registered(domain_of_address(message_id.strip("<>")))
    received = parts.all("received")
    bodies = parts.plain + parts.html
    urls = {u.rstrip(".,;") for body in bodies for u in _URL.findall(body)}
    return [
        *_auth_features(parts),
        _flag(bool(reply_to) and _registered(domain_of_address(reply_to)) != from_domain),
        (
            _flag(_registered(domain_of_address(return_path)) != from_domain)
            if return_path
            else MISSING
        ),
        _flag(brand_mismatch(display, from_domain)),
        _flag(tranco_ranks.get(from_domain, 0) > 0),
        float(len(received)),
        _chain_inconsistent(received),
        _flag(message_id_domain != from_domain) if message_id else MISSING,
        _flag(_mailer_suspicious(parts)),
        _date_anomaly(parts),
        _flag(bool(parts.html) and not parts.plain),
        float(len(parts.attachments)),
        _flag(
            any(PurePosixPath(n).suffix in RISKY_ATTACHMENT_EXTENSIONS for n in parts.attachments)
        ),
        float(len(urls)),
        _flag(_link_text_mismatch(parts.html)),
    ]
