"""Step 3: normalising URLs and emails, grouping keys (decision D4) and de-duplication."""

import email
import email.policy
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from email.message import EmailMessage
from email.utils import getaddresses, parsedate_to_datetime
from urllib.parse import urlsplit, urlunsplit

import tldextract

from phishguard.models.enums import Label
from phishguard_ml.data.records import SampleRecord

# Offline: use only the Public Suffix List snapshot bundled with tldextract.
_extract = tldextract.TLDExtract(suffix_list_urls=())

_DEFAULT_PORTS = {"http": 80, "https": 443}
_WHITESPACE = re.compile(r"\s+")
_TAG = re.compile(r"<[^>]+>")


def normalise_url(raw: str) -> str | None:
    """Canonical form used for hashing; None if this is not a usable http(s) URL.

    Scheme and host are lower-cased, default ports and the #fragment are dropped, an empty
    path becomes "/". Path and query are kept as they are (they are case-sensitive).
    """
    text = raw.strip()
    if not text or any(c.isspace() for c in text):
        return None
    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").rstrip(".")
    if scheme not in _DEFAULT_PORTS or not host:
        return None
    netloc = host if port in (None, _DEFAULT_PORTS[scheme]) else f"{host}:{port}"
    return urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))


def registered_domain(host: str) -> str:
    """eTLD+1 (e.g. evil.co.uk); for IP addresses or unknown suffixes, the host itself."""
    result = _extract(host)
    return result.top_domain_under_public_suffix or host.lower()


def url_group_key(normalised_url: str) -> str:
    return "domain:" + registered_domain(urlsplit(normalised_url).hostname or "")


def parse_email(raw: bytes) -> EmailMessage:
    return email.message_from_bytes(raw, policy=email.policy.default)


def decode_raw(raw: bytes) -> str:
    """Raw email bytes as text (Parquet needs valid UTF-8; undecodable bytes become U+FFFD)."""
    return raw.decode("utf-8", errors="replace")


def header(message: EmailMessage, name: str) -> str:
    try:
        return str(message.get(name, "") or "")
    except Exception:  # malformed headers raise various errors in the email package
        return ""


def sender_address(message: EmailMessage) -> str | None:
    addresses = getaddresses([header(message, "From")])
    for _name, address in addresses:
        if "@" in address:
            return address.strip().lower()
    return None


def message_date(message: EmailMessage):
    try:
        return parsedate_to_datetime(header(message, "Date")).date()
    except (TypeError, ValueError, IndexError, OverflowError):
        return None


def _part_text(part) -> str:
    try:
        return part.get_content()
    except Exception:
        payload = part.get_payload(decode=True) or b""
        return payload.decode("latin-1", errors="replace")


def body_text(message: EmailMessage) -> str:
    """Plain text of the body: text/plain parts, or text/html with tags removed."""
    plain, html = [], []
    for part in message.walk():
        try:
            if part.is_multipart() or part.get_content_disposition() == "attachment":
                continue
            kind = part.get_content_type()
        except Exception:  # unparsable part headers: skip the part
            continue
        if kind == "text/plain":
            plain.append(_part_text(part))
        elif kind == "text/html":
            html.append(_TAG.sub(" ", _part_text(part)))
    return "\n".join(plain) if plain else "\n".join(html)


def email_hash_basis(message: EmailMessage) -> str | None:
    """What two emails must share to count as duplicates: subject + body, whitespace and case
    ignored. None if both are empty (unusable sample)."""
    text = f"{header(message, 'Subject')}\n{body_text(message)}"
    basis = _WHITESPACE.sub(" ", text).strip().lower()
    return basis or None


@dataclass
class DedupReport:
    kept: int = 0
    duplicates: int = 0
    label_conflicts: int = 0
    conflict_ids: list[str] = field(default_factory=list)


def deduplicate(records: Iterable[SampleRecord]) -> tuple[list[SampleRecord], DedupReport]:
    """Keep the first record per sample_id. If the same content appears as both phishing and
    legitimate, the phishing copy is kept (a phishing report is direct evidence)."""
    kept: dict = {}
    report = DedupReport()
    for record in records:
        existing = kept.get(record.sample_id)
        if existing is None:
            kept[record.sample_id] = record
            continue
        report.duplicates += 1
        if existing.label != record.label:
            report.label_conflicts += 1
            report.conflict_ids.append(str(record.sample_id))
            if record.label is Label.PHISHING:
                kept[record.sample_id] = record
    report.kept = len(kept)
    return list(kept.values()), report
