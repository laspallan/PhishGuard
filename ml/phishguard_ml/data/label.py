"""Step 6: attack categories by ordered rules (decision D1). First matching rule wins:

1. malware             risky file extension in the URL path / an attachment, or URL on URLhaus
2. brand_impersonation a known brand is named but the registered domain is not that brand's,
                       or PhishTank names a target brand for the URL (not "Other")
3. credential_harvest  page has a password field or login form; email asks to sign in/verify
4. spear               email greets the recipient or names their organisation
5. unknown             none of the above

Legitimate samples are never given a category. The word lists live in
phishguard.services.features.lexicons, shared with feature extraction (Phase 2).
"""

import re
from collections import Counter
from collections.abc import Iterable
from email.message import EmailMessage
from email.utils import getaddresses
from pathlib import PurePosixPath
from urllib.parse import urlsplit

from phishguard.models.enums import AttackCategory, Label, Modality
from phishguard.services.features.lexicons import (
    BRAND_DOMAINS,
    CREDENTIAL_PHRASES,
    RISKY_EXTENSIONS,
)
from phishguard_ml.data import clean
from phishguard_ml.data.records import SampleRecord

_PASSWORD_INPUT = re.compile(r"<input[^>]+type\s*=\s*[\"']?password", re.IGNORECASE)
_FORM = re.compile(r"<form\b", re.IGNORECASE)
_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_WORD = re.compile(r"[a-z0-9]+")


def _brand_mismatch(text: str, domain: str) -> bool:
    words = set(_WORD.findall(text.lower()))
    compact = re.sub(r"[^a-z0-9]", "", text.lower())
    for brand, owned in BRAND_DOMAINS.items():
        named = brand in words or (len(brand) >= 5 and brand in compact)
        if named and domain not in owned:
            return True
    return False


def _risky_path(url: str) -> bool:
    return PurePosixPath(urlsplit(url).path.lower()).suffix in RISKY_EXTENSIONS


def _has_credential_phrase(text: str) -> bool:
    lowered = text.lower()
    return any(phrase in lowered for phrase in CREDENTIAL_PHRASES)


def label_url(
    url: str,
    html: str | None,
    urlhaus: frozenset[str] = frozenset(),
    phishtank_target: str | None = None,
) -> AttackCategory:
    normalised = clean.normalise_url(url) or url
    if _risky_path(normalised) or normalised in urlhaus:
        return AttackCategory.MALWARE
    if phishtank_target:
        return AttackCategory.BRAND_IMPERSONATION
    domain = clean.registered_domain(urlsplit(normalised).hostname or "")
    title_match = _TITLE.search(html or "")
    title = title_match.group(1) if title_match else ""
    if _brand_mismatch(
        f"{urlsplit(normalised).netloc} {urlsplit(normalised).path} {title}", domain
    ):
        return AttackCategory.BRAND_IMPERSONATION
    if html and (
        _PASSWORD_INPUT.search(html) or (_FORM.search(html) and _has_credential_phrase(html))
    ):
        return AttackCategory.CREDENTIAL_HARVEST
    return AttackCategory.UNKNOWN


def _attachment_names(message: EmailMessage) -> list[str]:
    names = []
    for part in message.walk():
        try:
            name = part.get_filename()
        except Exception:  # unparsable Content-Disposition / Content-Type
            continue
        if name:
            names.append(name.lower())
    return names


def _recipient(message: EmailMessage) -> tuple[str | None, str | None]:
    """(first name, organisation word from the address domain) of the first To recipient."""
    try:
        pairs = getaddresses([clean.header(message, "To")])
    except Exception:
        return None, None
    for display, address in pairs:
        first = display.strip().split()[0].strip(",\"'").lower() if display.strip() else None
        org = address.split("@")[-1].split(".")[0].lower() if "@" in address else None
        return (first if first and len(first) > 2 else None), (
            org if org and len(org) > 3 else None
        )
    return None, None


def label_email(message: EmailMessage) -> AttackCategory:
    if any(PurePosixPath(n).suffix in RISKY_EXTENSIONS for n in _attachment_names(message)):
        return AttackCategory.MALWARE
    subject = clean.header(message, "Subject")
    body = clean.body_text(message)
    sender = clean.sender_address(message) or ""
    sender_domain = clean.registered_domain(sender.split("@")[-1]) if "@" in sender else ""
    display = clean.header(message, "From")
    if _brand_mismatch(f"{display} {subject} {body[:2000]}", sender_domain):
        return AttackCategory.BRAND_IMPERSONATION
    if _has_credential_phrase(f"{subject} {body}"):
        return AttackCategory.CREDENTIAL_HARVEST
    first_name, organisation = _recipient(message)
    opening = body[:300].lower()
    if (first_name and re.search(rf"\b{re.escape(first_name)}\b", opening)) or (
        organisation and organisation in opening
    ):
        return AttackCategory.SPEAR
    return AttackCategory.UNKNOWN


def label_record(
    record: SampleRecord,
    html: str | None = None,
    urlhaus: frozenset[str] = frozenset(),
    phishtank_targets: dict[str, str] | None = None,
) -> SampleRecord:
    if record.label is Label.LEGITIMATE:
        return record
    if record.sample_type is Modality.URL:
        target = (phishtank_targets or {}).get(clean.normalise_url(record.raw_content) or "")
        category = label_url(record.raw_content, html, urlhaus, target)
    else:
        category = label_email(clean.parse_email(record.raw_content.encode("utf-8")))
    return record.model_copy(update={"attack_category": category})


def category_counts(records: Iterable[SampleRecord]) -> Counter:
    return Counter(
        f"{r.sample_type.value}:{r.attack_category.value}"
        for r in records
        if r.attack_category is not None
    )
