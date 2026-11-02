"""Robust access to the parts of an email that the header and text features need.

Real phishing mail has broken headers (e.g. `To:\tunlisted-recipients:; (no To-header on
input)`) that make the email package raise on access. Headers are therefore read with
`raw_items()` (no parsing) and unfolded here; decoding is done per value inside try blocks.
"""

import email
import email.policy
import re
from dataclasses import dataclass, field
from email.header import decode_header, make_header
from email.message import EmailMessage
from email.utils import getaddresses, parseaddr

_FOLD = re.compile(r"\r?\n[ \t]+")


@dataclass
class EmailParts:
    headers: list[tuple[str, str]]  # (lower-case name, unfolded raw value), in order
    plain: list[str] = field(default_factory=list)  # decoded text/plain bodies
    html: list[str] = field(default_factory=list)  # decoded text/html bodies
    attachments: list[str] = field(default_factory=list)  # lower-case file names

    def all(self, name: str) -> list[str]:
        return [v for n, v in self.headers if n == name]

    def first(self, name: str) -> str | None:
        values = self.all(name)
        return values[0] if values else None


def decode_words(value: str) -> str:
    """RFC 2047 encoded words (=?utf-8?...?=) to text; the raw value if that fails."""
    try:
        return str(make_header(decode_header(value)))
    except Exception:  # malformed encoded words or unknown charsets
        return value


def address(value: str | None) -> tuple[str, str]:
    """(decoded display name, lower-case address) of the first address in a header value."""
    if not value:
        return "", ""
    try:
        pairs = getaddresses([value])
    except Exception:
        pairs = [parseaddr(value)]
    name, addr = pairs[0] if pairs else ("", "")
    return decode_words(name).strip(), addr.strip().lower()


def domain_of_address(addr: str) -> str:
    return addr.rsplit("@", 1)[1].strip(">").strip() if "@" in addr else ""


def _body_text(part: EmailMessage) -> str:
    try:
        return part.get_content()
    except Exception:
        payload = part.get_payload(decode=True)
        return payload.decode("utf-8", errors="replace") if isinstance(payload, bytes) else ""


def parse(raw: str) -> EmailParts:
    message = email.message_from_bytes(
        raw.encode("utf-8", errors="surrogateescape"), policy=email.policy.default
    )
    headers = [(n.strip().lower(), _FOLD.sub(" ", str(v)).strip()) for n, v in message.raw_items()]
    parts = EmailParts(headers=headers)
    for part in message.walk():
        try:
            name = part.get_filename()
            disposition = part.get_content_disposition()
            content_type = part.get_content_type()
        except Exception:  # unparsable Content-Type / Content-Disposition: skip this part
            continue
        if name or disposition == "attachment":
            parts.attachments.append((name or "").lower())
        elif content_type == "text/plain":
            parts.plain.append(_body_text(part))
        elif content_type == "text/html":
            parts.html.append(_body_text(part))
    return parts
