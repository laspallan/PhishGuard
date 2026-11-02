"""Step 4: remove time clues from emails (proposal Section 3.6.1).

The legitimate corpora (Enron 2001-2002, SpamAssassin 2002-2005) are much older than the
phishing emails, so a model could learn "old vs new" instead of "legitimate vs phishing".
This normaliser is applied before feature extraction and text-model training:

- Date and Delivery-Date header values  -> <DATE>
- the timestamp after ";" in Received   -> <DATE>
- X-Mailer, User-Agent, X-MimeOLE       -> <MAILER>   (mail-client names date an email)
- years 1990-2039 in Subject and body   -> <YEAR>

Raw records keep the original text; this is a view used by later phases.
"""

import re

DATE_HEADERS = frozenset({"date", "delivery-date"})
MAILER_HEADERS = frozenset({"x-mailer", "user-agent", "x-mimeole"})
YEAR = re.compile(r"(?<![0-9])(?:199[0-9]|20[0-3][0-9])(?![0-9])")
_HEADER_END = re.compile(r"\r?\n\r?\n")


def _split(raw: str) -> tuple[str, str, str]:
    match = _HEADER_END.search(raw)
    if not match:
        return raw, "", ""
    return raw[: match.start()], match.group(0), raw[match.end() :]


def _logical_headers(block: str) -> list[str]:
    """Header lines with folded continuation lines kept attached to their header."""
    headers: list[str] = []
    for line in block.splitlines(keepends=True):
        if line[:1] in (" ", "\t") and headers:
            headers[-1] += line
        else:
            headers.append(line)
    return headers


def _normalise_header(header: str) -> str:
    name, sep, value = header.partition(":")
    if not sep:
        return header
    key = name.strip().lower()
    ending = "\r\n" if header.endswith("\r\n") else "\n" if header.endswith("\n") else ""
    if key in DATE_HEADERS:
        return f"{name}: <DATE>{ending}"
    if key in MAILER_HEADERS:
        return f"{name}: <MAILER>{ending}"
    if key == "received" and ";" in value:
        before, _, _ = value.rpartition(";")
        return f"{name}:{before}; <DATE>{ending}"
    if key == "subject":
        return YEAR.sub("<YEAR>", header)
    return header


def normalise_time_clues(raw: str) -> str:
    header_block, separator, body = _split(raw)
    headers = "".join(_normalise_header(h) for h in _logical_headers(header_block))
    return headers + separator + YEAR.sub("<YEAR>", body)
