"""The exact text the LSTM, CNN and DistilBERT read, for training and for live scans (Phase 3).

It lives outside `services/features` on purpose: `feature_code_hash` covers that package, and
this file is not a feature, so changing it must not mark the tabular models as stale.

- url / text_full   the URL as collected
- url / text_host   scheme and host only (D10c: legitimate Tranco URLs are mostly home pages, so a
                    model on the full URL can learn "has a path means phishing")
- email / text_body subject and body after the time-clue normaliser, no other headers (Enron has
                    no delivery headers, so they would identify the dataset, not phishing)
"""

import hashlib
import re
from pathlib import Path
from urllib.parse import urlsplit

from phishguard.services.features import email_parts
from phishguard.services.features.email_normalise import YEAR, normalise_time_clues
from phishguard.services.features.nlp_text import body_text

# Words that name a dataset, not phishing (development rows, 2026-11-06, share of legitimate /
# phishing emails): enron 37.5% / 0%, ect 7.6% / 0%, hou 6.6% / 0% (Enron and its mail tags); jose
# 0.6% / 19.5%, monkey 0.1% / 16.4% (jose@monkey.org, the owner of the Nazario corpus). A text model
# would otherwise score well by recognising the source. Years are removed for the same reason:
# after the normaliser, the <YEAR> placeholder itself was in 56% / 18% of the emails.
_CORPUS_WORDS = re.compile(r"\b(?:enron|ect|hou|jose|monkey)\b", re.IGNORECASE)
_SPACES = re.compile(r"[ \t]+")

TEXT_INPUTS: dict[str, tuple[str, ...]] = {
    "url": ("text_full", "text_host"),
    "email": ("text_body",),
}


def url_host_text(url: str) -> str:
    """Scheme and host; user info is dropped because it is not where the site is."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return ""
    return f"{parts.scheme}://{parts.netloc.rpartition('@')[2].lower()}"


def email_text(raw_email: str) -> str:
    parts = email_parts.parse(normalise_time_clues(raw_email))
    subject = email_parts.decode_words(parts.first("subject") or "")
    text = YEAR.sub("", f"{subject}\n{body_text(parts)}").replace("<YEAR>", "")
    # Bytes that were not valid text arrive as lone surrogates, which cannot be saved as UTF-8.
    text = text.encode("utf-8", "replace").decode("utf-8")
    return _SPACES.sub(" ", _CORPUS_WORDS.sub("<ORG>", text)).strip()


def text_for(modality: str, text_input: str, raw_content: str) -> str:
    if text_input not in TEXT_INPUTS.get(modality, ()):
        raise ValueError(f"unknown text input {text_input!r} for {modality!r}")
    if text_input == "text_body":
        return email_text(raw_content)
    return url_host_text(raw_content) if text_input == "text_host" else raw_content


def text_code_hash() -> str:
    """Recorded with each text model, like `feature_code_hash` for the tabular models."""
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
