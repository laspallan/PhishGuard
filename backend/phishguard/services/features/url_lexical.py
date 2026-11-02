"""F1–F45: URL lexical features, computed from the URL string alone (no network, no page).

Definitions where Docs/features.md leaves room (decided here, used everywhere):
- The URL is taken as given (surrounding whitespace removed); it is not normalised first.
- "hostname" is the lower-cased host without port; for IPv6 without the brackets.
- F23/F24 subdomain = labels before the registered domain (eTLD+1), "www" included.
- F25 tld_length = length of the last host label (e.g. "uk" in example.co.uk), not of the
  public suffix "co.uk"; missing for IP addresses.
- F31 has_mixed_script = one host label mixes letters of two scripts (e.g. Latin "pp" with a
  Cyrillic "а"). Checked per label, so an all-Cyrillic name under ".com" is not mixed.
  Punycode labels are decoded first.
- F34/F35 tokens = runs of letters and digits in the whole URL (scheme included).
- F39/F40/F41/F42 word matching is case-insensitive; a brand counts when it is a whole token,
  or (brands of 5+ letters) a substring of the text with separators removed, as in labelling.
- A URL that cannot be parsed, or has no host, gets MISSING for every feature.
"""

import math
import re
import unicodedata
from collections import Counter
from pathlib import PurePosixPath
from urllib.parse import SplitResult, urlsplit

from phishguard.services.features.hosts import is_ip, split_host
from phishguard.services.features.lexicons import (
    BRAND_DOMAINS,
    RISKY_EXTENSIONS,
    SENSITIVE_URL_WORDS,
    SUSPICIOUS_TLDS,
    URL_SHORTENERS,
)
from phishguard.services.features.missing import MISSING

FEATURE_NAMES: tuple[str, ...] = (
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "fragment_length",
    "num_dots",
    "num_hyphens",
    "num_underscores",
    "num_slashes",
    "num_question_marks",
    "num_equals",
    "num_at_symbols",
    "num_ampersands",
    "num_percent",
    "num_tilde",
    "num_digits_url",
    "digit_ratio_url",
    "letter_ratio_url",
    "special_char_ratio",
    "has_ip_address",
    "uses_https",
    "has_port",
    "num_subdomains",
    "subdomain_length",
    "tld_length",
    "suspicious_tld",
    "is_shortened",
    "has_double_slash_redirect",
    "has_http_in_path",
    "has_punycode",
    "has_mixed_script",
    "url_entropy",
    "hostname_entropy",
    "longest_token_length",
    "avg_token_length",
    "num_path_tokens",
    "num_query_params",
    "suspicious_file_extension",
    "brand_in_subdomain",
    "brand_in_path",
    "has_sensitive_word_url",
    "num_sensitive_words_url",
    "hostname_digit_ratio",
    "max_char_repeat",
    "hostname_vowel_ratio",
)

_DEFAULT_PORTS = {"http": 80, "https": 443}
_TOKEN = re.compile(r"[^\W_]+")  # letters and digits (any script)
_WORD = re.compile(r"[a-z0-9]+")
_SEPARATORS = re.compile(r"[^a-z0-9]")
_VOWELS = frozenset("aeiou")


def _flag(condition: bool) -> float:
    return 1.0 if condition else 0.0


def _ratio(part: int, whole: int) -> float:
    return part / whole if whole else MISSING


def entropy(text: str) -> float:
    """Shannon entropy in bits per character; 0 for an empty string."""
    if not text:
        return 0.0
    counts = Counter(text)
    return -sum(n / len(text) * math.log2(n / len(text)) for n in counts.values())


def _has_non_default_port(parts: SplitResult) -> bool:
    try:
        port = parts.port
    except ValueError:  # e.g. "host:99999" or "host:abc": a port is given, and not a standard one
        return True
    return port is not None and port != _DEFAULT_PORTS.get(parts.scheme.lower())


def _script(char: str) -> str | None:
    """First word of the Unicode name ("LATIN", "CYRILLIC", "GREEK", …) for letters."""
    if not char.isalpha():
        return None
    return unicodedata.name(char, "UNKNOWN").split()[0]


def _decode_label(label: str) -> str:
    if label.startswith("xn--"):
        try:
            return label.encode("ascii").decode("idna")
        except UnicodeError:
            return label
    return label


def mixed_script(host: str) -> bool:
    for label in host.split("."):
        scripts = {_script(c) for c in _decode_label(label)} - {None}
        if len(scripts) > 1:
            return True
    return False


def brand_named(text: str) -> bool:
    lowered = text.lower()
    words = set(_WORD.findall(lowered))
    compact = _SEPARATORS.sub("", lowered)
    return any(brand in words or (len(brand) >= 5 and brand in compact) for brand in BRAND_DOMAINS)


def _max_run(text: str) -> int:
    best = run = 0
    previous = None
    for char in text:
        run = run + 1 if char == previous else 1
        best = max(best, run)
        previous = char
    return best


def extract(url: str) -> list[float]:
    """F1–F45 in catalogue order."""
    url = url.strip()
    try:
        parts = urlsplit(url)
    except ValueError:
        return [MISSING] * len(FEATURE_NAMES)
    host = (parts.hostname or "").rstrip(".")
    if not host:
        return [MISSING] * len(FEATURE_NAMES)

    host_parts = split_host(host)
    ip = is_ip(host)
    lowered = url.lower()
    length = len(url)
    digits = sum(c.isdigit() for c in url)
    letters = sum(c.isalpha() for c in url)
    tokens = _TOKEN.findall(url)
    host_letters = [c for c in host if c.isalpha()]
    sensitive = sum(lowered.count(word) for word in SENSITIVE_URL_WORDS)
    last_label = host.rsplit(".", 1)[-1]

    values = [
        length,
        len(host),
        len(parts.path),
        len(parts.query),
        len(parts.fragment),
        url.count("."),
        url.count("-"),
        url.count("_"),
        url.count("/"),
        url.count("?"),
        url.count("="),
        url.count("@"),
        url.count("&"),
        url.count("%"),
        url.count("~"),
        digits,
        _ratio(digits, length),
        _ratio(letters, length),
        _ratio(sum(not c.isalnum() for c in url), length),
        _flag(ip),
        _flag(parts.scheme.lower() == "https"),
        _flag(_has_non_default_port(parts)),
        len(host_parts.subdomain.split(".")) if host_parts.subdomain else 0,
        len(host_parts.subdomain),
        MISSING if ip else len(last_label),
        MISSING if ip else _flag(last_label in SUSPICIOUS_TLDS),
        _flag(host_parts.registered_domain in URL_SHORTENERS or host in URL_SHORTENERS),
        _flag("//" in parts.path),
        _flag("http" in f"{parts.path}?{parts.query}".lower()),
        _flag(any(label.startswith("xn--") for label in host.split("."))),
        _flag(mixed_script(host)),
        entropy(url),
        entropy(host),
        max((len(t) for t in tokens), default=0),
        sum(len(t) for t in tokens) / len(tokens) if tokens else 0.0,
        len([s for s in parts.path.split("/") if s]),
        len([p for p in parts.query.split("&") if p]),
        _flag(PurePosixPath(parts.path.lower()).suffix in RISKY_EXTENSIONS),
        _flag(brand_named(host_parts.subdomain)),
        _flag(brand_named(parts.path)),
        _flag(sensitive > 0),
        sensitive,
        _ratio(sum(c.isdigit() for c in host), len(host)),
        _max_run(url),
        _ratio(sum(c in _VOWELS for c in host_letters), len(host_letters)),
    ]
    return [float(v) for v in values]
