"""F116–F140: text features of an email, computed on the time-normalised email (dates, years and
mailer names replaced, see ml/phishguard_ml/data/email_normalise.py). Definitions decided here:

- Body = the decoded text/plain parts; if there are none, the visible text of the HTML parts
  (outside <script>/<style>). URLs are removed from the body before word-based features, so a
  long link does not count as words or spelling errors. Text = subject + body.
- Words = runs of letters (any script), with an inner apostrophe allowed. Lower-cased for
  matching. Terms and phrases from the lexicons are matched as whole words.
- F116 counts brand-name tokens in the text; F117–F121, F123, F132 count term occurrences.
- F122 generic greeting = a GENERIC_GREETINGS phrase within the first 100 characters of the body.
- F124 = subject starts with RE:/FW:/FWD: but the email has no In-Reply-To or References header.
- F127 uppercase letters / letters; F137 non-ASCII characters / all characters (body).
- F129 = words of 2+ letters unknown to pyspellchecker's English list / such words. Brand names
  are not errors. Non-English emails therefore score high (a known limit).
- F130 Flesch reading ease = 206.835 − 1.015·(words/sentences) − 84.6·(syllables/words);
  syllables = vowel groups (a e i o u y) per word, minus a silent final "e", at least 1;
  sentences = runs ending in . ! ? (at least 1).
- F133 = VADER compound score (−1..1) of the first 20,000 characters of the body.
- F135 counts $ € £ ¥ ₹ and the codes USD EUR GBP BTC; F136 counts phone-like numbers (9–15
  digits, optional +, spaces, dots, dashes, brackets).
- F138 phishing_lexicon_score = 100 · (urgency + threat + reward + financial + call-to-action
  + 2 · credential terms) / words: a fixed formula, weights chosen before training, not tuned.
- F139 deadline = "within N hours/days/minutes", "N hours/days left/remaining", "by
  today/tomorrow/tonight/end of day", "expires today/tomorrow/in N".
- F140 = a brand is named in the text but the From address is not on that brand's domain.
- Ratios with nothing to divide by (no words, no letters, empty body) are MISSING.
"""

import re
from html.parser import HTMLParser

from spellchecker import SpellChecker
from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer

from phishguard.services.features.brands import brand_mismatch
from phishguard.services.features.email_parts import (
    EmailParts,
    address,
    decode_words,
    domain_of_address,
)
from phishguard.services.features.hosts import split_host
from phishguard.services.features.lexicons import (
    BRAND_DOMAINS,
    CALL_TO_ACTION_PHRASES,
    CREDENTIAL_PHRASES,
    FINANCIAL_TERMS,
    GENERIC_GREETINGS,
    REWARD_TERMS,
    THREAT_TERMS,
    URGENCY_TERMS,
)
from phishguard.services.features.missing import MISSING

FEATURE_NAMES: tuple[str, ...] = (
    "num_brand_mentions",
    "num_urgency_terms",
    "num_threat_terms",
    "num_reward_terms",
    "num_credential_terms",
    "num_financial_terms",
    "generic_greeting",
    "subject_urgency_terms",
    "fake_reply_subject",
    "subject_length",
    "word_count",
    "uppercase_ratio",
    "exclamation_count",
    "spelling_error_ratio",
    "readability_score",
    "avg_sentence_length",
    "call_to_action_count",
    "sentiment_polarity",
    "lexical_diversity",
    "num_currency_symbols",
    "num_phone_numbers",
    "non_ascii_ratio",
    "phishing_lexicon_score",
    "deadline_mention",
    "brand_sender_mismatch",
)

_URL = re.compile(r"https?://\S+|www\.\S+", re.IGNORECASE)
_WORD = re.compile(r"[^\W\d_]+(?:'[^\W\d_]+)?")
_SENTENCE = re.compile(r"[^.!?]+[.!?]*")
_VOWEL_GROUP = re.compile(r"[aeiouy]+")
_REPLY = re.compile(r"^\s*(re|fw|fwd)\s*:", re.IGNORECASE)
_CURRENCY = re.compile(r"[$€£¥₹]|\b(?:USD|EUR|GBP|BTC)\b")
_PHONE = re.compile(r"(?<![\w+])\+?\(?\d[\d\s().-]{7,}\d(?!\w)")
_DEADLINE = re.compile(
    r"\bwithin\s+\d+\s*(?:hours?|hrs?|days?|minutes?|mins?)\b"
    r"|\b\d+\s*(?:hours?|days?)\s+(?:left|remaining)\b"
    r"|\bby\s+(?:today|tomorrow|tonight|end\s+of\s+(?:the\s+)?day)\b"
    r"|\bexpires?\s+(?:today|tomorrow|in\s+\d+)",
    re.IGNORECASE,
)
_SENTIMENT_CHARS = 20_000
_spell = SpellChecker(language="en")
_sentiment = SentimentIntensityAnalyzer()


def _phrase_pattern(phrases: tuple[str, ...]) -> re.Pattern[str]:
    alternatives = sorted((re.escape(p) for p in phrases), key=len, reverse=True)
    return re.compile(r"(?<!\w)(?:" + "|".join(alternatives) + r")(?!\w)", re.IGNORECASE)


_URGENCY = _phrase_pattern(URGENCY_TERMS)
_THREAT = _phrase_pattern(THREAT_TERMS)
_REWARD = _phrase_pattern(REWARD_TERMS)
_CREDENTIAL = _phrase_pattern(CREDENTIAL_PHRASES)
_FINANCIAL = _phrase_pattern(FINANCIAL_TERMS)
_CTA = _phrase_pattern(CALL_TO_ACTION_PHRASES)
_GREETING = _phrase_pattern(GENERIC_GREETINGS)


class _VisibleText(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.chunks: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip += 1

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if not self._skip:
            self.chunks.append(data)


def visible_text(html: str) -> str:
    parser = _VisibleText()
    try:
        parser.feed(html)
        parser.close()
    except (AssertionError, ValueError):
        pass
    return " ".join(parser.chunks)


def body_text(parts: EmailParts) -> str:
    if parts.plain:
        return "\n".join(parts.plain)
    return "\n".join(visible_text(h) for h in parts.html)


def syllables(word: str) -> int:
    word = word.lower()
    count = len(_VOWEL_GROUP.findall(word))
    if word.endswith("e") and not word.endswith(("le", "ee")) and count > 1:
        count -= 1
    return max(count, 1)


def _ratio(part: float, whole: float) -> float:
    return part / whole if whole else MISSING


def _flag(condition: bool) -> float:
    return 1.0 if condition else 0.0


def extract(parts: EmailParts) -> list[float]:
    """F116–F140 in catalogue order, from the parts of the time-normalised email."""
    subject = decode_words(parts.first("subject") or "")
    raw_body = body_text(parts)
    body = _URL.sub(" ", raw_body)
    text = f"{subject}\n{body}"
    words = _WORD.findall(body)
    lowered = [w.lower() for w in words]
    letters = [c for c in body if c.isalpha()]
    sentences = [s for s in _SENTENCE.findall(body) if _WORD.search(s)] or [body]
    from_domain = split_host(domain_of_address(address(parts.first("from"))[1])).registered_domain

    counts = {
        name: len(pattern.findall(text))
        for name, pattern in (
            ("urgency", _URGENCY),
            ("threat", _THREAT),
            ("reward", _REWARD),
            ("credential", _CREDENTIAL),
            ("financial", _FINANCIAL),
            ("cta", _CTA),
        )
    }
    checkable = [w for w in lowered if len(w) >= 2 and w not in BRAND_DOMAINS]
    misspelled = _spell.unknown(checkable)
    n_words = len(words)
    readability = (
        206.835
        - 1.015 * (n_words / len(sentences))
        - 84.6 * (sum(syllables(w) for w in words) / n_words)
        if n_words
        else MISSING
    )
    lexicon = (
        counts["urgency"]
        + counts["threat"]
        + counts["reward"]
        + counts["financial"]
        + counts["cta"]
        + 2 * counts["credential"]
    )
    values = [
        sum(1 for w in _WORD.findall(text.lower()) if w in BRAND_DOMAINS),
        counts["urgency"],
        counts["threat"],
        counts["reward"],
        counts["credential"],
        counts["financial"],
        _flag(bool(_GREETING.search(body.strip()[:100]))),
        len(_URGENCY.findall(subject)),
        _flag(
            bool(_REPLY.match(subject))
            and not parts.first("in-reply-to")
            and not parts.first("references")
        ),
        len(subject),
        n_words,
        _ratio(sum(c.isupper() for c in letters), len(letters)),
        text.count("!"),
        _ratio(sum(1 for w in checkable if w in misspelled), len(checkable)),
        readability,
        _ratio(n_words, len(sentences)) if n_words else MISSING,
        counts["cta"],
        _sentiment.polarity_scores(body[:_SENTIMENT_CHARS])["compound"]
        if body.strip()
        else MISSING,
        _ratio(len(set(lowered)), n_words),
        len(_CURRENCY.findall(text)),
        sum(1 for m in _PHONE.findall(text) if 9 <= sum(c.isdigit() for c in m) <= 15),
        _ratio(sum(ord(c) > 127 for c in raw_body), len(raw_body)),
        _ratio(100 * lexicon, n_words),
        _flag(bool(_DEADLINE.search(text))),
        _flag(brand_mismatch(text, from_domain)),
    ]
    return [float(v) for v in values]
