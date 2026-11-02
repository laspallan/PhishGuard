"""Finding known brand names in text (features F39, F40, F88, F89, F104, F116, F140).

A brand counts when it is a whole token, or (brands of 5+ letters) a substring of the text with
separators removed, so "paypal-secure" and "secure-paypal.com" both name PayPal. The same rule
as the dataset labeller (decision D1).
"""

import re

from phishguard.services.features.lexicons import BRAND_DOMAINS

_WORD = re.compile(r"[a-z0-9]+")
_SEPARATORS = re.compile(r"[^a-z0-9]")


def brands_named(text: str) -> set[str]:
    lowered = text.lower()
    words = set(_WORD.findall(lowered))
    compact = _SEPARATORS.sub("", lowered)
    return {
        brand for brand in BRAND_DOMAINS if brand in words or (len(brand) >= 5 and brand in compact)
    }


def brand_named(text: str) -> bool:
    return bool(brands_named(text))


def brand_mismatch(text: str, registered_domain: str) -> bool:
    """A brand is named in the text but the domain is not one the brand owns."""
    return any(registered_domain not in BRAND_DOMAINS[b] for b in brands_named(text))
