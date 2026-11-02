"""Word lists shared by dataset labelling (ml/) and feature extraction (Phase 2).

Kept in one place so the labelling rules (decision D1) and the features use the same lists.
Changing a list changes both the labels and the features: record it in Docs/decisions.md.
"""

# Brands commonly impersonated in phishing. Each maps to the registered domains it really owns,
# so "brand named but domain is not the brand's" can be checked.
BRAND_DOMAINS: dict[str, frozenset[str]] = {
    "paypal": frozenset({"paypal.com", "paypal.me"}),
    "apple": frozenset({"apple.com", "icloud.com"}),
    "microsoft": frozenset({"microsoft.com", "live.com", "outlook.com", "office.com"}),
    "office365": frozenset({"office.com", "microsoft.com"}),
    "outlook": frozenset({"outlook.com", "live.com", "microsoft.com"}),
    "google": frozenset({"google.com", "gmail.com"}),
    "gmail": frozenset({"gmail.com", "google.com"}),
    "amazon": frozenset({"amazon.com", "amazon.co.uk", "amazon.de"}),
    "netflix": frozenset({"netflix.com"}),
    "facebook": frozenset({"facebook.com", "fb.com"}),
    "instagram": frozenset({"instagram.com"}),
    "whatsapp": frozenset({"whatsapp.com"}),
    "linkedin": frozenset({"linkedin.com"}),
    "dropbox": frozenset({"dropbox.com"}),
    "docusign": frozenset({"docusign.com", "docusign.net"}),
    "adobe": frozenset({"adobe.com"}),
    "dhl": frozenset({"dhl.com"}),
    "fedex": frozenset({"fedex.com"}),
    "ups": frozenset({"ups.com"}),
    "usps": frozenset({"usps.com"}),
    "chase": frozenset({"chase.com"}),
    "wellsfargo": frozenset({"wellsfargo.com"}),
    "bankofamerica": frozenset({"bankofamerica.com"}),
    "americanexpress": frozenset({"americanexpress.com"}),
    "visa": frozenset({"visa.com"}),
    "mastercard": frozenset({"mastercard.com"}),
    "ebay": frozenset({"ebay.com"}),
    "steam": frozenset({"steampowered.com", "steamcommunity.com"}),
    "coinbase": frozenset({"coinbase.com"}),
    "binance": frozenset({"binance.com"}),
    "metamask": frozenset({"metamask.io"}),
    "yahoo": frozenset({"yahoo.com"}),
    "aol": frozenset({"aol.com"}),
    "att": frozenset({"att.com"}),
    "irs": frozenset({"irs.gov"}),
}

# File extensions that usually mean malware delivery (feature F38, F113; rule "malware").
RISKY_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".msi", ".vbs", ".js", ".jse",
        ".wsf", ".hta", ".jar", ".apk", ".ps1", ".lnk", ".iso", ".img", ".zip", ".rar",
        ".7z", ".docm", ".xlsm", ".pptm",
    }
)  # fmt: skip

# Phrases asking the reader to sign in or confirm an account (rule "credential_harvest").
CREDENTIAL_PHRASES: tuple[str, ...] = (
    "sign in",
    "log in",
    "login",
    "password",
    "verify your account",
    "confirm your account",
    "update your account",
    "verify your identity",
    "account verification",
    "validate your account",
)

# Words in a URL that suggest a login or account page (features F41, F42).
SENSITIVE_URL_WORDS: tuple[str, ...] = (
    "login",
    "signin",
    "logon",
    "verify",
    "secure",
    "account",
    "update",
    "banking",
    "confirm",
    "password",
    "webscr",
)
