"""Word lists shared by dataset labelling (ml/) and feature extraction (Phase 2).

Kept in one place so the labelling rules (decision D1) and the features use the same lists.
Changing a list changes both the labels and the features: record it in Docs/decisions.md.
"""

import re
from importlib.resources import files

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

# TLDs often abused for phishing (feature F26), lower case, without the dot. The 20 TLDs with the
# highest Phishing Domain Score (phishing domains per 10,000 domains in the TLD; TLDs with at
# least 30,000 domains and 25 phishing domains), Table 2 of Interisle Consulting Group,
# "Phishing Activity in TLDs, May 2025 - April 2026",
# https://www.cybercrimeinfocenter.org/phishing-activity-in-tlds-may-april-2026 (read 2026-11-02).
# The score table is used, not the count table, which ranks big TLDs (com, net) first by size.
SUSPICIOUS_TLDS: frozenset[str] = frozenset(
    {
        "xin", "win", "icu", "garden", "cfd", "pro", "help", "mom", "rest", "mobi",
        "qpon", "live", "ink", "best", "lat", "cyou", "top", "wang", "life", "homes",
    }
)  # fmt: skip


def _load_domain_list(name: str) -> frozenset[str]:
    text = (files("phishguard.services.features") / "data" / name).read_text(encoding="utf-8")
    lines = (line.strip().lower() for line in text.splitlines())
    return frozenset(line for line in lines if line and not line.startswith("#"))


# URL-shortening services, by domain (feature F27). Source, version and licence (CC BY-SA 4.0):
# data/README.md.
URL_SHORTENERS: frozenset[str] = _load_domain_list("url_shorteners.txt")

# X-Mailer patterns of bulk-mail / spam tools (feature F109): the three X-Mailer "known spam
# mailers" rules of Apache SpamAssassin 4.0.2, rules/20_ratware.cf (tag spamassassin_release_4_0_2,
# commit 031cc0e790a8e013e5edc41dfa6f270a2148ae59, 2025-08-27; file SHA-256 e9fe7051...c311bf;
# Apache License 2.0), regexes copied unchanged: RATWARE_EGROUPS, RATWARE_OE_MALFORMED,
# RATWARE_MPOP_WEBMAIL. No published list names phishing kits, so F109 is rarely 1.
SUSPICIOUS_MAILERS: tuple[re.Pattern[str], ...] = (
    re.compile(r"eGroups Message Poster"),
    re.compile(r"^Microsoft Outlook Express \d(?:\.\d+){3} \w+$"),
    re.compile(r"mPOP Web-Mail", re.IGNORECASE),
)

# Word lists for the text features F116-F140. Written by hand for this project (no published
# list exists), fixed before any model was trained, and never tuned on the data. Matched as
# whole words / phrases, case-insensitive.
URGENCY_TERMS: tuple[str, ...] = (
    "urgent", "urgently", "immediately", "immediate", "asap", "right away", "as soon as possible",
    "now", "today", "quickly", "promptly", "final notice", "last chance", "act fast",
)  # fmt: skip
THREAT_TERMS: tuple[str, ...] = (
    "suspended", "suspend", "locked", "lock", "disabled", "deactivated", "terminated", "closed",
    "restricted", "unauthorized", "unusual activity", "suspicious activity", "legal action",
    "penalty", "blocked", "compromised",
)  # fmt: skip
REWARD_TERMS: tuple[str, ...] = (
    "prize", "winner", "won", "reward", "refund", "bonus", "gift", "free", "congratulations",
    "claim", "lottery", "cashback", "voucher",
)  # fmt: skip
FINANCIAL_TERMS: tuple[str, ...] = (
    "bank", "payment", "invoice", "transfer", "wire", "credit card", "debit card", "billing",
    "transaction", "account balance", "funds", "tax", "salary", "bitcoin", "wallet", "paypal",
)  # fmt: skip
GENERIC_GREETINGS: tuple[str, ...] = (
    "dear customer", "dear user", "dear client", "dear member", "dear valued customer",
    "dear account holder", "dear sir", "dear madam", "dear sir/madam", "dear sir or madam",
    "hello customer", "hello user", "dear friend", "dear beneficiary",
)  # fmt: skip
CALL_TO_ACTION_PHRASES: tuple[str, ...] = (
    "click here", "click below", "click the link", "click on the link", "follow the link",
    "act now", "verify now", "update now", "log in now", "sign in now", "confirm now",
    "open the attachment", "download now", "respond now",
)  # fmt: skip
