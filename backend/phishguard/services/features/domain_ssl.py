"""F46–F65: domain registration, DNS and TLS features, from data stored at collection time.

Inputs are the dicts the snapshot collector and the RDAP step store (dns.json, tls.json,
data/rdap/<domain>.json); nothing is looked up here. Definitions decided here:

- Every age is measured at `reference_time`, the moment the page was captured, not "now", so
  a feature does not change with the day the matrix is built.
- RDAP was queried after the capture. A "last changed" date after the capture may be a
  takedown of the phishing domain (it would leak the label), so F51 is then MISSING.
- F49 whois_available: 1 = RDAP answered with a record, 0 = the registry says the domain does
  not exist (404). MISSING when nobody could be asked (no RDAP server for the TLD, refused,
  errors) or for IP hosts. F46–F48, F50–F52 are MISSING when there is no record.
- F50/F52: thin registries (e.g. Verisign for .com) hold no registrant at all; then MISSING,
  not 0. F50 = 1 if the record carries an RFC 9537 "redacted" member or the registrant entry
  says redacted / privacy / proxy.
- DNS answers are for the URL's host. NXDOMAIN / NoAnswer count as 0 records; timeouts and
  other errors are MISSING. F55 falls back to the RDAP name servers when the host has no NS
  answer (common for subdomains). F56 is the lowest TTL seen across A, AAAA, MX, NS (the
  remaining TTL reported by the resolver).
- F57/F58 use the Tranco ranks passed in (registered domain); 0 / 0 if not listed.
- F59 = 1 only if the chain and hostname verified; 0 if no valid certificate was offered on
  port 443. F60–F64 come from the certificate even when it did not verify; MISSING if none.
- F62 matches the issuer organisation against FREE_ACME_CAS.
- F65 suspicious_asn is always MISSING (decided 2026-11-02: no IP-to-ASN data is collected).
"""

import json
from collections.abc import Mapping
from datetime import UTC, datetime

from phishguard.services.features.hosts import is_ip, split_host
from phishguard.services.features.missing import MISSING, is_missing

FEATURE_NAMES: tuple[str, ...] = (
    "domain_age_days",
    "domain_expiry_days",
    "registration_length_days",
    "whois_available",
    "whois_privacy",
    "days_since_whois_update",
    "registrant_country_known",
    "num_a_records",
    "has_mx_record",
    "num_name_servers",
    "dns_min_ttl",
    "tranco_rank",
    "in_tranco_top_1m",
    "ssl_valid",
    "ssl_cert_age_days",
    "ssl_validity_days",
    "ssl_free_ca",
    "ssl_hostname_match",
    "ssl_san_count",
    "suspicious_asn",
)

# Issuer organisations (the O= part of the certificate issuer) of free, automated (ACME) CAs.
FREE_ACME_CAS: frozenset[str] = frozenset({"let's encrypt", "zerossl"})
_EMPTY_DNS_ERRORS = frozenset({"NXDOMAIN", "NoAnswer"})
_PRIVACY_WORDS = ("redacted", "privacy", "proxy")


def _date(text: str | None) -> datetime | None:
    if not text:
        return None
    try:
        value = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def _days(later: datetime | None, earlier: datetime | None) -> float:
    if later is None or earlier is None:
        return MISSING
    return float((later - earlier).days)


def _flag(condition: bool) -> float:
    return 1.0 if condition else 0.0


def _events(record: dict) -> dict[str, datetime]:
    found = {}
    for event in record.get("events") or []:
        when = _date(event.get("eventDate"))
        action = event.get("eventAction")
        if when and action and action not in found:
            found[action] = when
    return found


def _registrant(record: dict) -> dict | None:
    for entity in record.get("entities") or []:
        if "registrant" in (entity.get("roles") or []):
            return entity
    return None


def _country_known(entity: dict) -> bool:
    vcard = entity.get("vcardArray")
    properties = vcard[1] if isinstance(vcard, list) and len(vcard) > 1 else []
    for prop in properties:
        if not prop or prop[0] != "adr":
            continue
        params = prop[1] if len(prop) > 1 and isinstance(prop[1], dict) else {}
        value = prop[3] if len(prop) > 3 else None
        if params.get("cc") or (isinstance(value, list) and len(value) >= 7 and value[6]):
            return True
    return False


def rdap_features(rdap: dict | None, reference_time: datetime) -> list[float]:
    """F46–F52."""
    status = (rdap or {}).get("status")
    if status == 404 and "error" not in (rdap or {}):  # the registry: no such domain
        return [MISSING, MISSING, MISSING, 0.0, MISSING, MISSING, MISSING]
    record = (rdap or {}).get("response")
    if status != 200 or not isinstance(record, dict):
        return [MISSING] * 7

    events = _events(record)
    registered = events.get("registration")
    expires = events.get("expiration")
    changed = events.get("last changed")
    registrant = _registrant(record)
    if registrant is None and "redacted" not in record:
        privacy = MISSING
    else:
        text = json.dumps(registrant or {}).lower()
        privacy = _flag("redacted" in record or any(w in text for w in _PRIVACY_WORDS))
    return [
        _days(reference_time, registered),
        _days(expires, reference_time),
        _days(expires, registered),
        1.0,
        privacy,
        _days(reference_time, changed) if changed and changed <= reference_time else MISSING,
        MISSING if registrant is None else _flag(_country_known(registrant)),
    ]


def _record_count(dns: dict, kind: str) -> float:
    entry = dns.get(kind) or {}
    if "records" in entry:
        return float(len(entry["records"]))
    return 0.0 if entry.get("error") in _EMPTY_DNS_ERRORS else MISSING


def dns_features(dns: dict | None, rdap: dict | None) -> list[float]:
    """F53–F56."""
    if not dns:
        return [MISSING] * 4
    mx = _record_count(dns, "MX")
    name_servers = _record_count(dns, "NS")
    rdap_ns = ((rdap or {}).get("response") or {}).get("nameservers") or []
    if rdap_ns and (is_missing(name_servers) or name_servers == 0):
        name_servers = float(len(rdap_ns))
    ttls = [e["ttl"] for e in dns.values() if isinstance(e, dict) and "ttl" in e]
    return [
        _record_count(dns, "A"),
        MISSING if is_missing(mx) else _flag(mx > 0),
        name_servers,
        float(min(ttls)) if ttls else MISSING,
    ]


def _issuer_org(issuer: str) -> str:
    for part in issuer.split(","):
        key, _, value = part.partition("=")
        if key.strip().upper() == "O":
            return value.strip().lower()
    return ""


def hostname_matches(host: str, names: list[str]) -> bool:
    """RFC 6125 style: exact name, or a "*." wildcard covering exactly one leftmost label."""
    host = host.lower().rstrip(".")
    for name in names:
        name = name.lower().rstrip(".")
        if name == host:
            return True
        if name.startswith("*.") and "." in host and host.split(".", 1)[1] == name[2:]:
            return True
    return False


def _subject_cn(subject: str) -> list[str]:
    return [p.split("=", 1)[1] for p in subject.split(",") if p.strip().upper().startswith("CN=")]


def tls_features(host: str, tls: dict | None, reference_time: datetime) -> list[float]:
    """F59–F64."""
    if not tls:
        return [MISSING] * 6
    if "not_before" not in tls:  # no certificate obtained
        return [0.0, MISSING, MISSING, MISSING, MISSING, MISSING]
    not_before = _date(tls.get("not_before"))
    not_after = _date(tls.get("not_after"))
    san = list(tls.get("san") or [])
    names = san or _subject_cn(tls.get("subject", ""))
    return [
        _flag(bool(tls.get("verified"))),
        _days(reference_time, not_before),
        _days(not_after, not_before),
        _flag(_issuer_org(tls.get("issuer", "")) in FREE_ACME_CAS),
        _flag(hostname_matches(host, names)),
        float(len(san)),
    ]


def extract(
    host: str,
    *,
    rdap: dict | None,
    dns: dict | None,
    tls: dict | None,
    reference_time: datetime,
    tranco_ranks: Mapping[str, int],
) -> list[float]:
    """F46–F65 in catalogue order for one URL host."""
    host = host.lower().rstrip(".")
    if not host:
        return [MISSING] * len(FEATURE_NAMES)
    registration = [MISSING] * 7 if is_ip(host) else rdap_features(rdap, reference_time)
    rank = tranco_ranks.get(split_host(host).registered_domain, 0)
    return [
        *registration,
        *dns_features(dns, rdap),
        float(rank),
        _flag(rank > 0),
        *tls_features(host, tls, reference_time),
        MISSING,  # F65 suspicious_asn: not implemented (decision 2026-11-02)
    ]
