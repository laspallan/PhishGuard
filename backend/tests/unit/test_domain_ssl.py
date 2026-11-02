"""F46–F65. Inputs have the shapes of the real stored files (data/rdap, dns.json, tls.json)."""

import math
import re
from datetime import UTC, datetime
from pathlib import Path

import pytest

from phishguard.services.features import domain_ssl
from phishguard.services.features.domain_ssl import FEATURE_NAMES, extract, hostname_matches

CATALOGUE = Path(__file__).resolve().parents[3] / "Docs" / "features.md"
ROW = re.compile(r"^\| F(\d+) \| ([a-z0-9_]+) \|")
CAPTURED = datetime(2026, 11, 2, tzinfo=UTC)

RDAP = {
    "status": 200,
    "response": {
        "objectClassName": "domain",
        "events": [
            {"eventAction": "registration", "eventDate": "2026-10-01T00:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2027-10-01T00:00:00Z"},
            {"eventAction": "last changed", "eventDate": "2026-10-31T00:00:00Z"},
        ],
        "entities": [
            {"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Reg Inc"]]]},
            {
                "roles": ["registrant"],
                "vcardArray": [
                    "vcard",
                    [
                        ["fn", {}, "text", "REDACTED FOR PRIVACY"],
                        ["adr", {"cc": "PA"}, "text", ["", "", "", "", "", "", ""]],
                    ],
                ],
            },
        ],
        "nameservers": [{"ldhName": "ns1.host-test.com"}, {"ldhName": "ns2.host-test.com"}],
    },
}
DNS = {
    "A": {"records": ["203.0.113.5", "203.0.113.6"], "ttl": 300},
    "AAAA": {"error": "NoAnswer"},
    "MX": {"error": "NoAnswer"},
    "NS": {"error": "NoAnswer"},
}
TLS = {
    "verified": True,
    "issuer": "CN=R11,O=Let's Encrypt,C=US",
    "subject": "CN=shop-test.com",
    "not_before": "2026-10-03T00:00:00+00:00",
    "not_after": "2027-01-01T00:00:00+00:00",
    "san": ["*.shop-test.com", "shop-test.com"],
}


def features(host="login.shop-test.com", rdap=RDAP, dns=DNS, tls=TLS, ranks=None):
    values = extract(
        host,
        rdap=rdap,
        dns=dns,
        tls=tls,
        reference_time=CAPTURED,
        tranco_ranks=ranks if ranks is not None else {"shop-test.com": 1234},
    )
    return dict(zip(FEATURE_NAMES, values, strict=True))


def test_names_and_order_match_the_catalogue():
    rows = [ROW.match(line) for line in CATALOGUE.read_text(encoding="utf-8").splitlines()]
    assert list(FEATURE_NAMES) == [m[2] for m in rows if m and 46 <= int(m[1]) <= 65]


def test_hand_checked_example():
    f = features()
    expected = {
        "domain_age_days": 32,  # 1 Oct -> 2 Nov 2026
        "domain_expiry_days": 333,  # 2 Nov 2026 -> 1 Oct 2027 (365 - 32)
        "registration_length_days": 365,
        "whois_available": 1,
        "whois_privacy": 1,  # registrant "REDACTED FOR PRIVACY"
        "days_since_whois_update": 2,  # 31 Oct -> 2 Nov
        "registrant_country_known": 1,  # adr cc=PA
        "num_a_records": 2,
        "has_mx_record": 0,  # NoAnswer = no MX
        "num_name_servers": 2,  # host has no NS answer -> the 2 RDAP name servers
        "dns_min_ttl": 300,
        "tranco_rank": 1234,  # by registered domain shop-test.com
        "in_tranco_top_1m": 1,
        "ssl_valid": 1,
        "ssl_cert_age_days": 30,  # 3 Oct -> 2 Nov
        "ssl_validity_days": 90,  # 3 Oct 2026 -> 1 Jan 2027
        "ssl_free_ca": 1,  # O=Let's Encrypt
        "ssl_hostname_match": 1,  # *.shop-test.com covers login.shop-test.com
        "ssl_san_count": 2,
    }
    assert {k: v for k, v in f.items() if k != "suspicious_asn"} == pytest.approx(expected)
    assert math.isnan(f["suspicious_asn"])  # F65: not implemented, always missing


def test_change_after_capture_is_missing_not_leaked():
    rdap = {"status": 200, "response": {**RDAP["response"], "events": [
        {"eventAction": "last changed", "eventDate": "2026-11-05T00:00:00Z"}]}}  # fmt: skip
    assert math.isnan(features(rdap=rdap)["days_since_whois_update"])


def test_thin_registry_record_has_no_registrant_data():
    thin = {"status": 200, "response": {"events": RDAP["response"]["events"]}}
    f = features(rdap=thin)
    assert f["whois_available"] == 1
    assert math.isnan(f["whois_privacy"]) and math.isnan(f["registrant_country_known"])

    redacted = {"status": 200, "response": {"events": [], "redacted": [{"name": {}}]}}
    assert features(rdap=redacted)["whois_privacy"] == 1  # RFC 9537 member


@pytest.mark.parametrize(
    ("rdap", "available"),
    [
        ({"status": 404}, 0.0),  # the registry says: no such domain
        ({"status": 404, "error": "no RDAP server"}, None),  # nobody could be asked
        ({"status": 403, "error": "HTTP 403"}, None),  # refused
        (None, None),  # not queried
    ],
)
def test_whois_available_only_when_a_registry_answered(rdap, available):
    f = features(rdap=rdap)
    if available is None:
        assert math.isnan(f["whois_available"])
    else:
        assert f["whois_available"] == available
    assert math.isnan(f["domain_age_days"])


def test_ip_hosts_have_no_registration_data():
    f = features(host="203.0.113.5", tls={"error": "ConnectionRefusedError: x"}, ranks={})
    assert all(math.isnan(f[n]) for n in FEATURE_NAMES[:7])
    assert f["tranco_rank"] == 0 and f["in_tranco_top_1m"] == 0
    assert f["ssl_valid"] == 0  # no certificate offered
    assert math.isnan(f["ssl_cert_age_days"])


def test_dns_timeouts_are_missing_but_empty_answers_are_zero():
    dns = {"A": {"error": "LifetimeTimeout"}, "MX": {"error": "NXDOMAIN"}, "NS": {"error": "x"}}
    f = features(dns=dns, rdap=None)
    assert math.isnan(f["num_a_records"])
    assert f["has_mx_record"] == 0
    assert math.isnan(f["num_name_servers"])  # no answer and no RDAP name servers
    assert math.isnan(f["dns_min_ttl"])
    assert all(math.isnan(v) for v in domain_ssl.dns_features(None, None))


def test_unverified_certificate_still_gives_details():
    tls = {**TLS, "verified": False, "issuer": "CN=x,O=Some CA,C=US", "san": []}
    f = features(tls=tls)
    assert f["ssl_valid"] == 0
    assert f["ssl_free_ca"] == 0
    assert f["ssl_san_count"] == 0
    assert f["ssl_hostname_match"] == 0  # falls back to CN=shop-test.com, not the login host


def test_hostname_matching_rules():
    assert hostname_matches("a.b.com", ["a.b.com"])
    assert hostname_matches("a.b.com", ["*.b.com"])
    assert not hostname_matches("x.a.b.com", ["*.b.com"])  # wildcard covers one label only
    assert not hostname_matches("b.com", ["*.b.com"])
