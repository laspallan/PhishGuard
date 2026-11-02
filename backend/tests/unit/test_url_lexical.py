"""F1–F45. Every expected value below was counted by hand (working in the comments)."""

import math
import re
from pathlib import Path

import pytest

from phishguard.services.features import url_lexical
from phishguard.services.features.url_lexical import FEATURE_NAMES, entropy, extract

CATALOGUE = Path(__file__).resolve().parents[3] / "Docs" / "features.md"
ROW = re.compile(r"^\| F(\d+) \| ([a-z0-9_]+) \|")

# 7 "http://" + 22 host + 5 ":8080" + 15 path + 11 "?q=1&r=%20~" + 4 "#top" = 64 characters
URL = "http://a-b.paypal.example.com:8080/x_y//login.exe?q=1&r=%20~#top"


def features(url: str) -> dict[str, float]:
    return dict(zip(FEATURE_NAMES, extract(url), strict=True))


def test_names_and_order_match_the_catalogue():
    rows = [ROW.match(line) for line in CATALOGUE.read_text(encoding="utf-8").splitlines()]
    catalogue = [m[2] for m in rows if m and 1 <= int(m[1]) <= 45]
    assert list(FEATURE_NAMES) == catalogue


def test_hand_counted_example():
    f = features(URL)
    expected = {
        "url_length": 64,
        "hostname_length": 22,  # a-b.paypal.example.com
        "path_length": 15,  # /x_y//login.exe
        "query_length": 10,  # q=1&r=%20~
        "fragment_length": 3,  # top
        "num_dots": 4,  # 3 in the host + ".exe"
        "num_hyphens": 1,
        "num_underscores": 1,
        "num_slashes": 5,  # "//" after http: + "/" "//" in the path
        "num_question_marks": 1,
        "num_equals": 2,
        "num_at_symbols": 0,
        "num_ampersands": 1,
        "num_percent": 1,
        "num_tilde": 1,
        "num_digits_url": 7,  # 8080, 1, 20
        "digit_ratio_url": 7 / 64,
        "letter_ratio_url": 37 / 64,  # http 4 + host 18 + path 10 + query 2 + fragment 3
        "special_char_ratio": 20 / 64,  # 64 - 37 letters - 7 digits
        "has_ip_address": 0,
        "uses_https": 0,
        "has_port": 1,  # 8080 is not the http default
        "num_subdomains": 2,  # a-b, paypal
        "subdomain_length": 10,  # "a-b.paypal"
        "tld_length": 3,  # com
        "suspicious_tld": 0,
        "is_shortened": 0,
        "has_double_slash_redirect": 1,  # "//" inside the path
        "has_http_in_path": 0,
        "has_punycode": 0,
        "has_mixed_script": 0,
        "url_entropy": entropy(URL),  # the function itself is hand-checked below
        "hostname_entropy": entropy("a-b.paypal.example.com"),
        "longest_token_length": 7,  # "example"
        # 16 tokens: http a b paypal example com 8080 x y login exe q 1 r 20 top = 44 characters
        "avg_token_length": 44 / 16,
        "num_path_tokens": 2,  # x_y, login.exe (empty segments not counted)
        "num_query_params": 2,
        "suspicious_file_extension": 1,  # .exe
        "brand_in_subdomain": 1,  # paypal
        "brand_in_path": 0,
        "has_sensitive_word_url": 1,
        "num_sensitive_words_url": 1,  # login
        "hostname_digit_ratio": 0,
        "max_char_repeat": 2,  # "tt", "//"
        "hostname_vowel_ratio": 7 / 18,  # a | a a | e a e | o  over 18 letters
    }
    assert f == pytest.approx(expected)


def test_entropy_by_hand():
    assert entropy("") == 0.0
    assert entropy("aaaa") == 0.0
    assert entropy("aabb") == pytest.approx(1.0)  # two symbols, p = 1/2 each
    assert entropy("abcd") == pytest.approx(2.0)  # four symbols, p = 1/4 each


def test_ip_host_https_and_default_port():
    f = features("https://192.168.0.1:443/login")
    assert f["has_ip_address"] == 1
    assert f["uses_https"] == 1
    assert f["has_port"] == 0  # 443 is the https default
    assert f["num_subdomains"] == 0
    assert math.isnan(f["tld_length"]) and math.isnan(f["suspicious_tld"])
    assert math.isnan(f["hostname_vowel_ratio"])  # an IP address has no letters
    assert f["hostname_digit_ratio"] == pytest.approx(8 / 11)  # 192168001 = 8 of "192.168.0.1"


def test_ipv6_host():
    f = features("http://[2001:db8::1]/")
    assert f["has_ip_address"] == 1
    assert f["hostname_length"] == len("2001:db8::1")


def test_invalid_port_counts_as_non_standard():
    assert features("http://example.com:99999/")["has_port"] == 1


def test_punycode_and_mixed_script():
    mixed = "аpple".encode("idna").decode()  # Cyrillic "а" + Latin "pple"
    f = features(f"http://{mixed}.com/")
    assert f["has_punycode"] == 1
    assert f["has_mixed_script"] == 1

    cyrillic = "пример".encode("idna").decode()  # "пример"
    g = features(f"http://{cyrillic}.com/")
    assert g["has_punycode"] == 1
    assert g["has_mixed_script"] == 0  # one script per label; ".com" is a separate label


def test_http_inside_path_or_query():
    assert features("http://x.example.com/go?u=https://evil.example")["has_http_in_path"] == 1
    assert features("http://x.example.com/redirect/http/a")["has_http_in_path"] == 1


def test_brand_in_path_and_sensitive_words_counted():
    f = features("http://x.example.com/paypal/secure-login/verify")
    assert f["brand_in_path"] == 1
    assert f["num_sensitive_words_url"] == 3  # secure, login, verify
    assert features("http://x.example.com/a")["has_sensitive_word_url"] == 0


def test_suspicious_tld_and_shortener(monkeypatch):
    monkeypatch.setattr(url_lexical, "SUSPICIOUS_TLDS", frozenset({"zz"}))
    monkeypatch.setattr(url_lexical, "URL_SHORTENERS", frozenset({"shrt-test.com"}))
    assert features("http://evil.zz/")["suspicious_tld"] == 1
    assert features("http://shrt-test.com/abc")["is_shortened"] == 1
    assert features("http://www.shrt-test.com/abc")["is_shortened"] == 1  # by registered domain


@pytest.mark.parametrize("bad", ["not a url", "http://[::1", "mailto:a@example.com", ""])
def test_unusable_urls_are_all_missing(bad):
    assert all(math.isnan(v) for v in extract(bad))


def test_real_lists_are_loaded():
    # Interisle 2026 Table 2 lists "top"; the CC BY-SA shortener list contains bit.ly.
    assert features("http://evil-shop.top/")["suspicious_tld"] == 1
    assert features("https://www.example.com/")["suspicious_tld"] == 0
    assert features("https://bit.ly/3abc")["is_shortened"] == 1
