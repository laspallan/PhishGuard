"""F66–F95. One hand-made page exercises every feature; expected values counted by hand."""

import math
import re
from pathlib import Path

import pytest

from phishguard.services.features.html_js import FEATURE_NAMES, extract

CATALOGUE = Path(__file__).resolve().parents[3] / "Docs" / "features.md"
ROW = re.compile(r"^\| F(\d+) \| ([a-z0-9_]+) \|")
PAGE_URL = "https://login.shop-test.com/a/"  # own registered domain: shop-test.com

PAGE = """<html><head><title>PayPal - Log in</title>
<link rel="icon" href="https://cdn.other-test.com/fav.ico">
<link rel="stylesheet" href="/style.css">
<meta http-equiv="Refresh" content="5; url=/x">
<script src="https://cdn.other-test.com/a.js"></script>
<script src="/local.js"></script>
<script>eval(atob("eA==")); atob("x"); String.fromCharCode(65); window.location = "/n";</script>
</head><body oncontextmenu="return false">
<form action="https://collect.other-test.com/post"><input type="text" name="u">
<input type="password" name="p"><input type="hidden" name="t"></form>
<form><input type="submit"></form>
<iframe src="/x" width="0" height="0"></iframe>
<div style="display:none">secret</div>
<a href="#">one</a><a href="javascript:void(0)">two</a>
<a href="https://other-test.com/">three</a><a href="/help">four</a>
<img src="https://img.other-test.com/logo.png"><img src="/a.png">
<p>Please sign in. Copyright © 2026 PayPal Inc.</p>
<img src="data:image/png;base64,AAAA">
</body></html>"""
VISIBLE = "PayPal - Log in secret one two three four Please sign in. Copyright © 2026 PayPal Inc."


def features(html, url=PAGE_URL):
    return dict(zip(FEATURE_NAMES, extract(html, url), strict=True))


def test_names_and_order_match_the_catalogue():
    rows = [ROW.match(line) for line in CATALOGUE.read_text(encoding="utf-8").splitlines()]
    assert list(FEATURE_NAMES) == [m[2] for m in rows if m and 66 <= int(m[1]) <= 95]


def test_hand_checked_page():
    expected = {
        "num_forms": 2,
        "num_password_fields": 1,
        "form_action_external": 1,  # collect.other-test.com
        "form_action_empty": 1,  # the second form has no action
        "form_action_mailto": 0,
        "num_input_fields": 4,  # text, password, hidden, submit
        "num_hidden_inputs": 1,
        "num_iframes": 1,
        "has_invisible_iframe": 1,  # width=0 height=0
        "num_script_tags": 3,
        "num_external_scripts": 1,  # cdn.other-test.com
        "has_eval_or_unescape": 1,
        "has_js_obfuscation": 1,  # atob( x2 + fromCharCode( x1 = 3
        "has_js_redirect": 1,  # window.location = ...
        "has_meta_refresh": 1,  # http-equiv="Refresh", any case
        "disables_right_click": 1,  # oncontextmenu=
        "has_popup_window": 0,
        "num_links": 4,
        "external_link_ratio": 1 / 4,  # other-test.com
        "null_link_ratio": 2 / 4,  # "#", javascript:void(0)
        "favicon_external": 1,
        "external_resource_ratio": 1 / 4,  # style.css, logo.png (other), a.png, data: URI
        "title_brand_mismatch": 1,  # "PayPal" on shop-test.com
        "copyright_brand_mismatch": 1,  # "© 2026 PayPal Inc."
        "html_length": len(PAGE),
        "num_hidden_elements": 1,  # div display:none
        "has_login_keywords_page": 1,  # "sign in"
        "num_images": 3,
        "text_to_html_ratio": len(VISIBLE) / len(PAGE),  # script contents not counted
        "has_base64_content": 1,
    }
    assert features(PAGE) == pytest.approx(expected)


def test_plain_page_without_forms_or_links():
    f = features("<html><title>Welcome</title><p>Hello</p></html>")
    assert f["num_forms"] == 0 and f["form_action_empty"] == 0
    assert f["num_links"] == 0
    assert math.isnan(f["external_link_ratio"]) and math.isnan(f["null_link_ratio"])
    assert math.isnan(f["external_resource_ratio"])
    assert f["favicon_external"] == 0  # no favicon named: /favicon.ico on the same site
    assert f["title_brand_mismatch"] == 0
    assert f["has_login_keywords_page"] == 0


def test_mailto_popup_and_style_hidden_iframe():
    html = (
        '<form action="MailTo:x@shop-test.com"></form>'
        '<iframe style="visibility: hidden"></iframe>'
        "<script>window.open('https://x.example');</script>"
    )
    f = features(html)
    assert f["form_action_mailto"] == 1
    assert f["has_invisible_iframe"] == 1
    assert f["has_popup_window"] == 1
    assert f["num_hidden_elements"] == 1  # the iframe's inline style hides it


def test_brand_on_its_own_domain_is_not_a_mismatch():
    assert features("<title>PayPal</title>", "https://www.paypal.com/")["title_brand_mismatch"] == 0


def test_location_comparison_is_not_a_redirect():
    f = features('<script>if (window.location.href == "x") {}</script>')
    assert f["has_js_redirect"] == 0
    assert features("<script>location.replace('/x')</script>")["has_js_redirect"] == 1


def test_light_obfuscation_is_not_heavy():
    assert features("<script>atob('eA==')</script>")["has_js_obfuscation"] == 0


def test_no_html_is_all_missing_and_broken_markup_does_not_crash():
    assert all(math.isnan(v) for v in extract(None, PAGE_URL))
    broken = "<html><![if foo]><a href='/x'>a</a><form action='"
    values = extract(broken, PAGE_URL)
    assert len(values) == len(FEATURE_NAMES)
