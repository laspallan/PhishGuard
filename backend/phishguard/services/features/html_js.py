"""F66–F95: page features from the stored HTML (read as text; scripts are never run).

Parsed with the standard library's lenient html.parser. "Other domain" always means a different
registered domain (eTLD+1) than the page's own, where the page is the final URL after
redirects. Definitions decided here:

- F68/F69/F70 are 1 if any form has that kind of action. A form without an action attribute
  counts as empty (F69), like action="" and "about:blank".
- F74 invisible iframe: width or height 0, the `hidden` attribute, or an inline style with
  display:none, visibility:hidden, or a zero width/height.
- F77/F79/F81/F82/F95 search the whole HTML source (inline scripts and event attributes).
- F78 "used heavily" = atob( and String.fromCharCode( together at least 3 times.
- F81: an oncontextmenu handler, a "contextmenu" event listener, or a check for mouse button 2.
- F83 counts <a> elements with an href. F84/F85 are shares of those; F87 is the share of
  <img src> and stylesheet <link href> on other domains. A share with nothing to count is MISSING.
- F85 null link: href empty, "#", or a javascript: URL.
- F86 = 0 when the page names no favicon (browsers then use /favicon.ico on the same site).
- F88/F89: a brand named in the <title> / in the text after a copyright mark (©, &copy;, the
  word "copyright"; 100 characters) that the page's domain does not belong to.
- F91 counts elements whose inline style hides them (display:none, visibility:hidden).
- Visible text (F89, F92, F94) is the text outside <script>, <style> and <template>,
  whitespace collapsed. F94 = visible text length / HTML length.
- No HTML (offline page, non-HTML response, unsafe host): every feature is MISSING.
"""

import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from phishguard.services.features.brands import brand_mismatch
from phishguard.services.features.hosts import split_host
from phishguard.services.features.missing import MISSING

FEATURE_NAMES: tuple[str, ...] = (
    "num_forms",
    "num_password_fields",
    "form_action_external",
    "form_action_empty",
    "form_action_mailto",
    "num_input_fields",
    "num_hidden_inputs",
    "num_iframes",
    "has_invisible_iframe",
    "num_script_tags",
    "num_external_scripts",
    "has_eval_or_unescape",
    "has_js_obfuscation",
    "has_js_redirect",
    "has_meta_refresh",
    "disables_right_click",
    "has_popup_window",
    "num_links",
    "external_link_ratio",
    "null_link_ratio",
    "favicon_external",
    "external_resource_ratio",
    "title_brand_mismatch",
    "copyright_brand_mismatch",
    "html_length",
    "num_hidden_elements",
    "has_login_keywords_page",
    "num_images",
    "text_to_html_ratio",
    "has_base64_content",
)

_HIDDEN_STYLE = re.compile(r"display\s*:\s*none|visibility\s*:\s*hidden", re.IGNORECASE)
_ZERO_SIZE_STYLE = re.compile(r"(?<![-\w])(width|height)\s*:\s*0(px)?\s*(;|$)", re.IGNORECASE)
_EVAL = re.compile(r"\b(eval|unescape)\s*\(")
_OBFUSCATION = re.compile(r"\batob\s*\(|String\.fromCharCode\s*\(")
_JS_REDIRECT = re.compile(
    r"\b(window|document|top|self)\.location(\.href)?\s*=(?!=)"
    r"|\blocation\.href\s*=(?!=)"
    r"|\blocation\.(replace|assign)\s*\("
)
_RIGHT_CLICK = re.compile(
    r"oncontextmenu\s*=|addEventListener\s*\(\s*[\"']contextmenu[\"']|\b(event|e)\.button\s*==+\s*2"
)
_POPUP = re.compile(r"\bwindow\.open\s*\(|\bprompt\s*\(")
_BASE64 = re.compile(r"data:[\w/+.-]+;base64,", re.IGNORECASE)
_COPYRIGHT = re.compile(r"(©|\bcopyright\b)(.{0,100})", re.IGNORECASE | re.DOTALL)
_LOGIN_WORDS = ("sign in", "log in", "password")
_WHITESPACE = re.compile(r"\s+")
_TEXT_SKIP = frozenset({"script", "style", "template"})


def _zero(value: str | None) -> bool:
    return value is not None and value.strip().lower() in ("0", "0px")


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[str | None] = []  # action attribute per form (None = absent)
        self.inputs: list[str] = []  # type per input
        self.iframes = 0
        self.invisible_iframe = False
        self.script_srcs: list[str | None] = []
        self.meta_refresh = False
        self.links: list[str] = []
        self.favicons: list[str] = []
        self.resources: list[str] = []
        self.images = 0
        self.hidden_elements = 0
        self.title: list[str] = []
        self.text: list[str] = []
        self._in_title = False
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        style = a.get("style", "")
        if style and _HIDDEN_STYLE.search(style):
            self.hidden_elements += 1
        if tag == "form":
            self.forms.append(a.get("action") if "action" in a else None)
        elif tag == "input":
            self.inputs.append(a.get("type", "text").strip().lower())
        elif tag == "iframe":
            self.iframes += 1
            if (
                _zero(a.get("width"))
                or _zero(a.get("height"))
                or "hidden" in a
                or _HIDDEN_STYLE.search(style)
                or _ZERO_SIZE_STYLE.search(style)
            ):
                self.invisible_iframe = True
        elif tag == "script":
            self.script_srcs.append(a.get("src") or None)
        elif tag == "meta" and a.get("http-equiv", "").strip().lower() == "refresh":
            self.meta_refresh = True
        elif tag == "a" and "href" in a:
            self.links.append(a["href"])
        elif tag == "link":
            rel = a.get("rel", "").lower().split()
            if "icon" in rel and a.get("href"):
                self.favicons.append(a["href"])
            if "stylesheet" in rel and a.get("href"):
                self.resources.append(a["href"])
        elif tag == "img":
            self.images += 1
            if a.get("src"):
                self.resources.append(a["src"])
        elif tag == "title":
            self._in_title = True
        if tag in _TEXT_SKIP:
            self._skip_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
        if tag in _TEXT_SKIP and self._skip_depth:
            self._skip_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title.append(data)
        if not self._skip_depth:
            self.text.append(data)


def _domain_of(href: str, page_url: str) -> str | None:
    """Registered domain an href points to, or None if it is not an http(s) URL."""
    try:
        absolute = urljoin(page_url, href.strip())
        parts = urlsplit(absolute)
        host = parts.hostname
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https") or not host:
        return None
    return split_host(host).registered_domain


def _is_external(href: str, page_url: str, own: str) -> bool:
    domain = _domain_of(href, page_url)
    return domain is not None and domain != own


def _share(part: int, whole: int) -> float:
    return part / whole if whole else MISSING


def _flag(condition: bool) -> float:
    return 1.0 if condition else 0.0


def _is_null_link(href: str) -> bool:
    value = href.strip().lower()
    return value in ("", "#") or value.startswith("javascript:")


def extract(html: str | None, page_url: str) -> list[float]:
    """F66–F95 in catalogue order. `page_url` is the final URL the HTML came from."""
    if html is None:
        return [MISSING] * len(FEATURE_NAMES)
    parser = _PageParser()
    try:
        parser.feed(html)
        parser.close()
    except (AssertionError, ValueError):  # rare broken markup: keep what was parsed so far
        pass
    own = split_host(urlsplit(page_url).hostname or "").registered_domain

    forms = parser.forms
    actions = [(f or "").strip().lower() for f in forms]
    text = _WHITESPACE.sub(" ", " ".join(parser.text)).strip()
    title = " ".join(parser.title)
    copyright_text = " ".join(m.group(0) for m in _COPYRIGHT.finditer(text))
    links = parser.links
    values = [
        len(forms),
        parser.inputs.count("password"),
        _flag(any(_is_external(f, page_url, own) for f in forms if f)),
        _flag(any(a in ("", "about:blank") for a in actions)),
        _flag(any(a.startswith("mailto:") for a in actions)),
        len(parser.inputs),
        parser.inputs.count("hidden"),
        parser.iframes,
        _flag(parser.invisible_iframe),
        len(parser.script_srcs),
        sum(_is_external(s, page_url, own) for s in parser.script_srcs if s),
        _flag(bool(_EVAL.search(html))),
        _flag(len(_OBFUSCATION.findall(html)) >= 3),
        _flag(bool(_JS_REDIRECT.search(html))),
        _flag(parser.meta_refresh),
        _flag(bool(_RIGHT_CLICK.search(html))),
        _flag(bool(_POPUP.search(html))),
        len(links),
        _share(sum(_is_external(h, page_url, own) for h in links), len(links)),
        _share(sum(_is_null_link(h) for h in links), len(links)),
        _flag(any(_is_external(h, page_url, own) for h in parser.favicons)),
        _share(
            sum(_is_external(r, page_url, own) for r in parser.resources), len(parser.resources)
        ),
        _flag(brand_mismatch(title, own)),
        _flag(brand_mismatch(copyright_text, own)),
        len(html),
        parser.hidden_elements,
        _flag(any(w in text.lower() for w in _LOGIN_WORDS)),
        parser.images,
        _share(len(text), len(html)),
        _flag(bool(_BASE64.search(html))),
    ]
    return [float(v) for v in values]
