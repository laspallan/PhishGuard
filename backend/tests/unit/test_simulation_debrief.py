from html.parser import HTMLParser

from phishguard.services.simulation.debrief import debrief_page


class _Tags(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags: list[str] = []
        self.attributes: list[str] = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        self.attributes += [name for name, _ in attrs]


def _parse(html: str) -> _Tags:
    parser = _Tags()
    parser.feed(html)
    return parser


def test_the_page_says_at_once_that_it_was_a_simulation():
    html = debrief_page("Kestrelmoor Institute", "study@example.org")
    assert "This was a simulated phishing email" in html
    assert "Kestrelmoor Institute is not a real organisation" in html
    assert "study@example.org" in html


def test_there_is_nowhere_to_type_and_nothing_is_loaded_from_elsewhere():
    page = _parse(debrief_page("Kestrelmoor Institute", "study@example.org"))
    assert not {"form", "input", "textarea", "select", "button", "script"} & set(page.tags)
    assert not {"img", "iframe", "link", "object", "embed"} & set(page.tags)
    assert not {"src", "href", "action"} & set(page.attributes)


def test_values_cannot_add_markup_to_the_page():
    page = _parse(debrief_page("<form>", "<script>"))
    assert "form" not in page.tags and "script" not in page.tags
