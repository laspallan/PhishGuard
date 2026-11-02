import json

import httpx

from phishguard_ml.data import rdap
from phishguard_ml.data.records import SampleRecord, Source

BOOTSTRAP = {
    "services": [
        [
            ["com", "net"],
            ["http://rdap.verisign.example/com/v1/", "https://rdap.verisign.example/com/v1/"],
        ],
        [["co.uk", "uk"], ["https://rdap.nominet.example/uk"]],
    ]
}
T = "2026-11-02T00:00Z"


def client(routes: dict[str, list[httpx.Response]], seen: list[str]):
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        seen.append(url)
        if url == rdap.BOOTSTRAP_URL:
            return httpx.Response(200, json=BOOTSTRAP)
        queue = routes.get(url)
        return queue.pop(0) if queue else httpx.Response(404)

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_bootstrap_prefers_https_and_longest_suffix():
    table = rdap.load_bootstrap(client({}, []))

    assert rdap.base_for("example.com", table) == "https://rdap.verisign.example/com/v1/"
    assert rdap.base_for("shop.example.co.uk", table) == "https://rdap.nominet.example/uk/"
    assert rdap.base_for("example.zz", table) is None


def test_domains_of_urls_only_and_no_ips():
    records = [
        SampleRecord.create(
            source=Source.PHISHTANK, raw_content="http://a.b.evil.com/x", collected_at=T
        ),
        SampleRecord.create(
            source=Source.PHISHTANK, raw_content="http://evil.com/y", collected_at=T
        ),
        SampleRecord.create(
            source=Source.PHISHTANK, raw_content="http://203.0.113.9/z", collected_at=T
        ),
        SampleRecord.create(source=Source.ENRON, raw_content="Subject: s\n\nb", collected_at=T),
    ]
    assert rdap.domains_of(records) == ["evil.com"]


def test_retry_on_429_then_success_and_resume(isolated_data_dir):
    url = "https://rdap.verisign.example/com/v1/domain/evil.com"
    seen: list[str] = []
    waits: list[float] = []
    routes = {
        url: [
            httpx.Response(429, headers={"retry-after": "7"}),
            httpx.Response(503),
            httpx.Response(200, json={"events": [{"eventAction": "registration"}]}),
        ]
    }
    c = client(routes, seen)

    outcome = rdap.collect(["evil.com", "gone.com", "x.zz"], c, interval=0.5, sleep=waits.append)

    assert outcome == {"http_200": 1, "http_404": 1, "no_rdap_server": 1}
    assert waits[:2] == [7, 10]  # Retry-After honoured, then backoff 5 * 2**attempt
    saved = json.loads((isolated_data_dir / "rdap" / "evil.com.json").read_text())
    assert saved["response"]["events"][0]["eventAction"] == "registration"

    seen.clear()
    again = rdap.collect(["evil.com", "gone.com", "x.zz"], c, sleep=waits.append)
    assert again == {"already_done": 3}
    assert [u for u in seen if "domain/" in u] == []


def test_persistent_errors_are_retried_next_run(isolated_data_dir):
    url = "https://rdap.verisign.example/com/v1/domain/busy.com"
    routes = {url: [httpx.Response(429)] * 5}
    c = client(routes, [])

    first = rdap.collect(["busy.com"], c, sleep=lambda s: None)
    assert first == {"http_429": 1}

    routes[url] = [httpx.Response(200, json={})]
    assert rdap.collect(["busy.com"], c, sleep=lambda s: None) == {"http_200": 1}
