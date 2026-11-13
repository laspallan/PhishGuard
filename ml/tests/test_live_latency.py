"""Live latency: stays under the rate limit, and reports per stage and the gate suggestion."""

import json

import httpx

from phishguard_ml.evaluation import live_latency


def test_answers_are_summarised_per_stage_and_refusals_are_counted():
    answers = iter([
        httpx.Response(200, json={"verdict": "allow", "stage": 1, "latency_ms": 5}),
        httpx.Response(200, json={"verdict": "allow", "stage": 2, "latency_ms": 9}),
        httpx.Response(503, json={"detail": "no model"}),
    ])  # fmt: skip
    seen = []

    def handler(request):
        seen.append(json.loads(request.content)["url"])
        assert request.headers["X-API-Key"] == "k"
        return next(answers)

    pauses = []
    client = httpx.Client(transport=httpx.MockTransport(handler))
    result = live_latency.measure(
        ["https://a.test/", "https://b.test/", "https://c.test/"], client,
        api_base="http://api.test/", api_key="k", sleep=pauses.append,
    )  # fmt: skip
    assert seen == ["https://a.test/", "https://b.test/", "https://c.test/"]
    assert result["requests"] == 3 and result["answered"] == 2
    assert result["not_answered_by_status"] == {"503": 1}
    assert result["stage_1"]["n"] == 1 and result["stage_2"]["n"] == 1
    assert result["suggested_gate_timeout_ms"] % 100 == 0
    assert all(p >= 1.0 for p in pauses)  # at most 60 a minute: the API's default limit


def test_nothing_answered_gives_no_suggestion():
    result = live_latency.summarise([{"status": 0, "client_ms": 5.0}])
    assert result["answered"] == 0 and result["suggested_gate_timeout_ms"] is None
