"""ti_score (0-100) from one VirusTotal and one OTX answer (agreed 2026-11-08, decisions.md RQ2).

- VirusTotal: 100 * min(1, (malicious + 0.5 * suspicious) / 5), counted per engine from
  `last_analysis_results` without the feeds our phishing URLs come from (FEED_ENGINES). Only if an
  answer has no per-engine results are the totals in `last_analysis_stats` used.
- OTX: 100 * min(1, pulse_count / 5), from `pulse_info.count`.
- ti_score = the higher of the two. "Not found" counts as 0; an error or an unreadable answer leaves
  that provider out; with both left out, ti_score is None (missing, like any other feature).

Fixed before any real answer was seen; the scale was not tuned.
"""

from typing import Any

FULL_SCORE_AT = 5  # engines or pulses for a full score
# PhishTank and OpenPhish are the sources of the phishing URLs, so their verdicts would repeat the
# label. Compared in lower case with the engine name and its key in last_analysis_results.
FEED_ENGINES = frozenset({"phishtank", "openphish"})


def _scaled(count: float) -> float:
    return 100.0 * min(1.0, count / FULL_SCORE_AT)


def _number(value: Any) -> float | None:
    return float(value) if isinstance(value, int | float) and not isinstance(value, bool) else None


def vt_component(response: dict[str, Any] | None) -> float | None:
    if not isinstance(response, dict) or "error" in response:
        return None
    if response.get("status") == "not_found":
        return 0.0
    attributes = (response.get("data") or {}).get("attributes") or {}
    results = attributes.get("last_analysis_results")
    if isinstance(results, dict) and results:
        malicious = suspicious = 0
        for key, entry in results.items():
            if not isinstance(entry, dict):
                continue
            names = {str(key).lower(), str(entry.get("engine_name", "")).lower()}
            if names & FEED_ENGINES:
                continue
            malicious += entry.get("category") == "malicious"
            suspicious += entry.get("category") == "suspicious"
        return _scaled(malicious + 0.5 * suspicious)
    stats = attributes.get("last_analysis_stats")
    if not isinstance(stats, dict):
        return None
    malicious, suspicious = _number(stats.get("malicious")), _number(stats.get("suspicious"))
    if malicious is None and suspicious is None:
        return None
    return _scaled((malicious or 0.0) + 0.5 * (suspicious or 0.0))


def otx_component(response: dict[str, Any] | None) -> float | None:
    if not isinstance(response, dict) or "error" in response:
        return None
    if response.get("status") == "not_found":
        return 0.0
    count = _number((response.get("pulse_info") or {}).get("count"))
    return None if count is None else _scaled(count)


def compute_ti_score(
    vt_resp: dict[str, Any] | None, otx_resp: dict[str, Any] | None
) -> float | None:
    parts = [p for p in (vt_component(vt_resp), otx_component(otx_resp)) if p is not None]
    return round(max(parts), 2) if parts else None
