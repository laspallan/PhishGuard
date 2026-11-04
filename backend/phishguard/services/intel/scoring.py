"""Combine VT and OTX into ti_score (0-100)."""

from __future__ import annotations

from typing import Any


def compute_ti_score(vt_resp: dict[str, Any] | None, otx_resp: dict[str, Any] | None) -> float:
    score = 0.0
    # VT: look for malicious/suspicious counts
    if vt_resp and isinstance(vt_resp, dict):
        data = vt_resp.get("data") or {}
        attrs = data.get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        malicious = stats.get("malicious") or 0
        suspicious = stats.get("suspicious") or 0
        # Scale conservatively
        score += min(60.0, malicious * 10.0 + suspicious * 3.0)
    # OTX
    if otx_resp and isinstance(otx_resp, dict):
        if otx_resp.get("error"):
            pass
        else:
            # pulse info can indicate maliciousness
            pulse_info = otx_resp.get("pulse_info") or {}
            count = pulse_info.get("count") or 0
            score += min(40.0, count * 4.0)
    # Clamp
    if score < 0:
        score = 0.0
    if score > 100:
        score = 100.0
    return round(score, 2)
