"""Cascade latency on the CPU (Phase 3 acceptance check), and DistilBERT prediction on this PC.

Measured on development rows, one sample at a time, as in a live scan: the tabular soft vote for
every sample, and DistilBERT only when the tabular score falls inside the band.
"""

import json
import time
from collections.abc import Callable
from pathlib import Path

import numpy as np

from phishguard_ml.training import ensembles


def distilbert_predictor(folder: Path) -> Callable[[list[str]], np.ndarray]:
    """Needs ml/.venv-text. Loads only the folder of a run imported with `text-import`."""
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    run = json.loads((folder / "run.json").read_text())
    max_length = run["params"]["max_length"]
    tokenizer = AutoTokenizer.from_pretrained(folder / "model", local_files_only=True)
    model = AutoModelForSequenceClassification.from_pretrained(
        folder / "model", local_files_only=True
    ).eval()

    def predict(texts: list[str], batch_size: int = 32) -> np.ndarray:
        out = np.empty(len(texts))
        with torch.no_grad():
            for start in range(0, len(texts), batch_size):
                inputs = tokenizer(
                    texts[start : start + batch_size], padding=True, truncation=True,
                    max_length=max_length, return_tensors="pt",
                )  # fmt: skip
                logits = model(**inputs).logits.squeeze(1)
                out[start : start + batch_size] = torch.sigmoid(logits).numpy()
        return out

    return predict


def measure(
    tabular: Callable[[np.ndarray], float],
    text: Callable[[str], float],
    X: np.ndarray,
    texts: list[str],
    *,
    band: tuple[float, float] = ensembles.CASCADE_BAND,
) -> dict:
    latencies, escalated = [], 0
    for row, sample in zip(X, texts, strict=True):
        started = time.perf_counter()
        score = tabular(row.reshape(1, -1))
        if band[0] <= score <= band[1]:
            text(sample)
            escalated += 1
        latencies.append((time.perf_counter() - started) * 1000)
    ordered = np.sort(latencies)
    return {
        "n": len(latencies),
        "share_sent_to_text_model": escalated / max(len(latencies), 1),
        "median_ms": float(np.median(ordered)),
        "p95_ms": float(np.percentile(ordered, 95)),
    }
