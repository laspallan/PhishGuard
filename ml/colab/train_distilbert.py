"""DistilBERT out-of-fold training for Google Colab (Phase 3, this PC has no NVIDIA GPU).

Standalone: needs only torch, transformers, numpy, pyarrow and scikit-learn, not this repository.
It reads one file made by `python -m phishguard_ml text-export`, which holds development rows only:
the locked test set never leaves the PC. Output goes to --out (use a Google Drive folder): one file
per finished fold, so a Colab disconnect costs at most the fold in progress. Run it again with the
same arguments to continue.

    pip install transformers
    python train_distilbert.py --data dev_text_email_text_body.parquet --out <drive folder>

Then copy the folder back and run `python -m phishguard_ml text-import <folder>`.
Settings are fixed, not tuned: 2e-5 and at most 3 epochs are the usual choices for this model, and
tuning would multiply the GPU time. Stated as a limitation in the thesis.
"""

import argparse
import hashlib
import json
import os
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq
import torch
from sklearn.metrics import log_loss
from sklearn.model_selection import GroupShuffleSplit

MODEL_NAME = "distilbert-base-uncased"
SEED = 42
LEARNING_RATE = 2e-5
MAX_EPOCHS = 3
PATIENCE = 1
VALIDATION_SHARE = 0.1


def default_tokenizer(name: str = MODEL_NAME):
    from transformers import AutoTokenizer

    return AutoTokenizer.from_pretrained(name)


def default_model(name: str = MODEL_NAME):
    from transformers import AutoModelForSequenceClassification

    return AutoModelForSequenceClassification.from_pretrained(name, num_labels=1)


def _inputs(tokenizer, texts: list[str], max_length: int, device) -> dict:
    encoded = tokenizer(
        texts, padding=True, truncation=True, max_length=max_length, return_tensors="pt"
    )
    return {k: encoded[k].to(device) for k in ("input_ids", "attention_mask")}


def predict(model, tokenizer, texts, max_length, device, batch_size=64) -> np.ndarray:
    """In order of length, which keeps batches small; the result is in the original order."""
    model.eval()
    order = np.argsort([len(t) for t in texts], kind="stable")
    out = np.empty(len(texts))
    with torch.no_grad():
        for start in range(0, len(order), batch_size):
            chosen = order[start : start + batch_size]
            inputs = _inputs(tokenizer, [texts[i] for i in chosen], max_length, device)
            out[chosen] = torch.sigmoid(model(**inputs).logits.squeeze(1)).cpu().numpy()
    return out


def _train_epoch(model, optimiser, tokenizer, texts, y, max_length, batch_size, device, rng):
    model.train()
    loss_function = torch.nn.BCEWithLogitsLoss()
    order = rng.permutation(len(texts))
    for start in range(0, len(order), batch_size):
        chosen = order[start : start + batch_size]
        inputs = _inputs(tokenizer, [texts[i] for i in chosen], max_length, device)
        target = torch.tensor(y[chosen], dtype=torch.float, device=device)
        optimiser.zero_grad()
        loss_function(model(**inputs).logits.squeeze(1), target).backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
        optimiser.step()


def fit(
    texts, y, groups, tokenizer, make_model, *, max_length, batch_size, device, seed=SEED,
    epochs=None, max_epochs=MAX_EPOCHS,
):  # fmt: skip
    """With `epochs`: exactly that many on all rows. Without: early stopping on a group-aware
    slice of these rows, never on the held-out fold."""
    torch.manual_seed(seed)
    rng = np.random.default_rng(seed)
    if epochs is None:
        splitter = GroupShuffleSplit(n_splits=1, test_size=VALIDATION_SHARE, random_state=seed)
        kept, watched = next(splitter.split(texts, y, groups))
    else:
        kept, watched = np.arange(len(texts)), np.array([], dtype=int)
    kept_texts = [texts[i] for i in kept]
    watched_texts = [texts[i] for i in watched]
    model = make_model().to(device)
    optimiser = torch.optim.AdamW(model.parameters(), lr=LEARNING_RATE)

    best_loss, best_state, best_epoch = float("inf"), None, 0
    for epoch in range(1, (epochs or max_epochs) + 1):
        _train_epoch(
            model, optimiser, tokenizer, kept_texts, y[kept], max_length, batch_size, device, rng
        )
        if epochs is not None:
            best_epoch = epoch
            continue
        p = predict(model, tokenizer, watched_texts, max_length, device)
        loss = log_loss(y[watched], p, labels=[0, 1])
        if loss < best_loss:
            best_loss, best_epoch = loss, epoch
            best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
        elif epoch - best_epoch >= PATIENCE:
            break
    if best_state is not None:
        model.load_state_dict(best_state)
    return model, best_epoch


def _write_json(path: Path, value) -> None:
    """Whole or not at all: a disconnect during the write must not leave a broken file."""
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value))
    os.replace(temporary, path)


def run(
    data_path: Path,
    out: Path,
    *,
    make_tokenizer: Callable = default_tokenizer,
    make_model: Callable = default_model,
    model_name: str = MODEL_NAME,
    batch_size: int = 32,
    seed: int = SEED,
    max_epochs: int = MAX_EPOCHS,
    log: Callable[[str], None] = print,
) -> dict:
    table = pq.read_table(data_path)
    meta = {k.decode(): v.decode() for k, v in (table.schema.metadata or {}).items()}
    if "text_input" not in meta:
        raise ValueError("this file was not made by `phishguard_ml text-export`")
    columns = table.to_pydict()
    texts, y = columns["text"], np.asarray(columns["label"], dtype=int)
    folds, groups = np.asarray(columns["fold"], dtype=int), columns["group"]
    max_length = int(meta["max_length"])
    device = "cuda" if torch.cuda.is_available() else "cpu"
    log(f"{meta['modality']}/{meta['text_input']}: {len(texts)} rows on {device}")
    out.mkdir(parents=True, exist_ok=True)
    tokenizer = make_tokenizer()

    oof, chosen_epochs = np.full(len(texts), np.nan), []
    for fold in np.unique(folds):
        saved = out / f"fold_{fold}.json"
        held_out = np.flatnonzero(folds == fold)
        if saved.exists():
            done = json.loads(saved.read_text())
            if done["n"] != len(held_out):
                raise ValueError(f"{saved} belongs to other data; use an empty --out folder")
            oof[held_out] = done["p_phishing"]
            chosen_epochs.append(done["epochs"])
            log(f"fold {fold}: already done")
            continue
        started = time.perf_counter()
        train = np.flatnonzero(folds != fold)
        model, epochs = fit(
            [texts[i] for i in train], y[train], [groups[i] for i in train], tokenizer, make_model,
            max_length=max_length, batch_size=batch_size, device=device, seed=seed,
            max_epochs=max_epochs,
        )  # fmt: skip
        p = predict(model, tokenizer, [texts[i] for i in held_out], max_length, device)
        oof[held_out] = p
        chosen_epochs.append(epochs)
        _write_json(saved, {"n": len(held_out), "epochs": epochs, "p_phishing": p.tolist()})
        log(
            f"fold {fold}: log loss {log_loss(y[held_out], p, labels=[0, 1]):.4f}, "
            f"epochs {epochs}, {time.perf_counter() - started:.0f} s"
        )
        del model
        if device == "cuda":
            torch.cuda.empty_cache()

    final_epochs = int(np.median(chosen_epochs))
    model, _ = fit(
        texts, y, groups, tokenizer, make_model, max_length=max_length, batch_size=batch_size,
        device=device, seed=seed, epochs=final_epochs,
    )  # fmt: skip
    model.save_pretrained(out / "model")
    tokenizer.save_pretrained(out / "model")
    pq.write_table(
        pa.table(
            {
                "sample_id": columns["sample_id"],
                "fold": folds.astype("int8"),
                "label": y.astype("int8"),
                "source": columns["source"],
                "group": groups,
                "p_phishing": oof,
            }
        ),
        out / "oof.parquet",
    )
    info = {
        "model": "distilbert",
        "modality": meta["modality"],
        "feature_set": meta["text_input"],
        "params": {
            "pretrained": model_name,
            "learning_rate": LEARNING_RATE,
            "batch_size": batch_size,
            "max_length": max_length,
            "final_epochs": final_epochs,
        },
        "oof_log_loss": float(log_loss(y, oof, labels=[0, 1])),
        "n_trials": 0,
        "seed": seed,
        "feature_code_hash": meta["text_code_hash"],
        "split_sha256": json.loads(meta["split_sha256"]),
        "n_samples": len(texts),
        "trained_at": datetime.now(UTC).isoformat(),
        "data_sha256": hashlib.sha256(data_path.read_bytes()).hexdigest(),
    }
    (out / "run.json").write_text(json.dumps(info, indent=1))  # last: it marks a finished run
    log(f"finished: OOF log loss {info['oof_log_loss']:.4f}")
    return info


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--allow-cpu", action="store_true", help="only for a small check")
    args = parser.parse_args()
    if not (torch.cuda.is_available() or args.allow_cpu):
        raise SystemExit("No GPU. Colab: Runtime > Change runtime type > GPU; Kaggle: GPU T4 x2.")
    run(args.data, args.out, batch_size=args.batch_size)


if __name__ == "__main__":
    main()
