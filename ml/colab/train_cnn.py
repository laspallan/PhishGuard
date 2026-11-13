"""1D-CNN training for Google Colab (Phase 3): fast on a GPU, and this keeps it off the PC's CPU.

Standalone: needs only torch, optuna, numpy, pyarrow and scikit-learn, not this repository. It reads
one file made by `python -m phishguard_ml text-export`, which holds development rows only: the
locked test set never leaves the PC. Output goes to --out (use a Google Drive folder). Every
finished trial and fold is saved, so a Colab disconnect costs at most the training in progress. Run
it again with the same arguments to continue.

    pip install optuna
    python train_cnn.py --data dev_text_email_text_body.parquet --out <drive folder>

Then copy the folder back and run `python -m phishguard_ml text-import <folder>`.

The design is the 1D-CNN in `phishguard_ml/training/text_cnn.py` (and the training loop in
`text_train.py`), and `test_text_models.py` checks that on a CPU this script and the repository give
the same predictions and search the same space. Only the device differs. After a disconnect the
remaining trials are drawn with a different seed, so a resumed search is valid but is not the exact
search an uninterrupted run would make.
"""

import argparse
import hashlib
import json
import os
import re
import time
from collections import Counter
from collections.abc import Callable
from datetime import UTC, datetime
from itertools import islice
from pathlib import Path

import numpy as np
import optuna
import pyarrow as pa
import pyarrow.parquet as pq
import torch
from optuna.distributions import CategoricalDistribution, FloatDistribution
from sklearn.metrics import log_loss
from sklearn.model_selection import GroupShuffleSplit
from torch import nn

SEED = 42
DEFAULT_TRIALS = 10
MAX_EPOCHS = 10
PATIENCE = 2
VALIDATION_SHARE = 0.1
PAD, UNKNOWN = 0, 1
FILTER_SIZES = (3, 4, 5)
# a convolution needs at least this many positions; shorter texts are padded up to it
MIN_LENGTH = max(FILTER_SIZES)
_WORD = re.compile(r"\w+|[^\w\s]")

SEARCH_SPACE = {
    "learning_rate": FloatDistribution(1e-4, 3e-3, log=True),
    "embed_dim": CategoricalDistribution([64, 128]),
    "dropout": FloatDistribution(0.1, 0.5),
    "batch_size": CategoricalDistribution([64, 128]),
    "num_filters": CategoricalDistribution([64, 100, 128]),
}


class TextCNN(nn.Module):
    """Same layers and names as `text_cnn.TextCNN`, so the PC can load the saved weights."""

    def __init__(self, vocab_size, embed_dim, num_filters, dropout):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=PAD)
        self.convs = nn.ModuleList([nn.Conv1d(embed_dim, num_filters, k) for k in FILTER_SIZES])
        self.fc = nn.Linear(len(FILTER_SIZES) * num_filters, 1)
        self.dropout = nn.Dropout(dropout)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Raw logits."""
        emb = self.embedding(x).permute(0, 2, 1)  # [batch, embed, sequence]
        pooled = [torch.relu(conv(emb)).max(dim=2).values for conv in self.convs]
        return self.fc(self.dropout(torch.cat(pooled, dim=1))).squeeze(1)


class Vocabulary:
    def __init__(self, tokens: list[str], settings: dict):
        self.tokens, self.settings = tokens, settings
        self._ids = {token: i + 2 for i, token in enumerate(tokens)}

    def __len__(self) -> int:
        return len(self.tokens) + 2

    def split(self, text: str) -> list[str]:
        limit = self.settings["max_length"]
        if self.settings["kind"] == "char":
            return list(text[:limit])
        return [m.group().lower() for m in islice(_WORD.finditer(text), limit)]

    @classmethod
    def build(cls, texts: list[str], settings: dict) -> "Vocabulary":
        empty = cls([], settings)
        counts = Counter(token for text in texts for token in empty.split(text))
        ranked = sorted(counts, key=lambda token: (-counts[token], token))
        return cls(ranked[: settings["max_vocabulary"]], settings)

    def encode(self, text: str) -> list[int]:
        return [self._ids.get(token, UNKNOWN) for token in self.split(text)] or [UNKNOWN]


def _batch(encoded: list[list[int]], order: np.ndarray, device) -> torch.Tensor:
    longest = max(MIN_LENGTH, *(len(encoded[i]) for i in order))
    x = torch.full((len(order), longest), PAD, dtype=torch.long)
    for row, i in enumerate(order):
        x[row, : len(encoded[i])] = torch.tensor(encoded[i], dtype=torch.long)
    return x.to(device)


def predict(model, vocabulary, texts, device, batch_size=256) -> np.ndarray:
    """In order of length, which keeps batches small; the result is in the original order."""
    encoded = [vocabulary.encode(t) for t in texts]
    model.eval()
    order = np.argsort([len(e) for e in encoded], kind="stable")
    out = np.empty(len(encoded))
    with torch.no_grad():
        for start in range(0, len(order), batch_size):
            chosen = order[start : start + batch_size]
            out[chosen] = torch.sigmoid(model(_batch(encoded, chosen, device))).cpu().numpy()
    return out


def _train_epoch(model, optimiser, encoded, y, batch_size, generator, device) -> None:
    model.train()
    loss_function = nn.BCEWithLogitsLoss()
    order = torch.randperm(len(encoded), generator=generator).numpy()
    for start in range(0, len(order), batch_size):
        chosen = order[start : start + batch_size]
        target = torch.tensor(y[chosen]).float().to(device)
        optimiser.zero_grad()
        loss = loss_function(model(_batch(encoded, chosen, device)), target)
        loss.backward()
        nn.utils.clip_grad_norm_(model.parameters(), 1.0)
        optimiser.step()


def fit(
    params, texts, y, groups, settings, *, device, seed=SEED, epochs=None, max_epochs=MAX_EPOCHS
):
    """With `epochs`: exactly that many on all rows. Without: early stopping on a group-aware
    slice of these rows, never on the held-out fold."""
    torch.manual_seed(seed)
    generator = torch.Generator().manual_seed(seed)
    if epochs is None:
        splitter = GroupShuffleSplit(n_splits=1, test_size=VALIDATION_SHARE, random_state=seed)
        kept, watched = next(splitter.split(texts, y, groups))
    else:
        kept, watched = np.arange(len(texts)), np.array([], dtype=int)
    vocabulary = Vocabulary.build([texts[i] for i in kept], settings)
    encoded = [vocabulary.encode(texts[i]) for i in kept]
    watched_texts = [texts[i] for i in watched]
    model = TextCNN(
        len(vocabulary), params["embed_dim"], params["num_filters"], params["dropout"]
    ).to(device)
    optimiser = torch.optim.Adam(model.parameters(), lr=params["learning_rate"])

    best_loss, best_state, best_epoch = float("inf"), None, 0
    for epoch in range(1, (epochs or max_epochs) + 1):
        _train_epoch(model, optimiser, encoded, y[kept], params["batch_size"], generator, device)
        if epochs is not None:
            best_epoch = epoch
            continue
        p = predict(model, vocabulary, watched_texts, device)
        loss = log_loss(y[watched], p, labels=[0, 1])
        if loss < best_loss:
            best_loss, best_epoch = loss, epoch
            best_state = {k: v.detach().clone() for k, v in model.state_dict().items()}
        elif epoch - best_epoch >= PATIENCE:
            break
    if best_state is not None:
        model.load_state_dict(best_state)
    return model, vocabulary, best_epoch


def _write_json(path: Path, value) -> None:
    """Whole or not at all: a disconnect during the write must not leave a broken file."""
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value))
    os.replace(temporary, path)


def _read_saved(path: Path, n: int) -> dict | None:
    if not path.exists():
        return None
    saved = json.loads(path.read_text())
    if saved["n"] != n:
        raise ValueError(f"{path} belongs to other data; use an empty --out folder")
    return saved


def tune(
    texts, y, folds, groups, settings, out, *, n_trials, device, seed, max_epochs, log
) -> dict:
    """Best parameters by log loss on the first fold, trained on the other folds."""
    optuna.logging.set_verbosity(optuna.logging.WARNING)
    path = out / "trials.json"
    saved = _read_saved(path, len(texts))
    done = saved["trials"] if saved else []
    # A new seed after a disconnect: the old one would draw the finished trials again.
    sampler = optuna.samplers.TPESampler(seed=seed + len(done))
    study = optuna.create_study(direction="minimize", sampler=sampler)
    for trial in done:
        study.add_trial(
            optuna.trial.create_trial(
                params=trial["params"], distributions=SEARCH_SPACE, value=trial["loss"]
            )
        )
    fold = int(np.unique(folds)[0])
    train = np.flatnonzero(folds != fold)
    held_out = np.flatnonzero(folds == fold)
    for number in range(len(done), n_trials):
        started = time.perf_counter()
        trial = study.ask(SEARCH_SPACE)
        model, vocabulary, _ = fit(
            trial.params, [texts[i] for i in train], y[train], [groups[i] for i in train], settings,
            device=device, seed=seed, max_epochs=max_epochs,
        )  # fmt: skip
        p = predict(model, vocabulary, [texts[i] for i in held_out], device)
        loss = float(log_loss(y[held_out], p, labels=[0, 1]))
        study.tell(trial, loss)
        done.append({"params": trial.params, "loss": loss})
        _write_json(path, {"n": len(texts), "trials": done})
        log(f"trial {number}: log loss {loss:.4f}, {time.perf_counter() - started:.0f} s")
    return dict(min(done, key=lambda t: t["loss"])["params"])


def run(
    data_path: Path,
    out: Path,
    *,
    n_trials: int = DEFAULT_TRIALS,
    seed: int = SEED,
    max_epochs: int = MAX_EPOCHS,
    device: str | None = None,
    log: Callable[[str], None] = print,
) -> dict:
    table = pq.read_table(data_path)
    meta = {k.decode(): v.decode() for k, v in (table.schema.metadata or {}).items()}
    if "text_input" not in meta:
        raise ValueError("this file was not made by `phishguard_ml text-export`")
    if "tokens" not in meta:
        raise ValueError("this file has no token settings; run `text-export` again")
    settings = json.loads(meta["tokens"])
    columns = table.to_pydict()
    texts, y = columns["text"], np.asarray(columns["label"], dtype=int)
    folds, groups = np.asarray(columns["fold"], dtype=int), columns["group"]
    device = device or ("cuda" if torch.cuda.is_available() else "cpu")
    log(f"{meta['modality']}/{meta['text_input']}: {len(texts)} rows on {device}")
    out.mkdir(parents=True, exist_ok=True)
    options = dict(device=device, seed=seed, max_epochs=max_epochs)

    params = tune(texts, y, folds, groups, settings, out, n_trials=n_trials, log=log, **options)
    log(f"best parameters: {params}")

    oof, chosen_epochs = np.full(len(texts), np.nan), []
    for fold in np.unique(folds):
        held_out = np.flatnonzero(folds == fold)
        path = out / f"fold_{fold}.json"
        saved = _read_saved(path, len(held_out))
        if saved:
            oof[held_out] = saved["p_phishing"]
            chosen_epochs.append(saved["epochs"])
            log(f"fold {fold}: already done")
            continue
        started = time.perf_counter()
        train = np.flatnonzero(folds != fold)
        model, vocabulary, epochs = fit(
            params, [texts[i] for i in train], y[train], [groups[i] for i in train], settings,
            **options,
        )  # fmt: skip
        p = predict(model, vocabulary, [texts[i] for i in held_out], device)
        oof[held_out] = p
        chosen_epochs.append(epochs)
        _write_json(path, {"n": len(held_out), "epochs": epochs, "p_phishing": p.tolist()})
        log(
            f"fold {fold}: log loss {log_loss(y[held_out], p, labels=[0, 1]):.4f}, "
            f"epochs {epochs}, {time.perf_counter() - started:.0f} s"
        )

    params["final_epochs"] = int(np.median(chosen_epochs))
    model, vocabulary, _ = fit(
        params, texts, y, groups, settings, device=device, seed=seed, epochs=params["final_epochs"]
    )
    torch.save({k: v.cpu() for k, v in model.state_dict().items()}, out / "model.pt")
    (out / "vocabulary.json").write_text(json.dumps(vocabulary.tokens))
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
        "model": "cnn_1d",
        "modality": meta["modality"],
        "feature_set": meta["text_input"],
        "params": params,
        "oof_log_loss": float(log_loss(y, oof, labels=[0, 1])),
        "n_trials": n_trials,
        "seed": seed,
        "feature_code_hash": meta["lstm_code_hash"],  # the text-code hash; model-independent
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
    parser.add_argument("--trials", type=int, default=DEFAULT_TRIALS)
    parser.add_argument("--allow-cpu", action="store_true", help="only for a small check")
    args = parser.parse_args()
    if not (torch.cuda.is_available() or args.allow_cpu):
        raise SystemExit("No GPU. In Colab: Runtime > Change runtime type > GPU.")
    run(args.data, args.out, n_trials=args.trials)


if __name__ == "__main__":
    main()
