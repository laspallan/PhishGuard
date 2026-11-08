"""LSTM and 1D-CNN on the text inputs of `services/text_input.py` (Phase 3).

Same out-of-fold design as the tabular models, so the report, calibration and McNemar work on the
same samples. Runs in `ml/.venv-text` (backend/.venv cannot load PyTorch, see PROGRESS.md).

- Vocabulary: built from the training rows of each fold only, so held-out text cannot leak in.
- Early stopping: on a group-aware 10% slice of the training rows, never on the held-out fold.
- Tuning: Optuna on one fold (fold 0), because 50 trials over 5 folds is too slow on a CPU. The
  text models therefore get less tuning than the tabular ones; a limitation stated in the thesis.
- Final model: all development rows, for the median number of epochs early stopping chose.
"""

import json
import re
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from itertools import islice
from pathlib import Path

import joblib
import numpy as np
import optuna
import pyarrow.parquet as pq
import torch
from sklearn.metrics import log_loss
from sklearn.model_selection import GroupShuffleSplit
from torch import nn

from phishguard_ml.training import calibration, registry, tabular
from phishguard_ml.training.devdata import DevText
from phishguard_ml.training.text_cnn import MIN_LENGTH, TextCNN
from phishguard_ml.training.text_lstm import TextLSTM
from phishguard_ml.training.text_settings import TOKENS, Tokens, code_hash

SEED = 42
MODELS = ("lstm", "cnn_1d")  # the names of ModelKind
DEFAULT_TRIALS = 10
MAX_EPOCHS = 10
PATIENCE = 2
VALIDATION_SHARE = 0.1
PAD, UNKNOWN = 0, 1
_WORD = re.compile(r"\w+|[^\w\s]")


class Vocabulary:
    def __init__(self, tokens: list[str], settings: Tokens):
        self.tokens, self.settings = tokens, settings
        self._ids = {token: i + 2 for i, token in enumerate(tokens)}

    def __len__(self) -> int:
        return len(self.tokens) + 2

    def split(self, text: str) -> list[str]:
        limit = self.settings.max_length
        if self.settings.kind == "char":
            return list(text[:limit])
        return [m.group().lower() for m in islice(_WORD.finditer(text), limit)]

    @classmethod
    def build(cls, texts: list[str], settings: Tokens) -> "Vocabulary":
        empty = cls([], settings)
        counts = Counter(token for text in texts for token in empty.split(text))
        ranked = sorted(counts, key=lambda token: (-counts[token], token))
        return cls(ranked[: settings.max_vocabulary], settings)

    def encode(self, text: str) -> list[int]:
        """Never empty: an empty text is one unknown token, so every model can read it."""
        return [self._ids.get(token, UNKNOWN) for token in self.split(text)] or [UNKNOWN]


def make_network(name: str, vocabulary_size: int, params: dict) -> nn.Module:
    common = {"embed_dim": params["embed_dim"], "dropout": params["dropout"]}
    if name == "lstm":
        return TextLSTM(vocabulary_size, hidden_dim=params["hidden_dim"], **common)
    if name == "cnn_1d":
        return TextCNN(vocabulary_size, num_filters=params["num_filters"], **common)
    raise ValueError(f"unknown text model {name!r}; choose from {MODELS}")


def search_space(name: str, trial: optuna.Trial) -> dict:
    params = {
        "learning_rate": trial.suggest_float("learning_rate", 1e-4, 3e-3, log=True),
        "embed_dim": trial.suggest_categorical("embed_dim", [64, 128]),
        "dropout": trial.suggest_float("dropout", 0.1, 0.5),
        "batch_size": trial.suggest_categorical("batch_size", [64, 128]),
    }
    if name == "lstm":
        params["hidden_dim"] = trial.suggest_categorical("hidden_dim", [64, 128, 256])
    else:
        params["num_filters"] = trial.suggest_categorical("num_filters", [64, 100, 128])
    return params


def _batch(encoded: list[list[int]], order: np.ndarray) -> torch.Tensor:
    longest = max(MIN_LENGTH, *(len(encoded[i]) for i in order))
    x = torch.full((len(order), longest), PAD, dtype=torch.long)
    for row, i in enumerate(order):
        x[row, : len(encoded[i])] = torch.tensor(encoded[i], dtype=torch.long)
    return x


def _probabilities(model: nn.Module, encoded: list[list[int]], batch_size: int = 256) -> np.ndarray:
    """In order of length, which keeps batches small; the result is in the original order."""
    model.eval()
    order = np.argsort([len(e) for e in encoded], kind="stable")
    out = np.empty(len(encoded))
    with torch.no_grad():
        for start in range(0, len(order), batch_size):
            chosen = order[start : start + batch_size]
            out[chosen] = torch.sigmoid(model(_batch(encoded, chosen))).numpy()
    return out


@dataclass
class FittedText:
    network: nn.Module
    vocabulary: Vocabulary
    epochs: int

    def predict(self, texts: list[str]) -> np.ndarray:
        return _probabilities(self.network, [self.vocabulary.encode(t) for t in texts])


def _train_epoch(model, optimiser, encoded, y, batch_size, generator) -> None:
    model.train()
    loss_function = nn.BCEWithLogitsLoss()
    order = torch.randperm(len(encoded), generator=generator).numpy()
    for start in range(0, len(order), batch_size):
        chosen = order[start : start + batch_size]
        optimiser.zero_grad()
        loss = loss_function(model(_batch(encoded, chosen)), torch.tensor(y[chosen]).float())
        loss.backward()
        nn.utils.clip_grad_norm_(model.parameters(), 1.0)
        optimiser.step()


def fit(
    name: str,
    params: dict,
    texts: list[str],
    y: np.ndarray,
    groups: list[str],
    settings: Tokens,
    *,
    seed: int = SEED,
    epochs: int | None = None,
    max_epochs: int = MAX_EPOCHS,
) -> FittedText:
    """With `epochs`: exactly that many on all rows. Without: early stopping on a group-aware
    slice of these rows."""
    torch.manual_seed(seed)
    generator = torch.Generator().manual_seed(seed)
    if epochs is None:
        splitter = GroupShuffleSplit(n_splits=1, test_size=VALIDATION_SHARE, random_state=seed)
        kept, watched = next(splitter.split(texts, y, groups))
    else:
        kept, watched = np.arange(len(texts)), np.array([], dtype=int)
    vocabulary = Vocabulary.build([texts[i] for i in kept], settings)
    encoded = [vocabulary.encode(texts[i]) for i in kept]
    watched_encoded = [vocabulary.encode(texts[i]) for i in watched]
    model = make_network(name, len(vocabulary), params)
    optimiser = torch.optim.Adam(model.parameters(), lr=params["learning_rate"])

    best_loss, best_state, best_epoch = float("inf"), None, 0
    for epoch in range(1, (epochs or max_epochs) + 1):
        _train_epoch(model, optimiser, encoded, y[kept], params["batch_size"], generator)
        if epochs is not None:
            best_epoch = epoch
            continue
        loss = log_loss(y[watched], _probabilities(model, watched_encoded), labels=[0, 1])
        if loss < best_loss:
            best_loss, best_epoch = loss, epoch
            best_state = {k: v.clone() for k, v in model.state_dict().items()}
        elif epoch - best_epoch >= PATIENCE:
            break
    if best_state is not None:
        model.load_state_dict(best_state)
    return FittedText(model, vocabulary, best_epoch)


def out_of_fold(
    name: str, params: dict, data: DevText, settings: Tokens, seed: int = SEED, **fit_options
) -> tuple[np.ndarray, list[int]]:
    oof, chosen_epochs = np.full(len(data.y), np.nan), []
    for fold in np.unique(data.folds):
        train = np.flatnonzero(data.folds != fold)
        held_out = np.flatnonzero(data.folds == fold)
        fitted = fit(
            name,
            params,
            [data.texts[i] for i in train],
            data.y[train],
            [data.groups[i] for i in train],
            settings,
            seed=seed,
            **fit_options,
        )
        oof[held_out] = fitted.predict([data.texts[i] for i in held_out])
        chosen_epochs.append(fitted.epochs)
    return oof, chosen_epochs


def tune(
    name: str,
    data: DevText,
    settings: Tokens,
    n_trials: int,
    seed: int = SEED,
    progress: Callable[[int, float], None] | None = None,
    **fit_options,
) -> dict:
    """Best parameters by log loss on fold 0, trained on the other folds."""
    optuna.logging.set_verbosity(optuna.logging.WARNING)
    fold = int(np.unique(data.folds)[0])
    train = np.flatnonzero(data.folds != fold)
    held_out = np.flatnonzero(data.folds == fold)

    def objective(trial: optuna.Trial) -> float:
        fitted = fit(
            name,
            search_space(name, trial),
            [data.texts[i] for i in train],
            data.y[train],
            [data.groups[i] for i in train],
            settings,
            seed=seed,
            **fit_options,
        )
        predicted = fitted.predict([data.texts[i] for i in held_out])
        loss = float(log_loss(data.y[held_out], predicted, labels=[0, 1]))
        if progress:
            progress(trial.number, loss)
        return loss

    study = optuna.create_study(direction="minimize", sampler=optuna.samplers.TPESampler(seed=seed))
    study.optimize(objective, n_trials=n_trials)
    return dict(study.best_params)


def run_is_complete(
    modality: str, text_input: str, name: str, *, n_trials: int, split_sha256: dict
) -> bool:
    """model.json is written last, so its presence means the run finished."""
    folder = tabular.run_dir(modality, text_input, name)
    try:
        run = json.loads((folder / "run.json").read_text())
    except (OSError, ValueError):
        return False
    return (
        (folder / "model.json").exists()
        and run.get("feature_code_hash") == code_hash(modality)
        and run.get("split_sha256") == split_sha256
        and run.get("n_trials") == n_trials
        and run.get("seed") == SEED
    )


def fit_final(folder: Path, data: DevText, settings: Tokens) -> dict:
    run = json.loads((folder / "run.json").read_text())
    if run["n_samples"] != len(data.y):
        raise ValueError("the development data differ from the data the run was tuned on")
    params = run["params"]
    fitted = fit(
        run["model"], params, data.texts, data.y, data.groups, settings,
        seed=run["seed"], epochs=params["final_epochs"],
    )  # fmt: skip
    torch.save(fitted.network.state_dict(), folder / "model.pt")
    (folder / "vocabulary.json").write_text(json.dumps(fitted.vocabulary.tokens))
    oof = pq.read_table(folder / "oof.parquet")
    calibrator = calibration.fit_calibrator(
        np.asarray(oof.column("p_phishing").to_numpy()), np.asarray(oof.column("label").to_numpy())
    )
    joblib.dump(calibrator, folder / "calibrator.joblib")
    return registry.register(folder, run, "model.pt", feature_names=[])


def load_final(folder: Path, modality: str) -> FittedText:
    run = json.loads((folder / "run.json").read_text())
    vocabulary = Vocabulary(json.loads((folder / "vocabulary.json").read_text()), TOKENS[modality])
    network = make_network(run["model"], len(vocabulary), run["params"])
    network.load_state_dict(torch.load(folder / "model.pt", weights_only=True))
    return FittedText(network, vocabulary, run["params"]["final_epochs"])


def train_and_save(
    name: str,
    data: DevText,
    *,
    modality: str,
    text_input: str,
    n_trials: int,
    split_sha256: dict,
    seed: int = SEED,
    progress: Callable[[int, float], None] | None = None,
    **fit_options,
) -> tuple[tabular.RunInfo, Path]:
    settings = TOKENS[modality]
    params = tune(name, data, settings, n_trials, seed, progress, **fit_options)
    oof, chosen_epochs = out_of_fold(name, params, data, settings, seed, **fit_options)
    params["final_epochs"] = int(np.median(chosen_epochs))
    info = tabular.RunInfo(
        model=name,
        modality=modality,
        feature_set=text_input,
        params=params,
        oof_log_loss=float(log_loss(data.y, oof)),
        n_trials=n_trials,
        seed=seed,
        feature_code_hash=code_hash(modality),
        split_sha256=split_sha256,
        n_samples=len(data.y),
        trained_at=datetime.now(UTC).isoformat(),
    )
    (tabular.run_dir(modality, text_input, name) / "model.json").unlink(missing_ok=True)
    return info, tabular.save_run(info, data, oof)
