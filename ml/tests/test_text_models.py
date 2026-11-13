"""LSTM, CNN and the DistilBERT Colab script on small synthetic text. Needs PyTorch, so these run
in ml/.venv-text (`make test-text`) and are skipped in backend/.venv."""

import importlib.util
import json
from pathlib import Path

import numpy as np
import pyarrow.parquet as pq
import pytest

torch = pytest.importorskip("torch")

from phishguard.models.enums import Modality  # noqa: E402
from phishguard.services import text_input  # noqa: E402
from phishguard.services.text_input import email_text, text_for, url_host_text  # noqa: E402
from phishguard_ml.__main__ import main  # noqa: E402
from phishguard_ml.data import split  # noqa: E402
from phishguard_ml.data.records import SampleRecord, Source  # noqa: E402
from phishguard_ml.evaluation import report  # noqa: E402
from phishguard_ml.training import devdata, registry, text_colab, text_train  # noqa: E402
from phishguard_ml.training.devdata import DevText  # noqa: E402
from phishguard_ml.training.text_cnn import TextCNN  # noqa: E402
from phishguard_ml.training.text_lstm import TextLSTM  # noqa: E402
from phishguard_ml.training.text_train import Tokens, Vocabulary  # noqa: E402

T = "2026-11-02T00:00Z"
CHARS = Tokens("char", 30, 50)
WORDS = Tokens("word", 5, 3)
LSTM = {
    "learning_rate": 0.01, "embed_dim": 8, "dropout": 0.1, "batch_size": 8, "hidden_dim": 8,
}  # fmt: skip
CNN = {
    "learning_rate": 0.01, "embed_dim": 8, "dropout": 0.1, "batch_size": 8, "num_filters": 8,
}  # fmt: skip


def _dev(n=60) -> DevText:
    texts = ["http://verify-login-now.test/a" if i % 2 else "https://shop.test/" for i in range(n)]
    return DevText(
        sample_ids=[f"s{i}" for i in range(n)],
        X=np.empty((n, 0)),
        y=np.array([i % 2 for i in range(n)]),
        folds=np.array([i % 5 for i in range(n)]),
        groups=[f"g{i}" for i in range(n)],
        sources=["phishtank" if i % 2 else "tranco" for i in range(n)],
        feature_names=[],
        texts=texts,
    )


# --- what the models read -------------------------------------------------------------------


def test_host_text_keeps_only_scheme_and_host():
    assert url_host_text("http://user@Bad-Test.com:8080/a/b?x=1#f") == "http://bad-test.com:8080"
    assert url_host_text("http://[bad") == ""


def test_email_text_has_subject_and_body_but_no_other_headers_or_years():
    raw = (
        "Received: from mail.enron-test.com\nDate: Mon, 1 Jan 2001 10:00:00 +0000\n"
        "X-Mailer: Outlook\nSubject: Your 2001 account\n\nPlease read this before 2002."
    )
    text = email_text(raw)
    assert text == "Your account\nPlease read this before ."


def test_email_text_hides_the_names_of_the_datasets():
    raw = "Subject: Enron meeting\n\nSent by jose@monkey.org via HOU/ECT. Not the word project."
    assert email_text(raw) == (
        "<ORG> meeting\nSent by <ORG>@<ORG>.org via <ORG>/<ORG>. Not the word project."
    )


def test_email_text_can_always_be_saved_as_utf8(monkeypatch):
    # Real emails reached the export with lone surrogates; this puts one in directly.
    monkeypatch.setattr(text_input, "body_text", lambda parts: "broken \udcff byte")
    text = email_text("Subject: hello\n\nbody")
    assert text.encode("utf-8") and "broken ? byte" in text


def test_html_email_is_read_as_visible_text():
    raw = (
        "Subject: hi\nContent-Type: text/html\n\n"
        "<html><style>x{}</style><body><p>Click here</p></body></html>"
    )
    assert "Click here" in email_text(raw) and "<p>" not in email_text(raw)


def test_unknown_text_input_is_refused():
    with pytest.raises(ValueError):
        text_for("email", "text_host", "x")


# --- vocabulary -----------------------------------------------------------------------------


def test_vocabulary_keeps_the_most_frequent_and_marks_the_rest_unknown():
    vocabulary = Vocabulary.build(["b b b a a c", "d"], Tokens("word", 10, 3))
    assert vocabulary.tokens == ["b", "a", "c"]  # size 3; ties in alphabetical order
    assert vocabulary.encode("B a zzz") == [2, 3, 1]


def test_tokens_are_cut_to_the_limit_and_an_empty_text_can_still_be_read():
    assert len(Vocabulary.build(["abc"], Tokens("char", 2, 9)).encode("abcabc")) == 2
    assert Vocabulary.build(["a"], WORDS).encode("") == [text_train.UNKNOWN]


def test_vocabulary_comes_from_the_training_rows_only(monkeypatch):
    """A word only in the held-out fold must be unknown to the model that predicts that fold."""
    seen = []
    original = Vocabulary.build

    def spy(texts, settings):
        seen.append(list(texts))
        return original(texts, settings)

    data = _dev(40)
    texts = [
        f"secret{i}" if fold == 0 else text
        for i, (text, fold) in enumerate(zip(data.texts, data.folds, strict=True))
    ]
    data = DevText(**{**data.__dict__, "texts": texts})
    monkeypatch.setattr(Vocabulary, "build", staticmethod(spy))
    text_train.out_of_fold("cnn_1d", CNN, data, CHARS, max_epochs=1)
    assert not any(t.startswith("secret") for t in seen[0])


# --- networks -------------------------------------------------------------------------------


def test_lstm_score_does_not_depend_on_padding():
    model = TextLSTM(10, embed_dim=4, hidden_dim=4, dropout=0.0).eval()
    short = torch.tensor([[2, 3, 4]])
    padded = torch.tensor([[2, 3, 4, 0, 0, 0, 0]])
    assert model(short).item() == pytest.approx(model(padded).item(), abs=1e-5)


@pytest.mark.parametrize("network", [TextLSTM(10), TextCNN(10)])
def test_networks_return_logits(network):
    network.eval()
    with torch.no_grad():
        network.fc.bias.fill_(50.0)  # a sigmoid output could never go above 1
        out = network(torch.ones((3, 6), dtype=torch.long))
    assert out.shape == (3,) and (out > 1).all()


# --- training -------------------------------------------------------------------------------


@pytest.mark.parametrize(("name", "params"), [("lstm", LSTM), ("cnn_1d", CNN)])
def test_models_learn_an_obvious_pattern_out_of_fold(name, params):
    data = _dev()
    oof, epochs = text_train.out_of_fold(name, params, data, CHARS, max_epochs=8)
    assert np.isfinite(oof).all() and len(epochs) == 5
    assert ((oof >= 0.5) == data.y).mean() > 0.95


def test_same_seed_gives_the_same_predictions():
    torch.set_num_threads(1)
    data = _dev(30)
    first, _ = text_train.out_of_fold("lstm", LSTM, data, CHARS, max_epochs=2)
    second, _ = text_train.out_of_fold("lstm", LSTM, data, CHARS, max_epochs=2)
    assert np.array_equal(first, second)


def test_early_stopping_never_sees_the_same_group_in_both_parts(monkeypatch):
    """Rows of one group stay on one side of the early-stopping slice, inside `fit` itself."""
    groups = [f"g{i // 3}" for i in range(60)]
    y = np.array([i % 2 for i in range(60)])
    texts = [f"row{i}" for i in range(60)]
    encoded_sets = []
    original = text_train._probabilities

    def spy(model, encoded, batch_size=256):
        encoded_sets.append(len(encoded))
        return original(model, encoded, batch_size)

    monkeypatch.setattr(text_train, "_probabilities", spy)
    text_train.fit("cnn_1d", CNN, texts, y, groups, CHARS, max_epochs=1)
    assert encoded_sets[0] % 3 == 0 and 0 < encoded_sets[0] < 60  # whole groups of 3 rows


# --- command line, report, resume -----------------------------------------------------------


def _records():
    out = []
    for i in range(60):
        phishing = i % 2 == 1
        out.append(
            SampleRecord.create(
                source=Source.PHISHTANK if phishing else Source.TRANCO,
                raw_content=f"http://verify-login-{i}.test/a"
                if phishing
                else f"https://s{i}.test/",
                collected_at=T,
                group_key=f"domain:{i}.test",
            )
        )
    return out


@pytest.fixture
def small_settings(monkeypatch):
    monkeypatch.setitem(text_train.TOKENS, "url", CHARS)
    monkeypatch.setattr(text_train, "MAX_EPOCHS", 2)
    original = text_train.fit

    def short_fit(*args, **kwargs):
        kwargs.setdefault("max_epochs", 2)
        return original(*args, **kwargs)

    monkeypatch.setattr(text_train, "fit", short_fit)


def test_train_text_command_saves_registers_reports_and_resumes(
    isolated_data_dir, small_settings, capsys
):
    records = _records()
    split.write_split(records, split.make_split(records), {})
    args = ["train-text", "--modality", "url", "--input", "text_host", "--models", "cnn_1d"]
    assert main([*args, "--trials", "1"]) == 0

    folder = isolated_data_dir / "models" / "url" / "text_host" / "cnn_1d"
    run = json.loads((folder / "run.json").read_text())
    assert run["params"]["final_epochs"] >= 1 and (folder / "model.json").exists()
    entry = registry.load_registry()[0]
    assert entry["model"] == "cnn_1d" and entry["feature_set"] == "text_host"

    # Same rows as the tabular runs would use: development only.
    locked = {r["sample_id"] for r in split.load_split()[1] if r["set"] != "dev"}
    trained_on = set(pq.read_table(folder / "oof.parquet")["sample_id"].to_pylist())
    assert locked and not locked & trained_on

    results = report.build(n_boot=5)
    assert results["url/text_host"][0]["model"] == "cnn_1d"

    capsys.readouterr()
    assert main([*args, "--trials", "1", "--resume"]) == 0
    assert "already complete" in capsys.readouterr().out

    reloaded = text_train.load_final(folder, "url")
    assert 0 <= reloaded.predict(["http://x.test"])[0] <= 1


# --- Colab ----------------------------------------------------------------------------------


def _colab_script():
    path = Path(__file__).parents[1] / "colab" / "train_distilbert.py"
    spec = importlib.util.spec_from_file_location("train_distilbert", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _tiny_factories(tmp_path):
    pytest.importorskip("transformers")
    from tokenizers import Tokenizer
    from tokenizers.models import WordLevel
    from tokenizers.pre_tokenizers import Whitespace
    from transformers import (
        DistilBertConfig,
        DistilBertForSequenceClassification,
        PreTrainedTokenizerFast,
    )

    words = ["[PAD]", "[UNK]", "https", "http", "shop", "verify", "login", "now", "test"]
    backend = Tokenizer(WordLevel({w: i for i, w in enumerate(words)}, unk_token="[UNK]"))
    backend.pre_tokenizer = Whitespace()
    tokenizer = PreTrainedTokenizerFast(
        tokenizer_object=backend, pad_token="[PAD]", unk_token="[UNK]"
    )
    config = DistilBertConfig(
        vocab_size=len(words), n_layers=1, n_heads=2, dim=8, hidden_dim=16, num_labels=1,
        max_position_embeddings=32,
    )  # fmt: skip
    return (lambda: tokenizer), (lambda: DistilBertForSequenceClassification(config))


def test_colab_export_holds_development_rows_and_the_run_can_be_imported(
    isolated_data_dir, tmp_path
):
    records = _records()
    split.write_split(records, split.make_split(records), {})
    manifest = split.verify_split()
    data = devdata.load_development_text(Modality.URL, "text_host")
    path = text_colab.export(data, "url", "text_host", manifest["sha256"])

    exported = pq.read_table(path)
    dev_ids = {r["sample_id"] for r in split.load_split()[1] if r["set"] == "dev"}
    assert set(exported["sample_id"].to_pylist()) == dev_ids and len(dev_ids) < len(records)

    script = _colab_script()
    make_tokenizer, make_model = _tiny_factories(tmp_path)
    out = tmp_path / "drive"
    messages = []
    options = dict(
        make_tokenizer=make_tokenizer, make_model=make_model, batch_size=8, max_epochs=1,
        log=messages.append,
    )  # fmt: skip
    info = script.run(path, out, **options)
    assert info["model"] == "distilbert" and (out / "model" / "model.safetensors").exists()

    # A disconnect costs at most one fold: finished folds are not trained again.
    (out / "run.json").unlink()
    messages.clear()
    script.run(path, out, **options)
    assert sum("already done" in m for m in messages) == 5

    entry = text_colab.import_run(out, data, manifest["sha256"])
    assert entry["model"] == "distilbert" and entry["feature_set"] == "text_host"
    assert "url/text_host" in report.build(n_boot=5)


def test_colab_import_refuses_other_data(isolated_data_dir, tmp_path):
    records = _records()
    split.write_split(records, split.make_split(records), {})
    manifest = split.verify_split()
    data = devdata.load_development_text(Modality.URL, "text_host")
    path = text_colab.export(data, "url", "text_host", manifest["sha256"])
    script = _colab_script()
    make_tokenizer, make_model = _tiny_factories(tmp_path)
    out = tmp_path / "drive"
    script.run(
        path, out, make_tokenizer=make_tokenizer, make_model=make_model, batch_size=8,
        max_epochs=1, log=lambda _: None,
    )  # fmt: skip

    with pytest.raises(ValueError, match="another split"):
        text_colab.import_run(out, data, {"dataset.parquet": "0" * 64})
    fewer = DevText(**{**data.__dict__, "sample_ids": data.sample_ids[:-1] + ["other"]})
    with pytest.raises(ValueError, match="samples, labels or folds"):
        text_colab.import_run(out, fewer, manifest["sha256"])


def test_colab_script_refuses_a_file_not_made_by_export(tmp_path):
    import pyarrow as pa

    path = tmp_path / "x.parquet"
    pq.write_table(pa.table({"text": ["a"]}), path)
    with pytest.raises(ValueError, match="text-export"):
        _colab_script().run(path, tmp_path / "out")


def _lstm_script():
    pytest.importorskip("optuna")
    path = Path(__file__).parents[1] / "colab" / "train_lstm.py"
    spec = importlib.util.spec_from_file_location("train_lstm", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_colab_lstm_gives_the_same_predictions_as_the_repository_code():
    script = _lstm_script()
    data = _dev()
    fitted = text_train.fit("lstm", LSTM, data.texts, data.y, data.groups, CHARS, max_epochs=2)
    settings = {"kind": "char", "max_length": 30, "max_vocabulary": 50}
    model, vocabulary, epochs = script.fit(
        LSTM, data.texts, data.y, data.groups, settings, device="cpu", max_epochs=2
    )
    assert epochs == fitted.epochs and vocabulary.tokens == fitted.vocabulary.tokens
    np.testing.assert_array_equal(
        script.predict(model, vocabulary, data.texts, "cpu"), fitted.predict(data.texts)
    )


def test_colab_lstm_searches_the_same_space_as_the_repository_code():
    import optuna

    trial = optuna.create_study().ask()
    text_train.search_space("lstm", trial)
    assert trial.distributions == _lstm_script().SEARCH_SPACE


def test_colab_lstm_resumes_and_is_imported_as_a_normal_text_model(isolated_data_dir, tmp_path):
    records = _records()
    split.write_split(records, split.make_split(records), {})
    manifest = split.verify_split()
    data = devdata.load_development_text(Modality.URL, "text_host")
    path = text_colab.export(data, "url", "text_host", manifest["sha256"])

    script = _lstm_script()
    out = tmp_path / "drive"
    messages = []
    options = dict(n_trials=2, max_epochs=1, device="cpu", log=messages.append)
    script.run(path, out, **options)
    trials = json.loads((out / "trials.json").read_text())["trials"]
    assert len(trials) == 2

    # A disconnect costs at most one training: one trial and all folds are kept, one fold is redone.
    (out / "run.json").unlink()
    (out / "fold_0.json").unlink()
    (out / "trials.json").write_text(json.dumps({"n": len(data.y), "trials": trials[:1]}))
    messages.clear()
    script.run(path, out, **options)
    assert sum(m.startswith("trial ") for m in messages) == 1
    assert sum("already done" in m for m in messages) == 4
    kept = json.loads((out / "trials.json").read_text())["trials"]
    assert kept[0] == trials[0] and kept[1]["params"] != trials[0]["params"]

    entry = text_colab.import_run(out, data, manifest["sha256"])
    assert entry["model"] == "lstm" and entry["feature_set"] == "text_host"
    folder = registry.load_registry()[-1]["path"]
    fitted = text_train.load_final(isolated_data_dir / "models" / folder, "url")
    assert fitted.predict(data.texts[:3]).shape == (3,)
    assert text_train.run_is_complete(
        "url", "text_host", "lstm", n_trials=2, split_sha256=manifest["sha256"]
    )
    assert "url/text_host" in report.build(n_boot=5)


def test_colab_lstm_refuses_an_old_export_and_import_refuses_a_missing_model(
    isolated_data_dir, tmp_path
):
    import pyarrow as pa

    old = tmp_path / "old.parquet"
    pq.write_table(pa.table({"text": ["a"]}).replace_schema_metadata({"text_input": "x"}), old)
    with pytest.raises(ValueError, match="text-export"):
        _lstm_script().run(old, tmp_path / "out")

    records = _records()
    split.write_split(records, split.make_split(records), {})
    manifest = split.verify_split()
    data = devdata.load_development_text(Modality.URL, "text_host")
    path = text_colab.export(data, "url", "text_host", manifest["sha256"])
    out = tmp_path / "drive"
    _lstm_script().run(path, out, n_trials=1, max_epochs=1, device="cpu", log=lambda _: None)
    (out / "vocabulary.json").unlink()
    with pytest.raises(ValueError, match="final model is missing"):
        text_colab.import_run(out, data, manifest["sha256"])


def _cnn_script():
    pytest.importorskip("optuna")
    path = Path(__file__).parents[1] / "colab" / "train_cnn.py"
    spec = importlib.util.spec_from_file_location("train_cnn", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_colab_cnn_gives_the_same_predictions_as_the_repository_code():
    script = _cnn_script()
    data = _dev()
    fitted = text_train.fit("cnn_1d", CNN, data.texts, data.y, data.groups, CHARS, max_epochs=2)
    settings = {"kind": "char", "max_length": 30, "max_vocabulary": 50}
    model, vocabulary, epochs = script.fit(
        CNN, data.texts, data.y, data.groups, settings, device="cpu", max_epochs=2
    )
    assert epochs == fitted.epochs and vocabulary.tokens == fitted.vocabulary.tokens
    np.testing.assert_array_equal(
        script.predict(model, vocabulary, data.texts, "cpu"), fitted.predict(data.texts)
    )


def test_colab_cnn_searches_the_same_space_as_the_repository_code():
    import optuna

    trial = optuna.create_study().ask()
    text_train.search_space("cnn_1d", trial)
    assert trial.distributions == _cnn_script().SEARCH_SPACE


def test_colab_cnn_resumes_and_is_imported_as_a_normal_text_model(isolated_data_dir, tmp_path):
    records = _records()
    split.write_split(records, split.make_split(records), {})
    manifest = split.verify_split()
    data = devdata.load_development_text(Modality.URL, "text_host")
    path = text_colab.export(data, "url", "text_host", manifest["sha256"])

    script = _cnn_script()
    out = tmp_path / "drive"
    messages = []
    options = dict(n_trials=2, max_epochs=1, device="cpu", log=messages.append)
    script.run(path, out, **options)
    trials = json.loads((out / "trials.json").read_text())["trials"]
    assert len(trials) == 2

    # A disconnect costs at most one training: one trial and all folds are kept, one fold is redone.
    (out / "run.json").unlink()
    (out / "fold_0.json").unlink()
    (out / "trials.json").write_text(json.dumps({"n": len(data.y), "trials": trials[:1]}))
    messages.clear()
    script.run(path, out, **options)
    assert sum(m.startswith("trial ") for m in messages) == 1
    assert sum("already done" in m for m in messages) == 4
    kept = json.loads((out / "trials.json").read_text())["trials"]
    assert kept[0] == trials[0] and kept[1]["params"] != trials[0]["params"]

    entry = text_colab.import_run(out, data, manifest["sha256"])
    assert entry["model"] == "cnn_1d" and entry["feature_set"] == "text_host"
    folder = registry.load_registry()[-1]["path"]
    fitted = text_train.load_final(isolated_data_dir / "models" / folder, "url")
    assert fitted.predict(data.texts[:3]).shape == (3,)
    assert text_train.run_is_complete(
        "url", "text_host", "cnn_1d", n_trials=2, split_sha256=manifest["sha256"]
    )
    assert "url/text_host" in report.build(n_boot=5)
