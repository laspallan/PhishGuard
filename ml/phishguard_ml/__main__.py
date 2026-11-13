"""Command line for the dataset pipeline: python -m phishguard_ml <command>.

download [SOURCE ...]        step 2 (default: every downloadable source)
build                        step 3: parse, clean, de-duplicate -> processed/records.parquet
snapshot [--limit N]         step 5: ONLY inside the container (docker compose --profile collect)
label                        step 6
count                        step 7: print counts, then you choose n_url / n_email (D3)
split --n-url N --n-email M  step 8: makes the frozen split (once)
verify-split                 fails if the frozen split changed
collect [--once]             step 9: daily collector (the compose service runs this)
datacard                     step 10: refresh the generated part of Docs/data_card.md
features [--workers N]       Phase 2: F1-F140 for every record -> processed/features.parquet
train --modality M [--feature-set S] [--models ...] [--trials N]
                             Phase 3: tune, OOF, final model, SHAP -> data/models/
train-text --modality M --input I [--models ...] [--trials N]
                             Phase 3: LSTM and CNN (run in ml/.venv-text, PYTHONHOME cleared)
text-export --modality M --input I
                             Phase 3: development text for DistilBERT on Colab -> data/colab/
text-import FOLDER           Phase 3: checks and registers a finished Colab run
choose-band                  D11: stage-1 band table -> data/models/stage1_band.json
final-eval --confirm-models-are-frozen
                             Phase 8: the ONE use of the locked test set
final-report                 Phase 8: every final number, from the saved predictions
report                       Phase 3: development results table -> data/models/results.md
baseline-export              D2: development emails -> data/baseline/dev_emails.mbox
baseline-import              D2: SpamAssassin scores -> data/models/baseline/ (after the
                             `spamassassin` compose service has run)
ti-record [--daily]          RQ2: today's VirusTotal and OTX lookups -> data/ti_responses/
rq2                          RQ2: url/live with and without ti_score -> data/models/rq2/
brand-icons                  D6: hashes of the brands' own favicons -> frontend/extension/src/
"""

import argparse
import json
import sys
from pathlib import Path

import joblib

from phishguard.models.enums import Label
from phishguard_ml.data import collect, datacard, pipeline, rdap, split
from phishguard_ml.data.download import download_source, make_client
from phishguard_ml.data.records import Source, read_records, write_records
from phishguard_ml.data.snapshot import (
    NotInSnapshotContainerError,
    load_snapshot,
    snapshot_records,
)
from phishguard_ml.features import matrix


def _print(obj) -> None:
    print(json.dumps(obj, indent=2, default=str))


def _final_url(record) -> str | None:
    """Where the snapshot's redirects ended (None if no snapshot or no answer)."""
    meta = load_snapshot(record, "meta.json")
    try:
        return json.loads(meta).get("final_url") if meta else None
    except ValueError:
        return None


def _train(args) -> list[dict]:
    from phishguard.models.enums import Modality
    from phishguard_ml.evaluation.shap_report import mean_abs_shap
    from phishguard_ml.training import devdata, registry, tabular

    data = devdata.load_development(Modality(args.modality), args.feature_set)
    manifest = split.verify_split()
    done = []
    for name in args.models or list(tabular.MODELS):
        folder = tabular.run_dir(args.modality, args.feature_set, name)
        if args.resume and tabular.run_is_complete(
            args.modality,
            args.feature_set,
            name,
            n_trials=args.trials,
            split_sha256=manifest["sha256"],
        ):
            print(f"{name}: already complete, skipped (--resume)")
            done.append({"model": name, "skipped": True})
            continue
        # shap.json marks a finished run: an old one must not vouch for an interrupted new run
        (folder / "shap.json").unlink(missing_ok=True)
        info = tabular.train_and_save(
            name,
            data,
            modality=args.modality,
            feature_set=args.feature_set,
            n_trials=args.trials,
            split_sha256=manifest["sha256"],
            progress=lambda n, loss, name=name: print(f"{name} trial {n}: log loss {loss:.4f}"),
        )
        entry = registry.fit_final(folder, data)
        model = joblib.load(folder / "model.joblib")
        (folder / "shap.json").write_text(json.dumps(mean_abs_shap(model, data), indent=1))
        done.append({"model": name, "oof_log_loss": info.oof_log_loss, "version": entry["version"]})
    return done


def _train_text(args) -> list[dict]:
    from phishguard.models.enums import Modality
    from phishguard_ml.training import devdata, text_train

    data = devdata.load_development_text(Modality(args.modality), args.input)
    manifest = split.verify_split()
    done = []
    for name in args.models or list(text_train.MODELS):
        if args.resume and text_train.run_is_complete(
            args.modality, args.input, name, n_trials=args.trials, split_sha256=manifest["sha256"]
        ):
            print(f"{name}: already complete, skipped (--resume)")
            done.append({"model": name, "skipped": True})
            continue
        info, folder = text_train.train_and_save(
            name,
            data,
            modality=args.modality,
            text_input=args.input,
            n_trials=args.trials,
            split_sha256=manifest["sha256"],
            progress=lambda n, loss, name=name: print(f"{name} trial {n}: log loss {loss:.4f}"),
        )
        entry = text_train.fit_final(folder, data, text_train.TOKENS[args.modality])
        done.append({"model": name, "oof_log_loss": info.oof_log_loss, "version": entry["version"]})
    return done


def _text_colab(args) -> None:
    from phishguard.models.enums import Modality
    from phishguard_ml.training import devdata, text_colab

    manifest = split.verify_split()
    if args.command == "text-export":
        data = devdata.load_development_text(Modality(args.modality), args.input)
        path = text_colab.export(data, args.modality, args.input, manifest["sha256"])
        print("written", path, len(data.y), "development rows")
    else:
        run = json.loads((args.folder / "run.json").read_text())
        data = devdata.load_development_text(Modality(run["modality"]), run["feature_set"])
        _print(text_colab.import_run(args.folder, data, manifest["sha256"]))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="phishguard_ml")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("download")
    p.add_argument(
        "sources", nargs="*", choices=[s.value for s in Source if s is not Source.OWN_MAILBOX]
    )
    p.add_argument("--force", action="store_true")
    p = sub.add_parser("build")
    p.add_argument("--tranco-limit", type=int, default=100_000)
    p.add_argument("--enron-fraction", type=float, default=0.1)
    p = sub.add_parser("snapshot")
    p.add_argument("--limit", type=int)
    p.add_argument("--workers", type=int, default=48)
    p.add_argument("--only", choices=["phishing", "legitimate"])
    p.add_argument("--links", type=int, default=1, help="same-site pages per Tranco home page")
    p = sub.add_parser("rdap")
    p.add_argument(
        "--interval", type=float, default=0.5, help="seconds between requests per registry"
    )
    sub.add_parser("label")
    sub.add_parser("count")
    p = sub.add_parser("split")
    p.add_argument("--n-url", type=int, required=True)
    p.add_argument("--n-email", type=int, required=True)
    sub.add_parser("verify-split")
    p = sub.add_parser("collect")
    p.add_argument("--once", action="store_true")
    sub.add_parser("datacard")
    p = sub.add_parser("features")
    p.add_argument("--workers", type=int, default=4)
    p = sub.add_parser("train")
    p.add_argument("--modality", choices=["url", "email"], required=True)
    p.add_argument("--feature-set", default="all")
    p.add_argument("--models", nargs="*", default=None)
    p.add_argument("--trials", type=int, default=50)
    p.add_argument(
        "--resume", action="store_true", help="skip models already complete with these settings"
    )
    p = sub.add_parser("train-text")
    p.add_argument("--modality", choices=["url", "email"], required=True)
    p.add_argument("--input", required=True, choices=["text_full", "text_host", "text_body"])
    p.add_argument("--models", nargs="*", default=None)
    p.add_argument("--trials", type=int, default=10)
    p.add_argument("--resume", action="store_true")
    p = sub.add_parser("text-export")
    p.add_argument("--modality", choices=["url", "email"], required=True)
    p.add_argument("--input", required=True, choices=["text_full", "text_host", "text_body"])
    p = sub.add_parser("text-import")
    p.add_argument("folder", type=Path)
    sub.add_parser("choose-band", help="stage-1 band table from M1's development predictions")
    p = sub.add_parser("final-eval", help="the one use of the locked test set (Phase 8)")
    p.add_argument("--confirm-models-are-frozen", action="store_true")
    sub.add_parser("final-report", help="every final number, from the saved predictions")
    p = sub.add_parser("report")
    p.add_argument("--n-boot", type=int, default=1000)
    p = sub.add_parser("live-latency", help="median and p95 of the running API's URL scans")
    p.add_argument("--n", type=int, default=200)
    p.add_argument("--api", default="http://127.0.0.1:8000")
    p = sub.add_parser("results", help="recompute every reported table from the saved files")
    p.add_argument("--n-boot", type=int, default=1000)
    sub.add_parser("baseline-export")
    sub.add_parser("baseline-import")
    p = sub.add_parser("ti-record", help="RQ2: today's VirusTotal and OTX lookups -> ti_responses/")
    p.add_argument("--per-class", type=int, default=250)
    p.add_argument("--daily", action="store_true", help="keep running, one batch a day")
    p = sub.add_parser("rq2", help="RQ2: live models with and without ti_score")
    p.add_argument("--n-boot", type=int, default=1000)
    sub.add_parser("brand-icons", help="D6: brand favicon hashes -> frontend/extension/src/")
    sub.add_parser("status")
    p = sub.add_parser("evidence-worker", help="live scan evidence collector (container only)")
    p.add_argument("--concurrency", type=int, default=8)
    args = parser.parse_args(argv)
    from phishguard_ml.training.devdata import LockedTestNotConfirmedError

    try:
        return _run(args)
    except (NotInSnapshotContainerError, LockedTestNotConfirmedError) as error:
        print(f"Refusing: {error}", file=sys.stderr)
        return 2


def _run(args) -> int:
    if args.command == "download":
        chosen = [Source(s) for s in args.sources] or [
            s for s in Source if s is not Source.OWN_MAILBOX
        ]
        with make_client() as client:
            for source in chosen:
                print(source.value, "->", download_source(source, client=client, force=args.force))
    elif args.command == "build":
        _print(pipeline.build(tranco_limit=args.tranco_limit, enron_fraction=args.enron_fraction))
    elif args.command == "snapshot":
        records = read_records(pipeline.records_path())
        updated = snapshot_records(
            records,
            workers=args.workers,
            limit=args.limit,
            only=Label(args.only) if args.only else None,
            links=args.links,
        )
        write_records(updated, pipeline.records_path())
        print(
            sum(r.snapshot_ref is not None for r in updated),
            "URL records have snapshots;",
            len(updated) - len(records),
            "same-site legitimate pages added",
        )
    elif args.command == "rdap":
        domains = rdap.domains_of(read_records(pipeline.records_path()))
        print(len(domains), "registered domains")
        with rdap.make_client() as client:
            _print(rdap.collect(domains, client, interval=args.interval))
    elif args.command == "label":
        _print(dict(pipeline.label_all()))
    elif args.command == "count":
        _print(pipeline.count())
    elif args.command == "split":
        records = split.regroup_phishing_urls(
            read_records(pipeline.labelled_path()), set(matrix.load_tranco_ranks()), _final_url
        )
        dataset = split.sample_dataset(records, n_url=args.n_url, n_email=args.n_email)
        rows = split.make_split(dataset)
        _print(split.write_split(dataset, rows, {"n_url": args.n_url, "n_email": args.n_email}))
    elif args.command == "verify-split":
        _print(split.verify_split())
    elif args.command == "collect":
        if args.once:
            with make_client() as client:
                _print(collect.collect_once(client))
        else:
            collect.run_forever()
    elif args.command == "evidence-worker":
        from phishguard_ml.data import evidence_worker

        evidence_worker.run_worker(args.concurrency)
    elif args.command == "status":
        _print(pipeline.status())
    elif args.command == "datacard":
        print("updated", datacard.update())
    elif args.command == "features":
        path = pipeline.labelled_path()
        records = read_records(path if path.exists() else pipeline.records_path())
        report = matrix.build(records, workers=args.workers)
        _print({k: v for k, v in report.items() if k != "missing_rate_in_own_modality"})
    elif args.command == "train":
        _print(_train(args))
    elif args.command == "train-text":
        _print(_train_text(args))
    elif args.command in ("text-export", "text-import"):
        _text_colab(args)
    elif args.command == "choose-band":
        from phishguard_ml.evaluation import band

        _print(band.choose())
    elif args.command in ("final-eval", "final-report"):
        from phishguard_ml.evaluation import final

        if args.command == "final-eval":
            _print(final.run(confirmed=args.confirm_models_are_frozen))
        else:
            _print(final.report())
    elif args.command == "report":
        from phishguard_ml.evaluation import report as results

        results.build(n_boot=args.n_boot)
        print("written", results.results_path())
    elif args.command == "live-latency":
        from phishguard.core.config import get_settings
        from phishguard_ml.evaluation import live_latency

        key = get_settings().api_key
        if key is None:
            print("Refusing: set PHISHGUARD_API_KEY in .env first", file=sys.stderr)
            return 2
        _print(live_latency.run(args.n, args.api, key.get_secret_value()))
    elif args.command == "results":
        from phishguard_ml.evaluation import rebuild

        _print(rebuild.rebuild(n_boot=args.n_boot))
    elif args.command in ("baseline-export", "baseline-import"):
        from phishguard.models.enums import Modality
        from phishguard_ml.evaluation import baseline
        from phishguard_ml.training.devdata import development_records

        emails = development_records(Modality.EMAIL)
        if args.command == "baseline-export":
            print("written", baseline.export(emails), len(emails), "emails")
        else:
            _print(baseline.import_scores(emails))
    elif args.command == "ti-record":
        _ti_record(args)
    elif args.command == "rq2":
        from phishguard_ml.training import rq2

        _print(rq2.run(n_boot=args.n_boot))
    elif args.command == "brand-icons":
        from phishguard_ml.data import brand_icons

        with brand_icons.make_client() as client:
            _print(brand_icons.build(client))
    return 0


def _ti_record(args) -> None:
    import time

    from phishguard.core.config import get_settings
    from phishguard.services.intel.alienvault import AlienVaultOTXClient
    from phishguard.services.intel.virustotal import VirusTotalClient
    from phishguard_ml.training import rq2

    settings = get_settings()

    def key(secret):
        return secret.get_secret_value() if secret else None

    vt = VirusTotalClient(key(settings.virustotal_api_key))
    otx = AlienVaultOTXClient(key(settings.alienvault_otx_api_key))
    while True:
        try:
            _print(rq2.record_day(vt, otx, per_class=args.per_class))
        except RuntimeError as error:  # no keys: stop, waiting would not help
            print(f"Refusing: {error}", file=sys.stderr)
            raise SystemExit(2) from None
        if not args.daily:
            return
        # Checked every 30 min by the wall clock, so a PC that slept catches up on waking.
        time.sleep(30 * 60)


if __name__ == "__main__":
    sys.exit(main())
