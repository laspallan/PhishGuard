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
report                       Phase 3: development results table -> data/models/results.md
"""

import argparse
import json
import sys

import joblib

from phishguard.models.enums import Label
from phishguard_ml.data import collect, datacard, pipeline, rdap, split
from phishguard_ml.data.download import download_source, make_client
from phishguard_ml.data.records import Source, read_records, write_records
from phishguard_ml.data.snapshot import NotInSnapshotContainerError, snapshot_records
from phishguard_ml.features import matrix


def _print(obj) -> None:
    print(json.dumps(obj, indent=2, default=str))


def _train(args) -> list[dict]:
    from phishguard.models.enums import Modality
    from phishguard_ml.evaluation.shap_report import mean_abs_shap
    from phishguard_ml.training import devdata, registry, tabular

    data = devdata.load_development(Modality(args.modality), args.feature_set)
    manifest = split.verify_split()
    done = []
    for name in args.models or list(tabular.MODELS):
        info = tabular.train_and_save(
            name,
            data,
            modality=args.modality,
            feature_set=args.feature_set,
            n_trials=args.trials,
            split_sha256=manifest["sha256"],
            progress=lambda n, loss, name=name: print(f"{name} trial {n}: log loss {loss:.4f}"),
        )
        folder = tabular.run_dir(args.modality, args.feature_set, name)
        entry = registry.fit_final(folder, data)
        model = joblib.load(folder / "model.joblib")
        (folder / "shap.json").write_text(json.dumps(mean_abs_shap(model, data), indent=1))
        done.append({"model": name, "oof_log_loss": info.oof_log_loss, "version": entry["version"]})
    return done


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
    p = sub.add_parser("report")
    p.add_argument("--n-boot", type=int, default=1000)
    sub.add_parser("status")
    args = parser.parse_args(argv)
    try:
        return _run(args)
    except NotInSnapshotContainerError as error:
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
        records = read_records(pipeline.labelled_path())
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
    elif args.command == "report":
        from phishguard_ml.evaluation import report as results

        results.build(n_boot=args.n_boot)
        print("written", results.results_path())
    return 0


if __name__ == "__main__":
    sys.exit(main())
