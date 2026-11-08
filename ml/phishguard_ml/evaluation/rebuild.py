"""`make results`: recompute every reported table from the saved files, in one command.

It only reproduces what has already been produced: development results from the saved
out-of-fold predictions, RQ2 if `rq2` has been run before (so it is never run early on part of
the data), and the final results from the saved locked-test predictions. It never opens the
locked test set: `final-eval` is the only command that does, and it is not called here.
"""

from phishguard_ml.evaluation import final, report
from phishguard_ml.training import rq2


def rebuild(n_boot: int = 1000) -> dict[str, str]:
    done: dict[str, str] = {}

    if report._runs():
        report.build(n_boot=n_boot)
        done["development"] = f"written {report.results_path()}"
    else:
        done["development"] = "skipped: no training runs yet"

    if (rq2.results_dir() / "results.json").exists():
        rq2.run(n_boot=n_boot)
        done["rq2"] = f"written {rq2.results_dir() / 'results.md'}"
    else:
        done["rq2"] = "skipped: `python -m phishguard_ml rq2` has not been run yet"

    if final.predictions_path().exists():
        final.report(n_boot=n_boot)
        done["final"] = f"written {final.predictions_path().parent / 'final_results.md'}"
    else:
        done["final"] = "skipped: `final-eval` has not been run (locked test set untouched)"
    return done
