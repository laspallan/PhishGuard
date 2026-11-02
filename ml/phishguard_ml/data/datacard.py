"""Step 10: fill the generated part of Docs/data_card.md from the pipeline's own outputs.

Only the text between the GENERATED markers is replaced; everything else is hand-written.
Every number comes from build_report.json, counts.json and the split manifest.
"""

import json
from pathlib import Path

from phishguard_ml import paths

START = "<!-- GENERATED:START (python -m phishguard_ml datacard) -->"
END = "<!-- GENERATED:END -->"


def _load(path: Path) -> dict | None:
    return json.loads(path.read_text()) if path.exists() else None


def _table(title: str, mapping: dict, key_name: str = "Key") -> str:
    lines = [f"**{title}**", "", f"| {key_name} | Count |", "|---|---|"]
    lines += [f"| {k} | {v:,} |" for k, v in mapping.items()]
    return "\n".join(lines) + "\n"


def render() -> str:
    build = _load(paths.processed_dir() / "build_report.json")
    counts = _load(paths.processed_dir() / "counts.json")
    manifest = _load(paths.splits_dir() / "manifest.json")
    parts = []
    if build:
        parts.append(
            f"Built {build['built_at']} with settings `{json.dumps(build['settings'])}`; "
            f"downloads used: `{json.dumps(build['downloads_used'])}`.\n"
        )
        parts.append(
            _table(
                "Parsed per source (before de-duplication)", build["parsed_per_source"], "Source"
            )
        )
        parts.append(_table("Rejected entries", build["rejected"] or {"none": 0}, "Reason"))
        parts.append(_table("De-duplication", build["dedup"], "Item"))
    if counts:
        parts.append(_table("Records by type and label", counts["by_type_label"], "Type:label"))
        parts.append(
            _table(
                "Phishing records by attack category (D1 rules)",
                counts["by_category"] or {"not labelled yet": 0},
                "Type:category",
            )
        )
        parts.append(_table("Records by source", counts["by_source"], "Source"))
        parts.append(_table("Source dates by year", counts["source_date_years"], "Source:year"))
        parts.append(
            f"URL snapshot coverage: {counts['url_snapshot_coverage']:.1%}. "
            f"Largest balanced set possible: `{json.dumps(counts['max_balanced'])}`.\n"
        )
    if manifest:
        parts.append(
            f"**Split** (seed {manifest['seed']}, created {manifest['created_at']}): "
            f"{manifest['samples']:,} samples, locked test {manifest['test']:,}, "
            f"dev folds `{json.dumps(manifest['dev_folds'])}`.\n\n"
            f"Hashes: `{json.dumps(manifest['sha256'])}`\n"
        )
    else:
        parts.append("**Split:** not made yet.\n")
    return "\n".join(parts)


def update(card: Path | None = None) -> Path:
    card = card or paths.REPO_ROOT / "Docs" / "data_card.md"
    text = card.read_text(encoding="utf-8")
    if START not in text or END not in text:
        raise ValueError(f"{card} has no GENERATED markers")
    head, rest = text.split(START, 1)
    _, tail = rest.split(END, 1)
    card.write_text(f"{head}{START}\n\n{render()}\n{END}{tail}", encoding="utf-8")
    return card
