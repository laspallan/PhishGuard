import json
from datetime import date

import httpx
import pytest

from phishguard_ml import __main__ as cli
from phishguard_ml.data import collect, datacard, download, pipeline
from phishguard_ml.data.records import SampleRecord, Source, read_records
from tests.fixtures import email_bytes, mbox, phishtank_csv, tranco_zip, write_download


def seed_raw(data_dir):
    raw = data_dir / "raw"
    write_download(
        raw / "phishtank" / "2026-11-02",
        {
            "online-valid.csv": phishtank_csv(
                [
                    ("http://paypal-login.bad.example/", "2026-11-01T00:00:00+00:00", "yes"),
                    ("https://shared.example/", "2026-11-01T00:00:00+00:00", "yes"),
                ]
            )
        },
        "phishtank",
    )
    write_download(
        raw / "openphish" / "2026-11-02",
        {"feed.txt": b"https://shared.example/\nhttp://other.bad.example/x.exe\n"},
        "openphish",
    )
    write_download(
        raw / "tranco" / "2026-11-02",
        {"top-1m.csv.zip": tranco_zip(["google.com", "shared.example"])},
        "tranco",
    )
    write_download(
        raw / "nazario" / "2026-11-02",
        {"phishing-2025": mbox([email_bytes(subject="Verify your account")])},
        "nazario",
    )
    (raw / "own_mailbox").mkdir(parents=True)
    (raw / "own_mailbox" / "a.eml").write_bytes(email_bytes(subject="Newsletter"))


def test_build_label_count_and_datacard(isolated_data_dir, tmp_path):
    seed_raw(isolated_data_dir)

    report = pipeline.build()
    assert report["parsed_per_source"]["phishtank"] == 2
    assert report["dedup"]["duplicates"] == 2  # shared.example: openphish copy + tranco copy
    assert report["dedup"]["label_conflicts"] == 1
    assert report["own_mailbox_records"] == 1
    assert report["records"] == 5

    categories = pipeline.label_all()
    assert categories["url:malware"] == 1
    assert categories["url:brand_impersonation"] == 1

    summary = pipeline.count()
    assert summary["by_type_label"] == {
        "email:phishing": 1,
        "url:legitimate": 1,
        "url:phishing": 3,
    }
    assert summary["max_balanced"] == {"url": 2, "email": 0}
    assert all(r.source is not Source.OWN_MAILBOX for r in read_records(pipeline.labelled_path()))

    card = tmp_path / "card.md"
    card.write_text(f"intro\n{datacard.START}\nold\n{datacard.END}\noutro\n")
    datacard.update(card)
    text = card.read_text()
    assert text.startswith("intro\n") and text.endswith("outro\n")
    assert "url:malware" in text and "old" not in text


def test_datacard_needs_markers(tmp_path):
    card = tmp_path / "card.md"
    card.write_text("no markers")
    with pytest.raises(ValueError):
        datacard.update(card)


def test_collect_keeps_only_new_samples_and_never_touches_the_split(isolated_data_dir, monkeypatch):
    seed_raw(isolated_data_dir)
    pipeline.build()
    splits = isolated_data_dir / "splits"
    splits.mkdir()
    (splits / "manifest.json").write_text("{}")
    before = sorted(p.name for p in splits.iterdir())

    responses = {
        r.url: body
        for source, body in [
            (
                Source.PHISHTANK,
                phishtank_csv(
                    [
                        ("http://paypal-login.bad.example/", "2026-12-01T00:00:00+00:00", "yes"),
                        ("http://brand-new.bad.example/", "2026-12-01T00:00:00+00:00", "yes"),
                    ],
                    targets=["Other", "PayPal"],
                ),
            ),
            (Source.OPENPHISH, b"http://other.bad.example/x.exe\n"),
            (Source.TRANCO, tranco_zip(["google.com", "newsite.example"])),
        ]
        for r in download.remote_files(source)[:1]
    }
    responses["https://tranco-list.eu/top-1m-id"] = b"ABCDE"
    client = httpx.Client(
        transport=httpx.MockTransport(
            lambda req: httpx.Response(200, content=responses[str(req.url)])
        )
    )

    report = collect.collect_once(client, day=date(2026, 12, 1), take_snapshots=False)

    assert report["sources"] == ["phishtank", "openphish", "tranco"]
    new = read_records(
        isolated_data_dir / "processed" / "monthly" / "2026-12" / "2026-12-01.parquet"
    )
    assert sorted(r.raw_content for r in new) == [
        "http://brand-new.bad.example/",
        "https://newsite.example/",
    ]
    by_url = {r.raw_content: r for r in new}
    # PhishTank's target brand is used, as in `label` (D1); Tranco samples get no category
    assert by_url["http://brand-new.bad.example/"].attack_category.value == "brand_impersonation"
    assert by_url["https://newsite.example/"].attack_category is None
    assert sorted(p.name for p in splits.iterdir()) == before

    again = collect.collect_once(client, day=date(2026, 12, 1), take_snapshots=False)
    assert again["sources"] == ["phishtank", "openphish"]  # tranco already done this month
    assert again["new"] == 0


def test_collector_follows_the_wall_clock_and_survives_a_restart(isolated_data_dir, monkeypatch):
    from datetime import UTC, datetime, timedelta

    runs = []
    monkeypatch.setattr(collect, "collect_once", lambda client: runs.append(1))
    start = datetime(2026, 12, 1, 20, 0, tzinfo=UTC)
    assert collect.run_due(None, start, 24) is True  # never ran: collect now
    assert collect.run_due(None, start + timedelta(hours=23), 24) is False
    # A PC that slept through the due time collects at the first check after waking, and the
    # last run is read from disk, so a restarted container does not collect twice.
    assert collect.run_due(None, start + timedelta(hours=39), 24) is True
    assert collect.run_due(None, start + timedelta(hours=40), 24) is False
    assert len(runs) == 2


def test_a_failed_day_still_counts_as_a_run(isolated_data_dir, monkeypatch):
    from datetime import UTC, datetime

    def fail(client):
        raise httpx.ConnectError("down")

    monkeypatch.setattr(collect, "collect_once", fail)
    now = datetime(2026, 12, 1, tzinfo=UTC)
    assert collect.run_due(None, now, 24) is True
    assert collect.is_due(now, 24) is False  # retried tomorrow, not every 30 minutes


def test_cli_refuses_snapshots_outside_container(isolated_data_dir, monkeypatch, capsys):
    monkeypatch.delenv("PHISHGUARD_IN_SNAPSHOT_CONTAINER", raising=False)
    seed_raw(isolated_data_dir)
    pipeline.build()

    assert cli.main(["snapshot", "--limit", "1"]) == 2
    assert "Refusing" in capsys.readouterr().err


def test_cli_count_prints_json(isolated_data_dir, capsys):
    seed_raw(isolated_data_dir)
    pipeline.build()

    assert cli.main(["count"]) == 0
    assert json.loads(capsys.readouterr().out)["total"] == 5


def test_status_reports_snapshot_and_rdap_progress(isolated_data_dir):
    seed_raw(isolated_data_dir)
    pipeline.build()
    records = read_records(pipeline.records_path())
    first_url = next(
        r for r in records if r.sample_type.value == "url" and r.label.value == "phishing"
    )
    folder = isolated_data_dir / "snapshots" / str(first_url.sample_id)
    folder.mkdir(parents=True)
    (folder / "meta.json").write_text("{}")
    (isolated_data_dir / "rdap").mkdir()
    (isolated_data_dir / "rdap" / "google.com.json").write_text('{"status": 200}')

    report = pipeline.status()

    assert report["snapshots"]["phishing"] == "1 of 3"
    assert report["rdap"]["final_answer"] == 1
    assert (
        report["rdap"]["domains"]
        == report["rdap"]["final_answer"]
        + report["rdap"]["to_retry"]
        + report["rdap"]["not_queried_yet"]
    )


def test_datacard_reports_missing_rates_per_class_in_own_modality(isolated_data_dir):
    import math

    import pyarrow as pa
    import pyarrow.parquet as pq

    from phishguard.services.features.extractor import FEATURE_NAMES
    from phishguard_ml.data.records import write_records

    records = [
        SampleRecord.create(source=Source.PHISHTANK, raw_content=f"http://p{i}.bad-x.com/",
                            collected_at="2026-11-05T00:00Z", group_key=f"g{i}")
        for i in range(2)
    ] + [
        SampleRecord.create(source=Source.TRANCO, raw_content="https://good-x.com/",
                            collected_at="2026-11-05T00:00Z", group_key="t")
    ]  # fmt: skip
    write_records(records, isolated_data_dir / "splits" / "dataset.parquet")
    first = FEATURE_NAMES[0]
    columns = {"sample_id": [str(r.sample_id) for r in records]}
    columns |= {n: [1.0, 1.0, 1.0] for n in FEATURE_NAMES}
    columns[first] = [math.nan, 1.0, math.nan]  # half of phishing, all legitimate missing
    (isolated_data_dir / "processed").mkdir(parents=True, exist_ok=True)
    pq.write_table(pa.table(columns), isolated_data_dir / "processed" / "features.parquet")

    rates = datacard.missing_rates()

    assert rates[first] == {"url:legitimate": 1.0, "url:phishing": 0.5}
    assert rates[FEATURE_NAMES[-1]] == {}  # email feature: no email rows here
    assert f"| {first} | 50.0% | 100.0% |" in datacard.render()
