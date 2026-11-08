import io
import json
import math
import zipfile
from pathlib import Path

import pyarrow.parquet as pq

import phishguard.services.features.extractor as backend_extractor
from phishguard_ml.data.records import SampleRecord, Source
from phishguard_ml.features import matrix

T = "2026-11-02T00:00Z"


def _snapshot(data: Path, record: SampleRecord, html: str) -> SampleRecord:
    folder = data / "snapshots" / str(record.sample_id)
    folder.mkdir(parents=True)
    meta = {
        "url": record.raw_content,
        "status": 200,
        "final_url": record.raw_content,
        "content_type": "text/html; charset=utf-8",
        "fetched_at": "2026-11-02T10:00:00+00:00",
    }
    (folder / "meta.json").write_text(json.dumps(meta))
    (folder / "page.html").write_text(html, encoding="utf-8")
    (folder / "dns.json").write_text(json.dumps({"A": {"records": ["203.0.113.5"], "ttl": 60}}))
    (folder / "tls.json").write_text(json.dumps({"error": "ConnectionRefusedError: x"}))
    return record.model_copy(update={"snapshot_ref": f"snapshots/{record.sample_id}"})


def test_uses_the_backend_extractor():
    assert matrix.extractor is backend_extractor  # training and API share one function


def test_build_writes_matrix_report_and_counts_unreadable_pages(isolated_data_dir, monkeypatch):
    data = isolated_data_dir
    phish = _snapshot(
        data,
        SampleRecord.create(
            source=Source.PHISHTANK, raw_content="http://evil-test.com/login", collected_at=T
        ),
        "<form><input type=password></form>",
    )
    blocked = _snapshot(
        data,
        SampleRecord.create(
            source=Source.PHISHTANK, raw_content="http://blocked-test.com/", collected_at=T
        ),
        "<p>x</p>",
    )
    (data / "rdap").mkdir()
    (data / "rdap" / "evil-test.com.json").write_text(json.dumps({"status": 404}))
    mail = SampleRecord.create(
        source=Source.ENRON, raw_content="From: a@b-test.com\n\nhi\n", collected_at=T
    )

    real_read = Path.read_bytes

    def read_bytes(path):  # simulate antivirus blocking one stored page
        if "page.html" in str(path) and str(blocked.sample_id) in str(path):
            raise OSError(22, "Invalid argument")
        return real_read(path)

    monkeypatch.setattr(Path, "read_bytes", read_bytes)
    report = matrix.build([phish, blocked, mail], ranks={"evil-test.com": 7}, workers=1)

    table = pq.read_table(matrix.features_path())
    assert table.num_rows == 3 and table.num_columns == 141  # sample_id + F1-F140
    assert table.schema.metadata[b"feature_code_hash"].decode() == report["feature_code_hash"]
    rows = table.to_pylist()
    assert rows[0]["num_password_fields"] == 1
    assert rows[0]["whois_available"] == 0  # registry said 404
    assert rows[0]["tranco_rank"] == 7
    assert math.isnan(rows[1]["num_forms"])  # unreadable page -> no HTML features
    assert math.isnan(rows[2]["url_length"]) and rows[2]["dkim_absent"] == 1
    assert report["rows"] == {"url": 2, "email": 1}
    assert report["pages"] == {"ok": 1, "unreadable": 1}
    assert report["missing_rate_in_own_modality"]["suspicious_asn"] == 1.0


def test_tranco_ranks_from_the_downloaded_zip(tmp_path):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("top-1m.csv", "1,google.com\n2,Example-Test.com\n")
    (tmp_path / "top-1m.csv.zip").write_bytes(buffer.getvalue())
    assert matrix.load_tranco_ranks(tmp_path) == {"google.com": 1, "example-test.com": 2}


def test_training_and_live_paths_give_the_same_140_values(isolated_data_dir):
    """D11 step 2 parity: a stored snapshot (training) and the same evidence as the
    collector would send it (live API) go through one builder and give identical features."""
    from phishguard.services.evidence import build_url_evidence

    record = _snapshot(
        isolated_data_dir,
        SampleRecord.create(
            source=Source.PHISHTANK, raw_content="http://login.paypa1-secure.com/a", collected_at=T
        ),
        "<html><title>PayPal</title><form><input type=password></form>café</html>",
    )
    folder = isolated_data_dir / record.snapshot_ref
    rdap = {"status": 200, "response": {"events": []}}
    (isolated_data_dir / "rdap").mkdir()
    (isolated_data_dir / "rdap" / "paypa1-secure.com.json").write_text(json.dumps(rdap))
    ranks = {"paypal.com": 5}

    stored, page_state = matrix.url_evidence(record)
    collector_answer = {  # what the evidence collector returns for a live scan
        "meta": json.loads((folder / "meta.json").read_text()),
        "page": (folder / "page.html").read_bytes(),
        "dns": json.loads((folder / "dns.json").read_text()),
        "tls": json.loads((folder / "tls.json").read_text()),
        "rdap": rdap,
    }
    live = build_url_evidence(record.raw_content, record.collected_at, **collector_answer)

    assert page_state == "ok" and stored == live
    training = backend_extractor.url_features(stored, ranks)
    api = backend_extractor.url_features(live, ranks)
    assert len(api) == 140
    assert all(
        (math.isnan(a) and math.isnan(b)) or a == b for a, b in zip(training, api, strict=True)
    )


def test_scan_path_gives_the_training_features_and_thresholds(isolated_data_dir):
    """Phase 2 and 5 acceptance: the API's own function, on what the collector would send."""
    import base64
    from datetime import datetime

    from phishguard.services.inference.service import BLOCK, WARN, url_values
    from phishguard_ml.training import ensembles

    assert (WARN, BLOCK) == (ensembles.WARN, ensembles.BLOCK)
    record = _snapshot(
        isolated_data_dir,
        SampleRecord.create(
            source=Source.PHISHTANK, raw_content="http://login.paypa1-secure.com/a", collected_at=T
        ),
        "<html><title>PayPal</title><form><input type=password></form></html>",
    )
    folder = isolated_data_dir / record.snapshot_ref
    answer = {
        "meta": json.loads((folder / "meta.json").read_text()),
        "page_b64": base64.b64encode((folder / "page.html").read_bytes()).decode(),
        "dns": json.loads((folder / "dns.json").read_text()),
        "tls": json.loads((folder / "tls.json").read_text()),
    }
    # the collector answer format and the batch path, both without RDAP or ranks as served
    api = url_values(
        record.raw_content, answer, datetime.fromisoformat("2026-11-02T00:00:00+00:00")
    )
    stored, _ = matrix.url_evidence(record)
    training = backend_extractor.url_features(stored, {})
    assert len(api) == 140
    assert all(
        (math.isnan(a) and math.isnan(b)) or a == b for a, b in zip(training, api, strict=True)
    )
