import uuid
from datetime import UTC, date, datetime

import pyarrow as pa
import pyarrow.parquet as pq
import pytest
from pydantic import ValidationError

from phishguard.models.enums import AttackCategory, Label, Modality
from phishguard_ml.data.records import (
    SOURCE_INFO,
    SampleRecord,
    SchemaMismatchError,
    Source,
    content_hash,
    make_sample_id,
    read_records,
    write_records,
)

COLLECTED = datetime(2026, 11, 2, 9, 30, tzinfo=UTC)


def url_record(url: str = "http://paypa1-login.example/verify", **fields) -> SampleRecord:
    fields.setdefault("collected_at", COLLECTED)
    return SampleRecord.create(source=Source.PHISHTANK, raw_content=url, **fields)


def test_every_source_has_a_type_and_label():
    assert set(SOURCE_INFO) == set(Source)


def test_create_derives_type_label_hash_and_id():
    record = url_record()

    assert record.sample_type is Modality.URL
    assert record.label is Label.PHISHING
    assert record.content_hash == content_hash("http://paypa1-login.example/verify")
    assert record.sample_id.version == 5


def test_sample_id_is_deterministic_and_depends_on_type():
    digest = content_hash("same content")

    assert make_sample_id(Modality.URL, digest) == make_sample_id(Modality.URL, digest)
    assert make_sample_id(Modality.URL, digest) != make_sample_id(Modality.EMAIL, digest)


def test_same_content_from_two_sources_gets_the_same_id():
    url = "http://bad.example/login"
    a = SampleRecord.create(source=Source.PHISHTANK, raw_content=url, collected_at=COLLECTED)
    b = SampleRecord.create(source=Source.OPENPHISH, raw_content=url, collected_at=COLLECTED)

    assert a.sample_id == b.sample_id


def test_hash_of_lets_normalised_content_decide_the_id():
    a = url_record("HTTP://Bad.Example/login", hash_of="http://bad.example/login")
    b = url_record("http://bad.example/login")

    assert a.sample_id == b.sample_id
    assert a.raw_content != b.raw_content


def test_label_must_match_the_source():
    good = url_record()
    with pytest.raises(ValidationError, match="provides"):
        SampleRecord(**{**good.model_dump(), "label": Label.LEGITIMATE})


def test_legitimate_samples_cannot_have_an_attack_category():
    with pytest.raises(ValidationError, match="no attack category"):
        SampleRecord.create(
            source=Source.TRANCO,
            raw_content="https://example.org/",
            collected_at=COLLECTED,
            attack_category=AttackCategory.MALWARE,
        )


def test_tampered_sample_id_is_rejected():
    good = url_record()
    with pytest.raises(ValidationError, match="sample_id"):
        SampleRecord(**{**good.model_dump(), "sample_id": uuid.uuid4()})


def test_collected_at_must_be_timezone_aware():
    with pytest.raises(ValidationError, match="timezone-aware"):
        url_record(collected_at=datetime(2026, 11, 2))


def test_only_urls_have_snapshots():
    with pytest.raises(ValidationError, match="only URL"):
        SampleRecord.create(
            source=Source.ENRON,
            raw_content="Subject: hi\n\nbody",
            collected_at=COLLECTED,
            snapshot_ref="snapshots/x",
        )


def test_unknown_fields_are_rejected():
    with pytest.raises(ValidationError):
        url_record(colour="red")


def test_parquet_round_trip_keeps_every_value(tmp_path):
    records = [
        url_record(
            attack_category=AttackCategory.CREDENTIAL_HARVEST,
            source_date=date(2026, 10, 30),
            group_key="paypa1-login.example",
            snapshot_ref="snapshots/abc",
        ),
        SampleRecord.create(
            source=Source.ENRON,
            raw_content="Subject: Meeting\n\nSee you at 10. ünïcode",
            collected_at=COLLECTED,
            group_key="allen-p",
        ),
    ]
    path = tmp_path / "processed" / "records.parquet"

    write_records(records, path)

    assert read_records(path) == records
    assert not path.with_suffix(".parquet.tmp").exists()


def test_reading_a_file_with_another_schema_fails(tmp_path):
    path = tmp_path / "other.parquet"
    pq.write_table(pa.table({"url": ["http://x.example"]}), path)

    with pytest.raises(SchemaMismatchError):
        read_records(path)
